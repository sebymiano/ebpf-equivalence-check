// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <signal.h>
#include <assert.h>
#include <stdlib.h>
#include <libgen.h>
#include <sys/stat.h>
#include <dirent.h>

#include <argparse.h>
#include <net/if.h>
#include <json-c/json.h>

#include "log.h"
#include "ktest.h"

#define A_PORT  6
#define B_PORT 7

static const char *const usages[] = {
    "bpf_run_test [options] [[--] args]",
    "bpf_run_test [options]",
    NULL,
};

KTestObject* get_ktest_object_by_name(KTest* input, const char* name) {
    for (int i = 0; i < input->numObjects; i++) {
        KTestObject* obj = &input->objects[i];
        if (strcmp(obj->name, name) == 0) {
            return obj;
        }
    }

    return NULL;
}

int fill_maps_with_correct_values(struct bpf_object *obj) {
    struct bpf_map *tx_port = bpf_object__find_map_by_name(obj, "tx_port");
    if (tx_port == NULL) {
        log_error("ERROR: tx_port map not found!");
        return -1;
    }

    int tx_port_fd = bpf_map__fd(tx_port);

    int keys[] = {B_PORT,A_PORT};
	int values[] = {B_PORT,A_PORT};

    for(int i = 0; i < sizeof(keys)/sizeof(keys[0]); i++){
        if (bpf_map_update_elem(tx_port_fd, &keys[i], &values[i], BPF_ANY) == 0) {
            log_debug("tx_port map updated with key %d and value %d", keys[i], values[i]);
        } else {
            log_error("ERROR: tx_port map not updated with key %d and value %d", keys[i], values[i]);
            return -1;
        }
    }

    return 0;
}

int run_bpf_program_with_ktest_file(int prog_fd, const char* ktest_file, char *res_dir, const struct bpf_program *prog) {
    KTest* input;
    int err, ret, ret_code = 0;
    char *buf, *buf_out;

    input = kTest_fromFile(ktest_file);
    if (!input) {
        log_error("ERROR: input file %s not valid.\n", ktest_file);
        return -1;
    }

    log_debug("Input file %s loaded.", ktest_file);
    log_debug("Now it is time to start parsing the KLEE Ktest file");

    log_debug("The Ktest file has %d objects.", input->numObjects);
    for (int i = 0; i < input->numObjects; i++) {
        KTestObject* obj = &input->objects[i];
        log_debug("Object %d has %d bytes.", i, obj->numBytes);
        log_debug("Object %d has name %s.", i, obj->name);
    }

    KTestObject* user_buf = get_ktest_object_by_name(input, "user_buf");
    if (!user_buf) {
        log_error("ERROR: user_buf not found in the Ktest file.");
        ret_code = -1;
        goto end;
    }

    log_debug("Got the user_buf object from the Ktest file.");
    log_debug("Allocating a buffer of size %d for the BPF program.", user_buf->numBytes);

	buf = malloc(user_buf->numBytes + sizeof(__u32));
	if (!buf) {
        log_error("ERROR: failed to allocate input buffer for BPF program.");
        ret_code = -1;
        goto end;
    }

    buf_out = malloc(user_buf->numBytes + sizeof(__u32));
	if (!buf) {
        log_error("ERROR: failed to allocate output buffer for BPF program.");
        ret_code = -1;
        goto end;
    }
	
    memcpy(buf + sizeof(__u32), user_buf->bytes, user_buf->numBytes);
    memset(buf_out, 0, user_buf->numBytes + sizeof(__u32));

    KTestObject* ingress_ifindex = get_ktest_object_by_name(input, "ingress_ifindex");
    if (!ingress_ifindex) {
        log_error("ERROR: ingress_ifindex not found in the Ktest file.");
        ret_code = -1;
        goto end;
    }

    log_debug("Got the ingress_ifindex object from the Ktest file.");

    struct xdp_md ctx_in = { 
                .data = sizeof(__u32),
				.data_end = user_buf->numBytes + sizeof(__u32),
                .ingress_ifindex = *(int*)ingress_ifindex->bytes
    };

    DECLARE_LIBBPF_OPTS(bpf_test_run_opts, topts,
            .data_in = buf,
            .data_size_in = user_buf->numBytes + sizeof(__u32),
            .data_out = buf_out,
            .data_size_out = user_buf->numBytes + sizeof(__u32),
            .ctx_in = &ctx_in,
            .ctx_size_in = sizeof(ctx_in)
    );

    log_debug("Now it is time to start running the BPF program");
	err = bpf_prog_test_run_opts(prog_fd, &topts);
    if (err) {
        log_error("Error running the BPF program: %d", err);
        ret_code = -1;
        goto end;
    }

    log_debug("Return code for the BPF program is: %d\n", topts.retval);
    
    log_debug("Let's now compare the output buffer with the expected output buffer.");
    ret = memcmp(buf, buf_out, user_buf->numBytes + sizeof(__u32));
    if (ret != 0) {
        log_error("ERROR: the output buffer is different from the expected output buffer.");
        ret_code = -1;
        goto end;
    }

    // Get filename from path
    char *ktest_file_copy = strdup(ktest_file);
    char *ktest_filename = basename(ktest_file_copy);

    // Remove extension from filename
    char *filename = strdup(ktest_filename);
    free(ktest_file_copy);
    char *dot = strrchr(filename, '.');
    if (dot)
        *dot = '\0';

    // Add json extension to filename
    char *json_filename = malloc(strlen(filename) + 5);
    if (!json_filename) {
        log_error("ERROR: failed to allocate memory for the JSON filename.");
        free(filename);
        ret_code = -1;
        goto end;
    }

    strcpy(json_filename, filename);
    strcat(json_filename, ".json");
    free(filename);

    // Create JSON file
    json_object *root = json_object_new_object();
    if (!root) {
        ret_code = -1;
        goto end;
    }

    // Add the name of the BPF program
    json_object *prog_name = json_object_new_string(bpf_program__name(prog));
    if (!prog_name) {
        ret_code = -1;
        goto end;
    }
    json_object_object_add(root, "prog_name", prog_name);

    // Add the name of the Ktest file
    json_object *ktest_name = json_object_new_string(ktest_file);
    if (!ktest_name) {
        ret_code = -1;
        goto end;
    }
    json_object_object_add(root, "ktest_name", ktest_name);

    // Add the return value of the BPF program
    json_object *ret_val = json_object_new_int(topts.retval);
    if (!ret_val) {
        ret_code = -1;
        goto end;
    }
    json_object_object_add(root, "ret_val", ret_val);

    // Add the output buffer
    json_object *output_buf = json_object_new_string_len(buf_out + sizeof(__u32), user_buf->numBytes);
    if (!output_buf) {
        ret_code = -1;
        goto end;
    }
    json_object_object_add(root, "output_buf", output_buf);

    char *final_filename = malloc(strlen(res_dir) + strlen(json_filename) + 2);
    strcpy(final_filename, res_dir);
    strcat(final_filename, "/");
    strcat(final_filename, json_filename);

    // Create path to the JSON file
    char *json_dir = strdup(final_filename);
    char *json_dirname = dirname(json_dir);
    if (access(json_dirname, F_OK) == -1) {
        if (mkdir(json_dirname, 0777) == -1) {
            log_error("ERROR: failed to create directory %s", json_dirname);
            ret_code = -1;
            goto end;
        }
    }
    free(json_dir);

    // Save the JSON file
    if (json_object_to_file_ext(final_filename, root, JSON_C_TO_STRING_PRETTY)) {
        log_error("Error: failed to save %s!!", final_filename);
        log_error("Error: %s", json_util_get_last_err());
    } else {
        log_info("%s saved", final_filename);
    }

    ret_code = 0;

end:
    kTest_free(input);
    free(buf);
    free(buf_out);
    free(json_filename);
    free(final_filename);
    return ret_code;
}

int main(int argc, const char **argv) {
    const char *bpf_file = NULL;
    const char *ktest_file = NULL;
    const char *input_dir = NULL;
    char *res_dir = NULL;

    struct bpf_program *prog;
	struct bpf_object *obj;
    int prog_fd;

    struct argparse_option options[] = {
        OPT_HELP(),
        OPT_GROUP("Basic options"),
        OPT_STRING('b', "bpf_file", &bpf_file, "BPF object file", NULL, 0, 0),
        OPT_STRING('k', "ktest_file", &ktest_file, "KLEE Ktest file", NULL, 0, 0),
        OPT_STRING('i', "input_dir", &input_dir, "Dir with a list of KLEE Ktest files", NULL, 0, 0),
        OPT_STRING('d', "res_dir", &res_dir, "Save results into this directory (default 'test')", NULL, 0, 0),
        OPT_END(),
    };

    struct argparse argparse;
    argparse_init(&argparse, options, usages, 0);
    argparse_describe(&argparse, "\nThis program runs a BPF program against a given KLEE ktest file.", 
        "If the program is equivalent, it will return 0. Otherwise, it will return 1.");

    argc = argparse_parse(&argparse, argc, argv);

    if (bpf_file == NULL) {
        log_error("Please specify a BPF object file.");
        exit(1);
    }

    if (ktest_file == NULL && input_dir == NULL) {
        log_error("Please specify a KLEE Ktest file or a directory with KLEE Ktest files.");
        exit(1);
    }

    if (res_dir == NULL) {
        log_warn("Directory not specified, using 'test' as default.");
        res_dir = malloc(5);
        strcpy(res_dir, "test");
    }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    obj = bpf_object__open(bpf_file);
	if (libbpf_get_error(obj))
		exit(1);

    log_debug("BPF object opened, let's now get the program.");

    prog = bpf_object__next_program(obj, NULL);
	if (bpf_object__load(obj))
		goto out;

	prog_fd = bpf_program__fd(prog);

    if (fill_maps_with_correct_values(obj) != 0) {
        log_error("Error: failed to fill maps with correct values.");
        goto out;
    }

    // Get all files from the input directory
    if (input_dir != NULL) {
        DIR *d;
        struct dirent *dir;
        d = opendir(input_dir);
        if (d) {
            while ((dir = readdir(d)) != NULL) {
                if (dir->d_type == DT_REG) {
                    if (strstr(dir->d_name, ".ktest") != NULL) {
                        log_debug("Found Ktest file: %s", dir->d_name);
                        char* ktest_file_in_dir = malloc(strlen(input_dir) + strlen(dir->d_name) + 2);
                        strcpy(ktest_file_in_dir, input_dir);
                        strcat(ktest_file_in_dir, "/");
                        strcat(ktest_file_in_dir, dir->d_name);
                        // Run BPF program against ktestfile
                        run_bpf_program_with_ktest_file(prog_fd, ktest_file_in_dir, res_dir, prog);
                        free(ktest_file_in_dir);
                    }
                }
            }
            closedir(d);
        }
    } else {
        // Run BPF program against ktestfile
        run_bpf_program_with_ktest_file(prog_fd, ktest_file, res_dir, prog);
    }

out:
    if (res_dir) {
        free(res_dir);
    }
	bpf_object__close(obj);

    return 0;
}
