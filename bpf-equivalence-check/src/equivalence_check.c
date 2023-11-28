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

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>

#include <argparse.h>
#include <net/if.h>
#include <json-c/json.h>

#include "log.h"
#include "ktest.h"

#define A_PORT  6
#define B_PORT 7

#ifndef BPFTOOL_PATH
#define BPFTOOL_PATH "/usr/sbin/bpftool"
#endif

const char *bpf_file = NULL;
const char *ktest_file = NULL;
const char *input_dir = NULL;
const char *input_map_dir = NULL;
const char *res_dir = NULL;
const char *bpf_tool = BPFTOOL_PATH;

struct packet {
  struct ethhdr ether;
  struct iphdr ipv4;
  struct tcphdr tcp;
  char payload[1500];
} __attribute__((__packed__));

static const char *const usages[] = {
    "equivalence_check [options] [[--] args]",
    "equivalence_check [options]",
    NULL,
};

void byte_array_to_hex_string(unsigned char *byte_array, int array_length, char *output) {
    static const char hex_chars[] = "0123456789ABCDEF";
    int i;
    for (i = 0; i < array_length; i++) {
        output[i * 2] = hex_chars[(byte_array[i] >> 4) & 0xF];
        output[i * 2 + 1] = hex_chars[byte_array[i] & 0xF];
    }
    output[i * 2] = '\0';
}

KTestObject* get_ktest_object_by_name(KTest* input, const char* name) {
    for (int i = 0; i < input->numObjects; i++) {
        KTestObject* obj = &input->objects[i];
        if (strcmp(obj->name, name) == 0) {
            return obj;
        }
    }

    return NULL;
}

const char* get_filename_from_path(const char *path) {
    const char *filename = strrchr(path, '/');  // For Unix-like systems
    if (filename) {
        return filename + 1;  // Skip the '/'
    }
    return path;  // Return the original path if no '/' is found
}

char *get_json_file_from_dir(const char *input_map_dir, const char *filename) {
    DIR *d;
    struct dirent *dir;
    d = opendir(input_map_dir);
    if (d) {
        while ((dir = readdir(d)) != NULL) {
            if (dir->d_type == DT_REG) {
                if (strstr(dir->d_name, filename) != NULL) {
                    // log_debug("Found JSON file: %s", dir->d_name);

                    char* json_file = malloc(strlen(input_map_dir) + strlen(dir->d_name) + 2);
                    strcpy(json_file, input_map_dir);
                    strcat(json_file, "/");
                    strcat(json_file, dir->d_name);

                    return json_file;
                }
            }
        }
        closedir(d);
    }

    return NULL;
}

int fill_maps_with_correct_values(struct bpf_object *obj, int prog_fd, const char *ktest_file_name, const char *input_map_dir, char ***map_names, int *map_names_count) {
    /* Get basename from path */
    const char *ktest_file_basename = get_filename_from_path(ktest_file_name);

    /* Copy basename */
    char *filename = strdup(ktest_file_basename);

    /* Remove extension from filename */
    char *dot = strrchr(filename, '.');
    if (dot) *dot = '\0';

    /* Add json extension to filename */
    char *json_filename = malloc(strlen(filename) + strlen(".json") + 1);
    strcpy(json_filename, filename);
    strcat(json_filename, ".json");

    log_trace("JSON filename: %s", json_filename);

    free(filename);
    
    char *json_file = get_json_file_from_dir(input_map_dir, json_filename);
    free(json_filename);

    if (json_file == NULL) {
        log_error("ERROR: JSON file %s not found for Ktest file %s", json_file, ktest_file_name);
        return -1;
    }

    log_debug("JSON file found: %s", json_file);

    json_object *root = json_object_from_file(json_file);
    if (!root) {
        log_error("ERROR: failed to parse JSON file %s", json_file);
        return -1;
    }

    *map_names_count = json_object_object_length(root);
    *map_names = malloc(*map_names_count * sizeof(char *));
    if (*map_names == NULL) {
        log_error("ERROR: failed to allocate memory for map_names");
        return -1;
    }

    int i = 0;
    json_object_object_foreach(root, map_name, val) {
        log_debug("Found key: %s", map_name);
        (*map_names)[i++] = strdup(map_name);

        struct bpf_map *map = bpf_object__find_map_by_name(obj, map_name);
        if (map == NULL) {
            log_error("ERROR: map %s not found!", map_name);
            return -1;
        }

        int map_fd = bpf_map__fd(map);

        /* Get info about this BPF map */
        struct bpf_map_info map_info = {};
        uint32_t info_len = sizeof(map_info);

        if (bpf_obj_get_info_by_fd(map_fd, &map_info, &info_len)) {
            log_error("ERROR: failed to get info for map %s", map_name);
            return -1;
        }

        if (json_object_is_type(val, json_type_object)) {
            json_object_object_foreach(val, lookup_str, lookup_val) {
                int lookup_num = atoi(lookup_str);

                log_trace("For map %s, lookup_num: %d", map_name, lookup_num);

                bool has_value = true;
                /* Check if val has a field called "hasValue" */
                json_object *has_value_obj;
                if (json_object_object_get_ex(lookup_val, "hasValue", &has_value_obj)) {
                    if (json_object_is_type(has_value_obj, json_type_boolean)) {
                        has_value = json_object_get_boolean(has_value_obj);
                    } else {
                        log_error("ERROR: hasValue field for map %s is not a boolean (lookup_num %d)", map_name, lookup_num);
                        return -1;
                    }
                }

                if (has_value) {
                    const char *key;
                    const char *value;
                    int key_len = 0;
                    int value_len = 0;

                    /* Check if val has a field called "key" */
                    json_object *key_obj;
                    if (json_object_object_get_ex(lookup_val, "key", &key_obj)) {
                        if (json_object_is_type(key_obj, json_type_string)) {
                            key = json_object_get_string(key_obj);
                        } else {
                            log_error("ERROR: key for map %s is not a string (lookup_num %d)", map_name, lookup_num);
                            return -1;
                        }
                    } else {
                        log_error("ERROR: key not found for map %s (lookup_num %d)", map_name, lookup_num);
                        return -1;
                    }

                    /* Check if val has a field called "value" */
                    json_object *value_obj;
                    if (json_object_object_get_ex(lookup_val, "value", &value_obj)) {
                        if (json_object_is_type(value_obj, json_type_string)) {
                            value = json_object_get_string(value_obj);
                        } else {
                            log_error("ERROR: value for map %s is not a string (lookup_num %d)", map_name, lookup_num);
                            return -1;
                        }
                    } else {
                        log_error("ERROR: value not found for map %s (lookup_num %d)", map_name, lookup_num);
                        return -1;
                    }

                    /* Check if val has a field called "key_size" */
                    json_object *key_size_obj;
                    if (json_object_object_get_ex(lookup_val, "key_size", &key_size_obj)) {
                        if (json_object_is_type(key_size_obj, json_type_int)) {
                            key_len = json_object_get_int(key_size_obj);
                        } else {
                            log_error("ERROR: key_size for map %s is not an integer (lookup_num %d)", map_name, lookup_num);
                            return -1;
                        }
                    } else {
                        log_error("ERROR: key_size not found for map %s (lookup_num %d)", map_name, lookup_num);
                        return -1;
                    }

                    /* Check if val has a field called "value_size" */
                    json_object *value_size_obj;
                    if (json_object_object_get_ex(lookup_val, "value_size", &value_size_obj)) {
                        if (json_object_is_type(value_size_obj, json_type_int)) {
                            value_len = json_object_get_int(value_size_obj);
                        } else {
                            log_error("ERROR: value_size for map %s is not an integer (lookup_num %d)", map_name, lookup_num);
                            return -1;
                        }
                    } else {
                        log_error("ERROR: value_size not found for map %s (lookup_num %d)", map_name, lookup_num);
                        return -1;
                    }

                    log_trace("key: %s, value: %s, key_len: %d, value_len: %d", key, value, key_len, value_len);

                    if (key_len != map_info.key_size) {
                        log_error("ERROR: key_size for map %s is not correct (lookup_num %d) got %d, expected %d", map_name, lookup_num, key_len, map_info.key_size);
                        return -1;
                    }

                    if (value_len != map_info.value_size) {
                        log_error("ERROR: value_size for map %s is not correct (lookup_num %d) got %d, expected %d", map_name, lookup_num, value_len, map_info.value_size);
                        return -1;
                    }

                    /* Convert hex value to char array */
                    unsigned char *value_bytes = malloc(value_len);
                    if (!value_bytes) {
                        log_error("ERROR: failed to allocate memory for value_bytes");
                        return -1;
                    }

                    for (int i = 0; i < value_len; i++) {
                        sscanf(value + 2*i, "%02hhx", &value_bytes[i]);
                    }

                    /* Convert hex key to char array */
                    unsigned char *key_bytes = malloc(key_len);
                    if (!key_bytes) {
                        log_error("ERROR: failed to allocate memory for key_bytes");
                        return -1;
                    }

                    for (int i = 0; i < key_len; i++) {
                        sscanf(key + 2*i, "%02hhx", &key_bytes[i]);
                    }

                    if (bpf_map_update_elem(map_fd, key_bytes, value_bytes, BPF_ANY) == 0) {
                        log_debug("map %s updated with key %s and value %s", map_name, key, value);
                    } else {
                        log_error("ERROR: map %s not updated with key %s and value %s", map_name, key, value);
                        return -1;
                    }

                    free(key_bytes);
                    free(value_bytes);
                }
            }            
        }
    }

    /* Cleanup */
    free(json_file);
    json_object_put(root);

    return 0;
}

int run_bpf_program_with_ktest_file(struct bpf_object *obj, int prog_fd, const char* ktest_file, const struct bpf_program *prog, json_object *root) {
    KTest* input;
    int err, ret, ret_code = 0;
    char *buf, *buf_out;

    input = kTest_fromFile(ktest_file);
    if (!input) {
        log_error("ERROR: input file %s not valid.", ktest_file);
        return -1;
    }

    log_debug("Input file %s loaded.", ktest_file);
    log_debug("Now it is time to start parsing the KLEE Ktest file");

    log_debug("The Ktest file has %d objects.", input->numObjects);
    for (int i = 0; i < input->numObjects; i++) {
        KTestObject* obj = &input->objects[i];
        log_trace("Object %d has %d bytes.", i, obj->numBytes);
        log_trace("Object %d has name %s.", i, obj->name);
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

    log_debug("Return code for the BPF program is: %d", topts.retval);
    
    log_debug("Let's now compare the output buffer with the expected output buffer.");
    ret = memcmp(buf, buf_out, user_buf->numBytes + sizeof(__u32));
    if (ret != 0) {
        log_warn("ERROR: the output buffer is different from the expected output buffer.");
        // ret_code = -1;
        // goto end;
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

    // Allocate memory for the hex string
    char *input_hex_string = (char *)malloc(user_buf->numBytes * 2 + 1);

    // Convert the byte array to a hex string
    byte_array_to_hex_string((unsigned char *)buf + sizeof(__u32), user_buf->numBytes, input_hex_string);

    // Add the input buffer
    json_object *input_buf = json_object_new_string(input_hex_string);
    if (!input_buf) {
        ret_code = -1;
        goto end;
    }
    json_object_object_add(root, "input_buf", input_buf);

    // Allocate memory for the hex string
    char *output_hex_string = (char *)malloc(user_buf->numBytes * 2 + 1);

    // Convert the byte array to a hex string
    byte_array_to_hex_string((unsigned char *)buf_out + sizeof(__u32), user_buf->numBytes, output_hex_string);

    // Add the output buffer
    // json_object *output_buf = json_object_new_string_len(buf_out + sizeof(__u32), user_buf->numBytes);
    json_object *output_buf = json_object_new_string(output_hex_string);
    if (!output_buf) {
        ret_code = -1;
        goto end;
    }
    json_object_object_add(root, "output_buf", output_buf);

    ret_code = 0;

end:
    kTest_free(input);
    free(buf);
    free(buf_out);
    free(input_hex_string);
    free(output_hex_string);
    return ret_code;
}

int save_json_file(const char *ktest_file_name, const char *res_dir, json_object *root) {
    /* Get basename from path */
    const char *ktest_file_basename = get_filename_from_path(ktest_file_name);

    /* Copy basename */
    char *filename = strdup(ktest_file_basename);

    /* Remove extension from filename */
    char *dot = strrchr(filename, '.');
    if (dot) *dot = '\0';

    /* Add json extension to filename */
    char *json_filename = malloc(strlen(filename) + strlen(".json") + 1);
    strcpy(json_filename, filename);
    strcat(json_filename, ".json");

    log_trace("Output JSON filename: %s", json_filename);

    free(filename);
    
    char *final_filename = malloc(strlen(res_dir) + strlen(json_filename) + 2);
    strcpy(final_filename, res_dir);
    strcat(final_filename, "/");
    strcat(final_filename, json_filename);

    log_debug("Final filename: %s", final_filename);

    /* Create directory if it does not exist */
    struct stat st = {0};
    if (stat(res_dir, &st) == -1) {
        mkdir(res_dir, 0700);
    }

    // Save the JSON file
    if (json_object_to_file_ext(final_filename, root, JSON_C_TO_STRING_PRETTY)) {
        log_error("Error: failed to save %s!!", final_filename);
        log_error("Error: %s", json_util_get_last_err());
        return -1;
    } else {
        log_info("%s saved", final_filename);
    }

    free(json_filename);
    free(final_filename);

    return 0;
}

int dump_maps(struct bpf_object *obj, const char **map_names, int map_names_count, const char *ktest_file_in_dir, const char *res_dir, json_object *root) {
    int ret = 0;
    const char *ktest_file_basename = get_filename_from_path(ktest_file_in_dir);

    /* Copy basename */
    char *filename = strdup(ktest_file_basename);

    /* Remove extension from filename */
    char *dot = strrchr(filename, '.');
    if (dot) *dot = '\0';

    /* In this case, we also dump the maps, so that we can compare them */
    for (int i = 0; i < map_names_count; i++) {
        const char *map_name = map_names[i];

        log_debug("Dumping map %s", map_name);

        struct bpf_map *map = bpf_object__find_map_by_name(obj, map_name);
        if (map == NULL) {
            log_error("ERROR: map %s not found!", map_name);
            ret = -1;
            goto end;
        }

        int map_fd = bpf_map__fd(map);

        /* Get info about this BPF map */
        struct bpf_map_info map_info = {};
        uint32_t info_len = sizeof(map_info);

        if (bpf_obj_get_info_by_fd(map_fd, &map_info, &info_len)) {
            log_error("ERROR: failed to get info for map %s", map_name);
            ret = -1;
            goto end;
        }

        /* Dump this map using the bpftool command */
        char *cmd = malloc(strlen(bpf_tool) + strlen(" map dump -j id ") + 10);
        sprintf(cmd, "%s map dump -j -p id %d", bpf_tool, map_info.id);

        // log_debug("Running command: %s", cmd);

        /* Run command and redirect output to file */
        char *map_dump_file = malloc(strlen(res_dir) + strlen(filename) + strlen(map_name) + strlen(".json") + 3);
        strcpy(map_dump_file, res_dir);
        strcat(map_dump_file, "/");
        strcat(map_dump_file, filename);
        strcat(map_dump_file, ".");
        strcat(map_dump_file, map_name);
        strcat(map_dump_file, ".json");

        char *cmd_with_redirect = malloc(strlen(cmd) + strlen(" > ") + strlen(map_dump_file) + 1);
        strcpy(cmd_with_redirect, cmd);
        strcat(cmd_with_redirect, " > ");
        strcat(cmd_with_redirect, map_dump_file);

        log_debug("Running command: %s", cmd_with_redirect);

        if (system(cmd_with_redirect) != 0) {
            log_error("ERROR: failed to run command %s", cmd_with_redirect);
            ret = -1;
            goto cleanup;
        }

        json_object *map_dump = json_object_from_file(map_dump_file);
        if (!map_dump) {
            log_error("ERROR: failed to parse JSON file %s", map_dump_file);
            ret = -1;
            goto cleanup;
        }

        /* Remove file map_dump_file */
        if (remove(map_dump_file) != 0) {
            log_error("ERROR: failed to remove file %s", map_dump_file);
            ret = -1;
            goto cleanup;
        }

        /* Add the map dump to the root object */
        json_object_object_add(root, map_name, map_dump);

    cleanup:
        free(cmd);
        free(cmd_with_redirect);
        free(map_dump_file);
        if (ret < 0) {
            goto end;
        }
    }

end:
    free(filename);
    return ret;
}

int run_test(const char *ktest_file_name) {
    struct bpf_program *prog;
	struct bpf_object *obj;
    int prog_fd;
    int ret = 0;
    char* ktest_file_in_dir = NULL;

    obj = bpf_object__open(bpf_file);
    if (libbpf_get_error(obj)) {
        log_error("ERROR: failed to open BPF object file %s", bpf_file);
        return -1;
    }

    log_debug("BPF object opened, let's now get the program.");

    prog = bpf_object__next_program(obj, NULL);
    if (bpf_object__load(obj)) {
        log_error("ERROR: failed to load BPF object file %s", bpf_file);
        ret = -1;
        goto out;
    }

    prog_fd = bpf_program__fd(prog);

    char **map_names = NULL;
    int map_names_count = 0;

    /* Extract only file name, without extension */
    if (input_map_dir) {
        if (fill_maps_with_correct_values(obj, prog_fd, ktest_file_name, input_map_dir, &map_names, &map_names_count) != 0) {
            log_error("ERROR: failed to fill maps with correct values");
            ret = -1;
            goto out;
        }
    }

    /* Check if we can open the file from the ktest_file_name */
    if (access(ktest_file_name, F_OK) == -1) {
        ktest_file_in_dir = malloc(strlen(input_dir) + strlen(ktest_file_name) + 2);
        strcpy(ktest_file_in_dir, input_dir);
        strcat(ktest_file_in_dir, "/");
        strcat(ktest_file_in_dir, ktest_file_name);
    } else {
        ktest_file_in_dir = strdup(ktest_file_name);
    }

    log_debug("Let's now run the BPF program against the Ktest file %s", ktest_file_in_dir);

    /* Create JSON file */
    json_object *root = json_object_new_object();
    if (!root) {
        ret = -1;
        goto out;
    }

    /* Run BPF program against ktestfile */
    if (run_bpf_program_with_ktest_file(obj, prog_fd, ktest_file_in_dir, prog, root) != 0) {
        ret = -1;
        goto out;
    }

    if (input_map_dir) {
        if (dump_maps(obj, (const char **)map_names, map_names_count, ktest_file_in_dir, res_dir, root) != 0) {
            ret = -1;
            goto out;
        }
    }

    /* Save JSON file */
    if (save_json_file(ktest_file_in_dir, res_dir, root) != 0) {
        ret = -1;
        goto out;
    }

out:
    free(ktest_file_in_dir);
    bpf_object__close(obj);
    json_object_put(root);

    if (map_names) {
        for (int i = 0; i < map_names_count; i++) {
            free(map_names[i]);
        }
        free(map_names);
    }

    return ret;
}

int compare_strings(const void *a, const void *b) {
    return strcmp(*(const char **)a, *(const char **)b);
}

int main(int argc, const char **argv) {
    const char *log_file = NULL;
    FILE *log_fp = NULL;
    struct argparse_option options[] = {
        OPT_HELP(),
        OPT_GROUP("Basic options"),
        OPT_STRING('b', "bpf_file", &bpf_file, "BPF object file", NULL, 0, 0),
        OPT_STRING('k', "ktest_file", &ktest_file, "KLEE Ktest file", NULL, 0, 0),
        OPT_STRING('i', "input_dir", &input_dir, "Dir with a list of KLEE Ktest files", NULL, 0, 0),
        OPT_STRING('m', "input_map_dir", &input_map_dir, "Directory with the list of .json files with the input map values", NULL, 0, 0),
        OPT_STRING('d', "res_dir", &res_dir, "Save results into this directory", NULL, 0, 0),
        OPT_STRING('l', "log_file", &log_file, "Log file", NULL, 0, 0),
        OPT_STRING('t', "bpf_tool", &bpf_tool, "Path to bpftool", NULL, 0, 0),
        OPT_END(),
    };

    struct argparse argparse;
    argparse_init(&argparse, options, usages, 0);
    argparse_describe(&argparse, "\nThis program runs a BPF program against a given KLEE ktest file.", 
        "If the program is equivalent, it will return 0. Otherwise, it will return 1.");

    argc = argparse_parse(&argparse, argc, argv);

    log_set_level(LOG_TRACE);

    if (log_file != NULL) {
        FILE *log_fp = fopen(log_file, "w");
        if (log_fp == NULL) {
            log_error("ERROR: failed to open log file %s", log_file);
            exit(1);
        }

        log_add_fp(log_fp, LOG_TRACE);
    }

    if (bpf_file == NULL) {
        log_error("Please specify a BPF object file.");
        exit(1);
    }

    if (ktest_file == NULL && input_dir == NULL) {
        log_error("Please specify a KLEE Ktest file or a directory with KLEE Ktest files.");
        exit(1);
    }

    if (input_map_dir == NULL) {
        log_warn("You didn't specify any directory with the input map values. The maps will be filled with default values (0).");
    }

    if (input_map_dir) {
        /* Let's check if the binary tool "bpftool" is available. 
         * We need it to dump the maps. 
         */
        if (access(bpf_tool, X_OK) == -1) {
            log_error("ERROR: bpftool not found. Please install it.");
            exit(1);
        }

        /* Let's also check if the folder exists and contains some entries */
        DIR *d;
        struct dirent *dir;
        d = opendir(input_map_dir);

        if (d) {
            int file_count = 0;

            while ((dir = readdir(d)) != NULL) {
                if (dir->d_type == DT_REG) {
                    if (strstr(dir->d_name, ".json") != NULL) {
                        file_count++;
                    }
                }
            }

            if (file_count == 0) {
                log_error("ERROR: directory %s is empty", input_map_dir);
                exit(1);
            }

            closedir(d);
        } else {
            log_error("ERROR: directory %s does not exist", input_map_dir);
            exit(1);
        }
    }

    if (res_dir == NULL) {
        log_error("Please specify a directory to save the results.");
        exit(1);
    }

    int ktest_files_count = 0;

    if (input_dir != NULL) {
        /* Let's also check if the folder exists and contains some entries */
        DIR *d;
        struct dirent *dir;
        d = opendir(input_dir);

        if (d) {
            while ((dir = readdir(d)) != NULL) {
                if (dir->d_type == DT_REG) {
                    if (strstr(dir->d_name, ".ktest") != NULL) {
                        ktest_files_count++;
                    }
                }
            }

            if (ktest_files_count == 0) {
                log_error("ERROR: directory %s is empty", input_dir);
                exit(1);
            }

            closedir(d);
        } else {
            log_error("ERROR: directory %s does not exist", input_dir);
            exit(1);
        }
    }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    // Get all files from the input directory
    if (input_dir != NULL) {
        DIR *d;
        struct dirent *dir;
        d = opendir(input_dir);
        if (d) {
            char **file_list = malloc(ktest_files_count * sizeof(char *));
            // char *file_list[1024];
            int file_count = 0;

            printf("Reading Ktest files from directory %s\n", input_dir);

            while ((dir = readdir(d)) != NULL) {
                if (dir->d_type == DT_REG) {
                    if (strstr(dir->d_name, ".ktest") != NULL) {
                        file_list[file_count] = strdup(dir->d_name);
                        file_count++;
                    }
                }
            }

            printf("Found %d Ktest files\n", file_count);
            // Sort the file names alphabetically
            qsort(file_list, file_count, sizeof(char *), compare_strings);

            for (int i = 0; i < file_count; ++i) {
                log_debug("Found Ktest file: %s", file_list[i]);

                if (run_test(file_list[i]) != 0) {
                    log_error("ERROR: failed to run BPF program against Ktest file %s", file_list[i]);
                }
                
                // Free the duplicated string
                free(file_list[i]);
            }
            
            closedir(d);
            free(file_list);
        }
    } else {
        // Run BPF program against ktestfile
        if (run_test(ktest_file) != 0) {
            log_error("ERROR: failed to run BPF program against Ktest file %s", ktest_file);
        }
    }

    if (log_fp != NULL) {
        fclose(log_fp);
    }

    return 0;
}
