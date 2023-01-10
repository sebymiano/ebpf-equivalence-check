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

#include <argparse.h>
#include <net/if.h>

#include "log.h"

static const char *const usages[] = {
    "bpf_run_test [options] [[--] args]",
    "bpf_run_test [options]",
    NULL,
};

int main(int argc, const char **argv) {
    const char *bpf_file = NULL;
    const char *ktest_file = NULL;
    const char *output_file = NULL;

    LIBBPF_OPTS(bpf_test_run_opts, topts);
    struct bpf_program *prog;
	struct bpf_object *obj;
    __u8 *buf;
    __u32 *offset;
    int err, prog_fd;

    struct argparse_option options[] = {
        OPT_HELP(),
        OPT_GROUP("Basic options"),
        OPT_STRING('b', "bpf_file", &bpf_file, "BPF object file", NULL, 0, 0),
        OPT_STRING('k', "ktest_file", &ktest_file, "KLEE Ktest file", NULL, 0, 0),
        OPT_STRING('o', "out_file", &output_file, "Save results into an output file", NULL, 0, 0),
        OPT_END(),
    };

    struct argparse argparse;
    argparse_init(&argparse, options, usages, 0);
    argparse_describe(&argparse, "\nThis program runs a BPF program against a given KLEE ktest file.", 
        "If the program is equivalent, it will return 0. Otherwise, it will return 1.");

    argc = argparse_parse(&argparse, argc, argv);

    if (bpf_file == NULL || ktest_file == NULL) {
        log_error("Please specify a BPF object file and a KLEE ktest file.");
        exit(1);
    }

    if (output_file == NULL) {
        log_error("Please specify an output file.");
        exit(1);
    }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    obj = bpf_object__open(bpf_file);
	if (libbpf_get_error(obj))
		return 1;

    log_debug("BPF object opened, let's now get the program.");

    prog = bpf_object__next_program(obj, NULL);
	if (bpf_object__load(obj))
		return 1;

	prog_fd = bpf_program__fd(prog);

	buf = malloc(128);
	if (!buf)
		goto out;

    memset(buf, 0, 128);
	offset = (__u32 *)buf;
	*offset = 16;
	buf[*offset] = 0xaa;		/* marker at offset 16 (head) */
	buf[*offset + 15] = 0xaa;	/* marker at offset 31 (head) */

	topts.data_in = buf;
	topts.data_out = buf;
	topts.data_size_in = 128;
	topts.data_size_out = 128;

	err = bpf_prog_test_run_opts(prog_fd, &topts);
    if (err) {
        log_error("Error running the BPF program: %d", err);
        exit(1);
    }

    log_debug("Return code for the BPF program is: %d\n", topts.retval);
	/* test_xdp_update_frags: buf[16,31]: 0xaa -> 0xbb */
	// ASSERT_OK(err, "xdp_update_frag");
	// ASSERT_EQ(topts.retval, XDP_PASS, "xdp_update_frag retval");
	// ASSERT_EQ(buf[16], 0xbb, "xdp_update_frag buf[16]");
	// ASSERT_EQ(buf[31], 0xbb, "xdp_update_frag buf[31]");

	free(buf);

out:
	bpf_object__close(obj);

    return 0;
}
