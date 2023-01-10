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

#include <argparse.h>
#include <net/if.h>

#include "log.h"

int main(int argc, const char **argv) {
    printf("Hello world!\n");
    return 0;
}
