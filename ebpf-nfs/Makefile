ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
LIBBPF_DIR:=$(ROOT_DIR)/../libbpf-stubbed/src
LIBBPF_ORIGINAL_DIR:=$(ROOT_DIR)/../../bpf-equivalence-check/libbpf/src
COMMON_DIR:=$(ROOT_DIR)/../common
PIX_DIR:= $(ROOT_DIR)/../..

LLC ?= llc
CLANG ?= clang
CC := gcc
PKG_CONFIG := pkg-config
UNAME_P := $(shell uname -p)

LIBJSON_PKG_CFLAGS := $(shell $(PKG_CONFIG) --cflags json-c)
LIBJSON_PKG_LIBS := $(shell $(PKG_CONFIG) --static --libs json-c)

XDP_C = ${XDP_TARGETS:=.c}
XDP_BPF = ${XDP_BPF_TARGETS:=.c}
XDP_OBJ = ${XDP_C:.c=.o}

OBJECT_LIBBPF = $(LIBBPF_DIR)/libbpf.a
OBJECT_LIBBPF_ORIGIN = $(LIBBPF_ORIGINAL_DIR)/libbpf.a

# Extend if including Makefile already added some
COMMON_OBJS += $(COMMON_DIR)/common_params.o $(COMMON_DIR)/common_user_bpf_xdp.o

# Create expansions for dependencies
COMMON_H := ${COMMON_OBJS:.o=.h}

EXTRA_DEPS +=

# BPF-prog kern and userspace shares struct via header file:
KERN_USER_H ?= $(wildcard common_kern_user.h)

LDFLAGS ?= -L$(LIBBPF_DIR)
LDFLAGS_ORIGIN ?= -L$(LIBBPF_ORIGINAL_DIR)

BPF_CFLAGS ?= -I$(LIBBPF_DIR)/build/usr/include/ -I../headers/ -I $(KLEE_INCLUDE)
BPF_CFLAGS_ORIGIN ?= -I$(LIBBPF_ORIGINAL_DIR)/build/usr/include/ -I../headers/
BPF_CFLAGS += -I /usr/include/$(UNAME_P)-linux-gnu
BPF_CFLAGS_ORIGIN += -I /usr/include/$(UNAME_P)-linux-gnu

ifeq ($(REPLAY), 1)
	BPF_CFLAGS += -DREPLAY
endif

clean:
	rm -rf $(LIBBPF_DIR)/build
	$(MAKE) -C $(LIBBPF_DIR) clean
	$(MAKE) -C $(COMMON_DIR) clean
	rm -f $(XDP_OBJ)
	rm -f *.ll *.bc *.o *.bin
	rm -f *~

clean-klee:
	rm -rf $(ROOT_DIR)/klee-*
	rm -f $(ROOT_DIR)/res-tree-*
	rm -f $(ROOT_DIR)/neg-tree*

llvm-check: $(CLANG) $(LLC)
	@for TOOL in $^ ; do \
		if [ ! $$(command -v $${TOOL} 2>/dev/null) ]; then \
			echo "*** ERROR: Cannot find tool $${TOOL}" ;\
			exit 1; \
		else true; fi; \
	done

xdp-target: $(XDP_C) Makefile $(KERN_USER_H) $(EXTRA_DEPS)
	$(CLANG) \
	    -target bpf \
	    -D __BPF_TRACING__ -DKLEE_VERIFICATION\
		-DOPENED_EQUIVALENCE\
	    $(BPF_CFLAGS) \
	    -I $(KLEE_INCLUDE) \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Werror \
	    -fno-builtin \
	    -O2 -emit-llvm -c -g $(XDP_C)
	# $(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

xdp-target-runtest: $(XDP_C) Makefile $(KERN_USER_H) $(EXTRA_DEPS)
	$(CLANG) \
	    -D __BPF_TRACING__ -DKLEE_VERIFICATION -DREPLAY \
		-DOPENED_EQUIVALENCE\
	    $(BPF_CFLAGS) \
		$(LIBJSON_PKG_CFLAGS) \
	    -I $(KLEE_INCLUDE) \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Werror \
	    -fno-builtin \
		-L/klee/build/lib/ \
		$(LIBJSON_PKG_LIBS) \
		-lkleeRuntest \
	    -O2 -o ${XDP_C:.c=.bin} $(XDP_C) 

xdp-target-origin: $(XDP_BPF) Makefile $(KERN_USER_H) $(EXTRA_DEPS)
	cp ${XDP_BPF:.c=.h} $(XDP_BPF)
	$(CLANG) \
	    -D __BPF_TRACING__ \
	    $(BPF_CFLAGS_ORIGIN) -DDEBUG \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Werror \
	    -fno-builtin \
	    -O2 -emit-llvm -c -g $(XDP_BPF)
	$(LLC) ${XDP_BPF:.c=.bc} -march=bpf -filetype=obj -o ${XDP_BPF:.c=.bpf.o}
	rm $(XDP_BPF)

libbpf:
	cd $(LIBBPF_DIR) && bash build.sh

libbpf-origin:
	cd $(LIBBPF_ORIGINAL_DIR) && rm -rf obj build && mkdir obj build && BUILD_STATIC_ONLY=y OBJDIR=obj DESTDIR=build make install

symbex:
	/usr/bin/time -v \
		klee -libc=uclibc --external-calls=concrete --disable-verify \
		-write-test-info \
		-solver-backend=z3 -exit-on-error -max-memory=750000 -search=dfs $(XDP_TARGETS).bc

helper-contracts:
	cd $(PIX_DIR)/dpdk-nfs/perf-contracts && make clean && make LLVM=TRUE

perf-contract:
	cd klee-last && $(KLEE_INCLUDE)/../scripts/process-traces.sh . verify-dpdk llvm Num_bucket_traversals 1 Num_hash_collisions 0  expired_flows 0

build-tests: clean libbpf xdp-target symbex

build-replay-tests: clean libbpf xdp-target-runtest

build-original: clean libbpf-origin xdp-target-origin

perf-interface: clean libbpf xdp-target symbex helper-contracts perf-contract
	bash $(KLEE_INCLUDE)/../scripts/tree-gen/build_trees.sh -m 1000 -n 0 -e llvm
