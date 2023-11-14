FROM ubuntu:18.04 as llvm-builder

ARG DEBIAN_FRONTEND=noninteractive
ARG LLVM_RELEASE=8.0.0

RUN apt-get -qq update \
 && apt-get -qq install --no-install-recommends \
    build-essential \
    ca-certificates \
    libnuma-dev \
    python3-pip \
    python3-pyelftools \
    python3-setuptools \
    wget \
	curl \
	git \
	libgoogle-perftools-dev \
	python2.7 \
	python3-minimal \
	parallel \
	xz-utils \
	gcc-multilib \
	graphviz \
	cmake \
    sudo net-tools \
    psmisc procps \
    iproute2 git \
    linux-headers-generic \
    python3 python3-pip \
    python \
    gperf \
    libgoogle-perftools-dev \
    libpcap-dev \
    bison \
    flex \
    zlib1g-dev \
    libncurses5-dev \
    libpcap-dev \
    python2.7 \
    python-dev \
    python3-dev \
    libedit-dev \
    libreadline-dev

RUN pip3 install meson ninja

RUN apt-get -qq update \
 && apt-get -qq install --no-install-recommends \
    swig

RUN mkdir -p /tmp/scripts
ADD scripts/llvm/checkout.sh /tmp/scripts/checkout.sh
RUN chmod +x /tmp/scripts/checkout.sh
ADD scripts/llvm/build_install_llvm.sh /tmp/scripts/build_install_llvm.sh
RUN chmod +x /tmp/scripts/build_install_llvm.sh

RUN mkdir -p /llvm
RUN /tmp/scripts/checkout.sh -b llvmorg-$LLVM_RELEASE
# Run the build. Results of the build will be available at /llvm/.
RUN /tmp/scripts/build_install_llvm.sh --to /llvm -i install -- \
    -DLLVM_TARGETS_TO_BUILD="X86;BPF" \
    -DLLVM_ENABLE_PROJECTS="all" \
    -DLLVM_INCLUDE_UTILS=ON \
    -DLLVM_INSTALL_UTILS=ON

FROM ocaml/opam:ubuntu-18.04-ocaml-4.06

ARG DEBIAN_FRONTEND=noninteractive
ARG DPDK_RELEASE=18.11
ARG PIN_RELEASE=3.16-98275-ge0db48c31
ARG Z3_RELEASE=z3-4.5.0
ARG OCAML_RELEASE=4.06.0
ARG KLEE_RELEASE=master
ARG KLEE_UCLIBC_RELEASE=klee_uclibc_v1.2

ENV PATH="/llvm/build/bin:$PATH"

COPY --from=llvm-builder /llvm/ /llvm/build/

WORKDIR /pix

ADD install /pix/install

USER root
RUN apt-get -qq update \
 && apt-get -qq install --no-install-recommends \
    build-essential \
    ca-certificates \
    libnuma-dev \
    python3-pip \
    python3-pyelftools \
    python3-setuptools \
    wget \
	curl \
	git \
	libgoogle-perftools-dev \
	python2.7 \
	python3-minimal \
	parallel \
	xz-utils \
	gcc-multilib \
	graphviz \
	cmake

RUN pip3 install meson ninja

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get -yq install sudo net-tools \
                                                        psmisc procps \
                                                        iproute2 git \
                                                        linux-headers-generic \
                                                        python3 python3-pip \
                                                        python

# Install and compile DPDK
WORKDIR /dpdk

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get -yq install gperf \
                                                       libgoogle-perftools-dev \
                                                       libpcap-dev

ENV RTE_TARGET=x86_64-native-linuxapp-gcc
ENV RTE_SDK=/dpdk

RUN curl -s "https://fast.dpdk.org/rel/dpdk-$DPDK_RELEASE.tar.xz" | tar xJf -
RUN mv "dpdk-$DPDK_RELEASE"/* .
RUN for p in /pix/install/dpdk.*.patch; do \
        patch -p 1 < "$p"; \
    done

# Must be applied last.
RUN patch -p1 < /pix/install/replay.dpdk.patch

# Compile
RUN meson build \
    && cd build \
    && ninja \
    && DESTDIR=. ninja install \
    && ldconfig \
    && cp usr/local/include/rte_string_fns.h lib/librte_cmdline/

# Install and compile PIN
WORKDIR /pin

ENV PINDIR=/pin
ENV PATH="/pin:$PATH"

RUN curl -s "https://software.intel.com/sites/landingpage/pintool/downloads/pin-$PIN_RELEASE-gcc-linux.tar.gz" | tar xzf -
RUN mv "pin-$PIN_RELEASE-gcc-linux"/* .

# Install and compile Z3
WORKDIR /z3
RUN git clone --depth 1 --branch "$Z3_RELEASE" https://github.com/Z3Prover/z3 /z3
RUN python scripts/mk_make.py --prefix=/z3/build
RUN cd build \
    && make -kj \
    && make install

# Install and compile LLVM
WORKDIR /llvm
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get -yq install bison \
                                                       flex \
                                                       zlib1g-dev \
                                                       libncurses5-dev \
                                                       libpcap-dev \
                                                       python2.7 

# ENV PATH="/llvm/build/bin:$PATH"

# COPY --from=llvm-builder /tmp/clang-install/ /llvm/build/
# RUN git clone --branch llvmorg-$LLVM_RELEASE --depth 1 https://github.com/llvm/llvm-project /llvm-project
# RUN mv /llvm-project/llvm/* /llvm/
# RUN mv /llvm-project/clang /llvm/tools/clang
# RUN rm -rf /llvm-project
# RUN mkdir build \
#     && cd build \
#     && CXXFLAGS="-D_GLIBCXX_USE_CXX11_ABI=0" cmake ../ \
#     && nproc=$(nproc) \
#     && nproc_div=$((nproc/2)) \
#     && make -kj$nproc_div 

# Install and compile KLEE UCLIBC
WORKDIR /klee-uclibc

RUN git clone --depth 1 --branch "$KLEE_UCLIBC_RELEASE" https://github.com/klee/klee-uclibc.git /klee-uclibc
RUN ./configure \
    --make-llvm-lib \
    --with-llvm-config="/llvm/build/bin/llvm-config" \
    --with-cc="/llvm/build/bin/clang"

RUN cp "/pix/install/klee-uclibc.config" '.config'
RUN make -kj

# Install and compile OCAML
RUN apt update && apt install -yq libgmp-dev
# RUN opam init -y

# RUN if opam --version | grep '^1.' >/dev/null ; then \
# 		opam switch $OCAML_RELEASE \
# 	else \
# 		opam switch list \
# 		if ! opam switch list 2>&1 | grep -Fq 4.06 ; then \
# 			opam switch create $OCAML_RELEASE \
# 		fi \
# 	fi

# ENV PATH="$HOME/.opam/system/bin:$PATH"
RUN eval $(opam env) && opam install goblint-cil core -y \
    && opam install ocamlfind num -y \
    && opam install ocamlfind sexplib menhir -y

ADD patches /pix/patches

# Install and compile KLEE
WORKDIR /klee

RUN pip3 install lit

ENV KLEE_INCLUDE=/klee/include
ENV PATH="/klee/build/bin:$PATH"

RUN git clone --branch "$KLEE_RELEASE" --recurse-submodules https://github.com/bolt-perf-contracts/klee.git /klee
RUN for p in /pix/patches/klee*.patch; do \
        patch -p 1 < "$p"; \
    done
RUN ./build.sh

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get -yq install libelf-dev \
                                                       pkg-config \
                                                       time 

RUN cd /llvm/build/bin && rm -rf clang-check clang-tidy clangd lldb-test c-index-test lldb-server \
                           bugpoint clang-import-test lli clang-query clang-refactor clang-change-namespace \
                           clang-rename clang-reorder-fields clang-extdef-mapping clang-include-fixer \
                           llvm-c-test modularize diagtool clang-offload-bundler llvm-split llvm-link \
                           llvm-extract opt lld llvm-* find-all-symbols dsymutil verify-uselistorder \
                           sancov obj2yaml sanstats yaml2obj lli-child-target clang-apply-replacements \
                           clang-format lldb-mi lldb-vscode

RUN cd /llvm/build/lib && rm -rf *.a

ENV LD_LIBRARY_PATH=/llvm/build/lib:/klee/build/lib/:$LD_LIBRARY_PATH

WORKDIR /libjson-c

RUN git clone --depth 1 --branch json-c-0.17-20230812 https://github.com/json-c/json-c.git /libjson-c
RUN mkdir json-c-build
RUN cd json-c-build \
    && cmake .. \
    && make -j \
    && make install

ENV LD_LIBRARY_PATH=/usr/local/lib:/llvm/build/lib:/klee/build/lib/:$LD_LIBRARY_PATH

WORKDIR /pix

ADD ebpf-nfs/common /pix/ebpf-nfs/common
ADD ebpf-nfs/headers /pix/ebpf-nfs/headers
ADD ebpf-nfs/libbpf-stubbed /pix/ebpf-nfs/libbpf-stubbed
ADD ebpf-nfs/Makefile /pix/ebpf-nfs/Makefile

ADD scripts /pix/scripts
# ADD dpdk-nfs/ /pix/dpdk-nfs

CMD ["/bin/bash"]