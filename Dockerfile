FROM ubuntu:22.04 AS build

ARG DEBIAN_FRONTEND=noninteractive

# Update and install essential packages
RUN apt-get -qq update \
    && apt-get -qq install -y \
    build-essential \
    cmake \
    curl \
    doxygen \
    file \
    gcc-multilib \
    g++-multilib \
    git \
    graphviz \
    libcap-dev \
    libelf-dev \
    libgoogle-perftools-dev \
    libncurses5-dev \
    libnuma-dev \
    libsqlite3-dev \
    libssl-dev \
    libtcmalloc-minimal4 \
    libtool \
    nano \
    parallel \
    pkg-config \
    python2.7 \
    python3-minimal \
    python3-pip \
    sudo \
    time \
    unzip \
    && apt-get -qq clean

WORKDIR /ebpf-se
ADD tool-ebpf-se/deps /ebpf-se/deps

# Install LLVM
RUN apt-get -qq install -y \
    clang-12 llvm-12 llvm-12-dev llvm-12-tools

# Install Z3 from source
RUN mkdir -p /ebpf-se/deps \
    && cd /ebpf-se/deps \
    && git clone --depth 1 --branch z3-4.8.15 https://github.com/Z3Prover/z3 \
    && cd z3 \
    && python3 scripts/mk_make.py -p /ebpf-se/deps/z3/build \
    && cd build \
    && make -j$(nproc) \
    && make install

# Install KLEE-uClibc from source
RUN cd /ebpf-se/deps \
    && git clone --depth 1 --branch klee_uclibc_v1.3 https://github.com/klee/klee-uclibc.git \
    && cd klee-uclibc \
    && ./configure --make-llvm-lib \
        --with-llvm-config="/usr/bin/llvm-config-12" \
        --with-cc="/usr/bin/clang-12" \
    && cp /ebpf-se/deps/klee-uclibc.config .config \
    && make -j$(nproc)

# Install KLEE from source
RUN cd /ebpf-se/deps \
    && git clone https://github.com/klee/klee.git \
    && cd klee \
    && git checkout v3.1 \
    && mkdir -p build \
    && cd build \
    && cmake -DENABLE_UNIT_TESTS=OFF \
        -DENABLE_SYSTEM_TESTS=OFF \
        -DBUILD_SHARED_LIBS=OFF \
        -DENABLE_SOLVER_Z3=ON \
        -DENABLE_KLEE_UCLIBC=ON \
        -DKLEE_UCLIBC_PATH="/ebpf-se/deps/klee-uclibc" \
        -DENABLE_POSIX_RUNTIME=ON \
        -DCMAKE_BUILD_TYPE=Debug \
        -DENABLE_KLEE_ASSERTS=ON \
        -DENABLE_DOXYGEN=ON \
        -DCMAKE_PREFIX_PATH="/ebpf-se/deps/z3/build" \
        -DCMAKE_INCLUDE_PATH="/ebpf-se/deps/z3/build/include/" \
        -DLLVM_CONFIG_BINARY="/usr/bin/llvm-config-12" \
        -DLLVMCC="/usr/bin/clang-12" \
        -DLLVMCXX="/usr/bin/clang++-12" \
        .. \
    && make -j$(nproc) \
    && make install

WORKDIR /libjson-c

RUN git clone --depth 1 --branch json-c-0.17-20230812 https://github.com/json-c/json-c.git /libjson-c
RUN mkdir json-c-build
RUN cd json-c-build \
    && cmake .. \
    && make -j \
    && sudo make install

WORKDIR /ebpf-se

# ENV LD_LIBRARY_PATH=/usr/local/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}

# Set environment variables
ENV PATH=/ebpf-se/deps/klee/build/bin:$PATH \
    KLEE_INCLUDE=/ebpf-se/deps/klee/include \
    KLEE_LIB=/ebpf-se/deps/klee/build/lib/ 

ADD libbpf-stubbed /ebpf-se/libbpf-stubbed

# Add startup script and set it as entrypoint
# COPY /ebpf-se/tool/startup.sh /ebpf-se/tool/startup.sh
# RUN chmod +x /ebpf-se/tool/startup.sh
# ENTRYPOINT ["/ebpf-se/tool/startup.sh"]
CMD ["/bin/bash"]
