#!/bin/bash

# Install dependencies for bpf-equivalence-check
wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh 14

sudo apt update
sudo apt install cmake libbsd-dev
sudo apt install clang llvm libelf-dev libpcap-dev gcc-multilib build-essential linux-headers-$(uname -r) linux-tools-common linux-tools-generic tcpdump
