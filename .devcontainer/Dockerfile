FROM registry.red-soft.ru/ubi8/ubi

RUN dnf -y update && \ 
    dnf makecache

RUN dnf -y install git gcc m4 gdb make cmake clang llvm iproute wget \
    bpftool \
    libpcap-devel elfutils-libelf-devel zlib-devel