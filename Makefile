# Build: BPF objects (clang -target bpf) + userspace loader (Go, static arm64).
# Overridable so CI can point at system toolchain:
#   make GOC=go LIBBPF_INC=/usr/include
PB         := $(HOME)/jni-ebpf
CLANG      ?= clang
GOC        ?= $(PB)/go/bin/go
LIBBPF_INC ?= $(PB)/tools/usr/include
CFLAGS     := -O2 -g -target bpf -D__TARGET_ARCH_arm64 -I$(CURDIR) -I$(LIBBPF_INC) -Wall
LDFLAGS    := -s -w

.PHONY: all bpf build clean
all: build

loader/envprobe.bpf.o: bpf/envprobe.bpf.c vmlinux.h
	$(CLANG) $(CFLAGS) -c $< -o $@

loader/recon.bpf.o: bpf/recon.bpf.c vmlinux.h
	$(CLANG) $(CFLAGS) -c $< -o $@

bpf: loader/envprobe.bpf.o loader/recon.bpf.o

build: bpf
	cd loader && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 $(GOC) build -trimpath -ldflags "$(LDFLAGS)" -o ../jniprobe .

clean:
	rm -f loader/*.bpf.o jniprobe
