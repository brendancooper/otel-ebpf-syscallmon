# Minimal Makefile for building the BPF object and user program

BPF_CLANG ?= clang
BPF_CFLAGS ?= -O2 -g -D__KERNEL__ -D__ASM_SYSREG_H -I/usr/include -I/usr/include/x86_64-linux-gnu
LIBBPF_CFLAGS ?= $(shell pkg-config --cflags libbpf 2>/dev/null || echo "-I/usr/include -I/usr/include/x86_64-linux-gnu")
LIBBPF_LDFLAGS ?= $(shell pkg-config --libs libbpf 2>/dev/null || echo "-lbpf -lelf -lz -pthread")

# Ensure user program links libcap for runtime capability checks

BPF_OBJ = syscall_monitoring.bpf.o
BPF_C = syscall_monitoring.c
USER = user_monitor

.PHONY: all clean

all: $(BPF_OBJ) $(USER)

$(BPF_OBJ): $(BPF_C)
	$(BPF_CLANG) -target bpf -c $< -o $@ $(BPF_CFLAGS)

$(USER): user_monitor.c syscall_monitoring.skel.h
	$(CC) -O2 -g user_monitor.c -o $(USER) $(LIBBPF_CFLAGS) $(LIBBPF_LDFLAGS)

syscall_monitoring.skel.h: $(BPF_OBJ)
	bpftool gen skeleton $(BPF_OBJ) > $@

clean:
	rm -f $(BPF_OBJ) $(USER) syscall_monitoring.skel.h
