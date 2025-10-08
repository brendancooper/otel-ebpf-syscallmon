# Minimal Makefile for building the BPF object and user program

BPF_CLANG ?= clang
BPF_CFLAGS ?= -O2 -g -D__KERNEL__ -D__ASM_SYSREG_H -D__TARGET_ARCH_x86 -I/usr/include -I/usr/include/x86_64-linux-gnu -I.
LIBBPF_CFLAGS ?= $(shell pkg-config --cflags libbpf 2>/dev/null || echo "-I/usr/include -I/usr/include/x86_64-linux-gnu")
LIBBPF_LDFLAGS ?= $(shell pkg-config --libs libbpf 2>/dev/null || echo "-lbpf -lelf -lz -pthread")

# Ensure user program links libcap for runtime capability checks

BPF_OBJ = syscall_monitoring.bpf.o
BPF_C = syscall_monitoring.c
USER = user_monitor

.PHONY: all clean

all: vmlinux.h $(BPF_OBJ) $(USER)

vmlinux.h:
	@if [ -f /sys/kernel/btf/vmlinux ]; then \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h; \
		else echo "ERROR: /sys/kernel/btf/vmlinux not found (install kernel BTF or headers)" >&2; exit 1; fi

$(BPF_OBJ): $(BPF_C) vmlinux.h
	$(BPF_CLANG) -target bpf -c $< -o $@ $(BPF_CFLAGS)

$(USER): user_monitor.go $(BPF_OBJ)
	GO111MODULE=on go mod tidy
	GO111MODULE=on CGO_ENABLED=0 go build -o $(USER) user_monitor.go

syscall_monitoring.skel.h: $(BPF_OBJ)
	bpftool gen skeleton $(BPF_OBJ) > $@

clean:
	rm -f $(BPF_OBJ) $(USER) syscall_monitoring.skel.h vmlinux.h
