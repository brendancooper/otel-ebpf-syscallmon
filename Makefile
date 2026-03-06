# Minimal Makefile for building the BPF object and user program

BPF_CLANG ?= clang
BPF_CFLAGS ?= -O2 -g -D__KERNEL__ -D__ASM_SYSREG_H -D__TARGET_ARCH_x86 -I/usr/include -I/usr/include/x86_64-linux-gnu -I/usr/include/bpf -I.
LIBBPF_CFLAGS ?= $(shell pkg-config --cflags libbpf 2>/dev/null || echo "-I/usr/include -I/usr/include/x86_64-linux-gnu")
LIBBPF_LDFLAGS ?= $(shell pkg-config --libs libbpf 2>/dev/null || echo "-lbpf -lelf -lz -pthread")

# Ensure user program links libcap for runtime capability checks

BPF_OBJ = syscall_monitoring.bpf.o
BPF_C = syscall_monitoring.c
USER = syscall_monitor

.PHONY: all clean

all: vmlinux.h $(BPF_OBJ) $(USER)

vmlinux.h:
	@set -e; \
	KVER="$$(uname -r)"; \
	echo "Generating vmlinux.h for kernel $$KVER"; \
	if [ -f /sys/kernel/btf/vmlinux ]; then \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h; \
		echo "Generated vmlinux.h from /sys/kernel/btf/vmlinux"; \
		exit 0; \
	fi; \
	if [ -f "/lib/modules/$$KVER/vmlinux" ]; then \
		bpftool btf dump file "/lib/modules/$$KVER/vmlinux" format c > vmlinux.h && echo "Generated vmlinux.h from /lib/modules/$$KVER/vmlinux" && exit 0; \
	fi; \
	if [ -f "/boot/vmlinux-$$KVER" ]; then \
		bpftool btf dump file "/boot/vmlinux-$$KVER" format c > vmlinux.h && echo "Generated vmlinux.h from /boot/vmlinux-$$KVER" && exit 0; \
	fi; \
	# Try to download linux-image package and extract vmlinux if available
	mkdir -p /tmp/linux-image-debs; cd /tmp/linux-image-debs; \
	sudo apt-get update || true; \
	# attempt several package name patterns
	sudo apt-get download "linux-image-$$KVER" 2>/dev/null || true; \
	sudo apt-get download "linux-image-$$KVER-azure" 2>/dev/null || true; \
	sudo apt-get download "linux-image-unsigned-$$KVER" 2>/dev/null || true; \
	for d in ./*.deb; do \
		[ -f "$$d" ] || continue; \
		dpkg-deb -x "$$d" extracted || continue; \
		if [ -f extracted/boot/vmlinux* ]; then \
			F=$$(find extracted -type f -name 'vmlinux*' | head -n1); \
			bpftool btf dump file "$$F" format c > $(CURDIR)/vmlinux.h && echo "Generated vmlinux.h from $$d (extracted)" && exit 0; \
		fi; \
		rm -rf extracted; \
	done; \
	echo "ERROR: could not find kernel BTF (no /sys/kernel/btf/vmlinux or vmlinux in modules/ or boot/)." >&2; \
	echo "You can fix this by running the workflow on a runner that provides kernel BTF or by providing a vmlinux.h for the target kernel." >&2; \
	exit 1

$(BPF_OBJ): $(BPF_C) vmlinux.h
	$(BPF_CLANG) -target bpf -c $< -o $@ $(BPF_CFLAGS)


$(USER): syscall_monitor.go $(BPF_OBJ)
	GO111MODULE=on go mod tidy
	GO111MODULE=on CGO_ENABLED=0 go build -o $(USER) syscall_monitor.go

clean:
	rm -f $(BPF_OBJ) $(USER) vmlinux.h
