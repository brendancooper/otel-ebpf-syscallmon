Go user-space replacement for user_monitor.c

Build prerequisites:
- Go 1.21+
- bpftool available to build the BPF object and vmlinux.h
- Kernel with BTF at /sys/kernel/btf/vmlinux

Build:
  make

Run (as root or with CAP_BPF, CAP_PERFMON, CAP_SYS_RESOURCE):
  sudo ./user_monitor -i 10 -c nginx -c sshd

Notes:
- The program loads syscall_monitoring.bpf.o (already built by Makefile), attaches all syscall enter/exit tracepoints, and periodically prints and clears per-PID per-syscall stats from the syscall_stats_map.
- It writes its own PID into monitor_pid_map to avoid self-monitoring and supports optional comm filtering using allowed_comms_map and filter_enabled_map.
