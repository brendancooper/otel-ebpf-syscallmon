# syscall monitoring

This workspace contains an eBPF program `syscall_monitoring.c` and a libbpf-based user program `user_monitor.c` to load it and periodically flush per-PID, per-syscall statistics to stdout.

What it does
- Tracks per-PID, per-syscall count, sum latency, max latency, and bytes for sendmsg/recvmsg.
- Flushes and prints stats every 10 seconds.

Build
1. Install dependencies: libbpf, bpftool, clang, pkg-config, and kernel headers.

On Debian/Ubuntu you can try:

```bash
sudo apt-get install -y clang llvm libbpf-dev libbpfcc-dev bpftool build-essential pkg-config linux-headers-$(uname -r)
```

2. Build:

```bash
make
```

This creates `syscall_monitoring.bpf.o`, generates `syscall_monitoring.skel.h`, and builds the `user_monitor` binary.

Run

Run as root (required to load BPF programs):

```bash
sudo ./user_monitor
```

Specify a flush interval (seconds):

```bash
sudo ./user_monitor -i 5
```

Whitelist only specific process comm names (task names) using one or more `-c/--comm` flags. When any are supplied, only syscalls from tasks whose `comm` exactly matches a provided name (truncated to 15 chars like the kernel) are monitored. Example monitoring only `nginx` and `redis-server`:

```bash
sudo ./user_monitor -c nginx -c redis-server
```

Combine with interval:

```bash
sudo ./user_monitor -i 2 -c bash -c sshd
```

If no `-c/--comm` options are given, all processes are monitored (except the monitor itself).

Output
Every 10 seconds the program prints lines like:

PID: 1234  syscall: sendmsg (47)  count: 10  avg_ms: 0.123  max_ms: 0.456  bytes: 4096

Notes
- The user program contains a small syscall name map for common syscalls. You can extend `syscall_name()` with additional names or integrate a full syscall table.
- If bpftool is not available, generate the skeleton header manually or use libbpf's build system.

- By default the user-space monitor writes its own PID into a BPF map so the eBPF program ignores events from the monitor process (prevents the program from monitoring itself). To disable this behavior remove or skip populating the `monitor_pid_map` in `user_monitor.c`.

- Command filtering implementation details: the eBPF side keeps a hash map of allowed `comm` strings (up to 64 entries). A second array map holds a single enable flag. If filtering is enabled and a task's `comm` is not present, the event is skipped early. This minimizes per-event overhead when no filtering is requested (just a single flag check).
