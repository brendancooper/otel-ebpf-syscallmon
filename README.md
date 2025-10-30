syscall-monitor — eBPF syscall latency/byte statistics

This repository contains an eBPF program (`syscall_monitoring.c`) and a Go-based userspace tool (`syscall_monitor.go`) that:

- Attaches to syscall enter/exit tracepoints.
- Aggregates per-PID, per-syscall statistics (count, total latency, max latency, bytes for I/O calls) in the kernel via BPF maps.
- Periodically reads and clears those stats and prints human-readable lines to stdout.

The original libbpf/C userspace was replaced with a Go implementation that uses `github.com/cilium/ebpf` to load and attach the pre-built BPF object (`syscall_monitoring.bpf.o`).

Requirements
------------
- Go 1.21 or newer (for building the userspace).
- bpftool (used by the Makefile to generate vmlinux.h when needed).
- Kernel BTF available at `/sys/kernel/btf/vmlinux` (required to compile the BPF object).

Build
-----
Build the BPF object and the Go userspace binary with:

```bash
make
```

This will produce:

- `syscall_monitoring.bpf.o` — compiled BPF object (from `syscall_monitoring.c`).
- `syscall_monitor` — the Go userspace binary (from `syscall_monitor.go`).

Run
---
`user_monitor` needs elevated privileges to attach BPF programs. Either run as root or grant the needed capabilities:

As root:

```bash
sudo ./syscall_monitor -i 10
```

Or grant capabilities and run as your user:

```bash
sudo setcap cap_bpf,cap_perfmon,cap_sys_resource+ep ./syscall_monitor
./syscall_monitor -i 10
```

Options
-------
- `-i`, `--interval <seconds>`: flush and print aggregated stats every N seconds (default: 10).
- `-c`, `--comm <name>`: add a task `comm` filter (repeatable). Only processes whose `/proc/<pid>/comm` matches any supplied name will be monitored. Names are truncated to 16 bytes to match kernel TASK_COMM_LEN.
 - `--otlp-endpoint <url>`: when provided, the monitor will POST aggregated metrics as an OTLP/JSON-style payload to this HTTP endpoint instead of printing to stdout. If the URL has no path the client will POST to `/v1/metrics`. Examples: `http://collector:4318`, `https://otel-collector.example/api`.
 - `--otlp-debug`: enable additional debug logging for OTLP exports (logs the JSON payload and response status/body). Useful when configuring a collector or troubleshooting ingestion problems.
 - `-a`, `--with-args`: include process command-line arguments (best-effort) by reading `/proc/<pid>/cmdline`. This can fail for very short-lived processes or across PID namespaces; when unavailable, args will be omitted.

Example
-------
Watch all processes, flushing every 5s:

```bash
sudo ./syscall_monitor -i 5
```

Only monitor `sshd` and `nginx`:

```bash
sudo ./syscall_monitor -i 5 -c sshd -c nginx
```

Include process arguments in output:

```bash
sudo ./syscall_monitor -i 5 --with-args
```

Send metrics to an OTLP HTTP collector (instead of stdout):

```bash
sudo ./syscall_monitor --otlp-endpoint http://collector:4318
```

Enable OTLP debug logging to print the JSON payload and collector responses:

```bash
sudo ./syscall_monitor --otlp-endpoint http://collector:4318 --otlp-debug
```

What the monitor prints
----------------------
Each flush prints lines in one of two formats:

- For syscalls that include a meaningful byte count (I/O):

  PID=<pid> comm=<comm> call=<name> count=<n> avg_ms=<avg latency ms> max_ms=<max latency ms> bytes=<total bytes>

- For other syscalls:

  PID=<pid> comm=<comm> call=<name> count=<n> avg_ms=<avg latency ms> max_ms=<max latency ms>

Maps used by the BPF program
----------------------------
- `syscall_stats_map` (BPF_HASH): keyed by `{ pid (u32), id (u32) }`, value `{ count, sum_ns, max_ns, bytes }`.
- `monitor_pid_map` (BPF_ARRAY): single-slot array used to store the monitor's PID so the BPF program can ignore events from the monitor itself.
- `allowed_comms_map` (BPF_HASH): optional whitelist of 16-byte comm strings.
- `filter_enabled_map` (BPF_ARRAY): single flag (key 0) indicating whether comm filtering is enabled.

Troubleshooting
---------------
- Permission errors when creating or attaching BPF programs usually mean you need to run as root or give the binary the required capabilities. See the `setcap` example above.
NB: Even non-root with the correct `setcap` capabilities, it will fail because the program currently requires access to /sys/kernel/tracing. Mounting this directory as non-kernel adds major security holes.
- If a tracepoint isn't available on your kernel (rare), the Go userspace will skip attaching that tracepoint and log a notice. If you prefer a hard-fail when tracepoints are missing, open an issue or request a change and I can add that behavior.
- If you see "iteration aborted" errors in earlier runs, update to the latest code in this repo; deletions are performed after iteration to avoid aborts.

