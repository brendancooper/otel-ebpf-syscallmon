#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/uio.h>
#include <linux/socket.h>
#include <bpf/bpf_helpers.h>

// Local minimal tracepoint structs (kernel headers may not expose full defs here)
struct trace_event_raw_sys_enter {
    __u64 args[6];
    __u32 id;
};

struct trace_event_raw_sys_exit {
    __s64 ret;
    __u64 args[6];
    __u32 id;
};

// Minimal user-space msghdr / iovec representations for reading from user memory
struct user_iovec {
    __u64 iov_base;
    __u64 iov_len;
};

struct user_msghdr {
    __u64 msg_name;
    __u64 msg_namelen;
    __u64 msg_iov;    // pointer
    __u64 msg_iovlen;
    __u64 msg_control;
    __u64 msg_controllen;
    __u64 msg_flags;
};

struct syscall_stats {
    __u64 count;
    __u64 sum_ns;
    __u64 max_ns;
    __u64 bytes; // bytes for sendmsg/recvmsg
};

struct syscall_key {
    __u32 pid;
    __u32 id;
};

// Map: per-PID per-syscall statistics
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct syscall_key);
    __type(value, struct syscall_stats);
} syscall_stats_map SEC(".maps");

// Map: per-TID syscall entry timestamp
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u64);
} start_ns_map SEC(".maps");

/* We removed the macro because the BPF verifier had trouble; each exit handler
 * below performs the same sequence explicitly: lookup start ts, compute delta,
 * update per-PID/per-syscall stats, and add bytes from ctx->ret when >0.
 */

// Define syscall IDs (these are arbitrary small IDs used for user reporting)
#define SCID_SENDMSG    1
#define SCID_SENDTO     2
#define SCID_RECVMSG    3
#define SCID_RECVFROM   4
#define SCID_CONNECT    5
#define SCID_CLOSE      6
#define SCID_CLOSE_RANGE 7
#define SCID_READ       8
#define SCID_READV      9
#define SCID_WRITE      10
#define SCID_WRITEV     11
#define SCID_OPEN       12
#define SCID_OPENAT     13
#define SCID_FSTAT      14
#define SCID_FSTATAT    15
#define SCID_POLL       16
#define SCID_PPOLL      17
#define SCID_EPOLL_WAIT 18

// Enter handlers: store start timestamp per-TID
SEC("tracepoint/syscalls/sys_enter_sendmsg")
int enter_sendmsg(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_ns_map, &tid, &ts, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int enter_sendto(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_ns_map, &tid, &ts, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvmsg")
int enter_recvmsg(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_ns_map, &tid, &ts, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int enter_recvfrom(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_ns_map, &tid, &ts, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int enter_connect(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_ns_map, &tid, &ts, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int enter_close(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_ns_map, &tid, &ts, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close_range")
int enter_close_range(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_ns_map, &tid, &ts, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int enter_read(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_ns_map, &tid, &ts, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_readv")
int enter_readv(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_ns_map, &tid, &ts, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int enter_write(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_ns_map, &tid, &ts, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_writev")
int enter_writev(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_ns_map, &tid, &ts, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_open")
int enter_open(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_ns_map, &tid, &ts, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int enter_openat(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_ns_map, &tid, &ts, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_newfstat")
int enter_fstat(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_ns_map, &tid, &ts, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_newfstatat")
int enter_fstatat(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_ns_map, &tid, &ts, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_poll")
int enter_poll(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_ns_map, &tid, &ts, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ppoll")
int enter_ppoll(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_ns_map, &tid, &ts, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_epoll_wait")
int enter_epoll_wait(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_ns_map, &tid, &ts, BPF_ANY);
    return 0;
}

// Exit handlers: update stats with ID and bytes from ctx->ret when present
SEC("tracepoint/syscalls/sys_exit_sendmsg")
int exit_sendmsg(struct trace_event_raw_sys_exit *ctx) {
    __s64 ret = 0;
    bpf_probe_read(&ret, sizeof(ret), &ctx->ret);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tid = (__u32)pid_tgid;
    __u64 *tsp = bpf_map_lookup_elem(&start_ns_map, &tid);
    if (!tsp) return 0;
    __u64 delta = bpf_ktime_get_ns() - *tsp;
    bpf_map_delete_elem(&start_ns_map, &tid);

    struct syscall_key key = { .pid = pid, .id = SCID_SENDMSG };
    struct syscall_stats zero = {};
    struct syscall_stats *stats = bpf_map_lookup_elem(&syscall_stats_map, &key);
    if (!stats) {
        bpf_map_update_elem(&syscall_stats_map, &key, &zero, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&syscall_stats_map, &key);
        if (!stats) return 0;
    }

    __sync_fetch_and_add(&stats->count, 1);
    __sync_fetch_and_add(&stats->sum_ns, delta);
    __u64 old_max = stats->max_ns;
    if (delta > old_max)
        __sync_val_compare_and_swap(&stats->max_ns, old_max, delta);

    if (ret > 0) {
        __u64 bytes = (__u64)ret;
        __sync_fetch_and_add(&stats->bytes, bytes);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendto")
int exit_sendto(struct trace_event_raw_sys_exit *ctx) {
    __s64 ret = 0;
    bpf_probe_read(&ret, sizeof(ret), &ctx->ret);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tid = (__u32)pid_tgid;
    __u64 *tsp = bpf_map_lookup_elem(&start_ns_map, &tid);
    if (!tsp) return 0;
    __u64 delta = bpf_ktime_get_ns() - *tsp;
    bpf_map_delete_elem(&start_ns_map, &tid);
    struct syscall_key key = { .pid = pid, .id = SCID_SENDTO };
    struct syscall_stats zero = {};
    struct syscall_stats *stats = bpf_map_lookup_elem(&syscall_stats_map, &key);
    if (!stats) {
        bpf_map_update_elem(&syscall_stats_map, &key, &zero, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&syscall_stats_map, &key);
        if (!stats) return 0;
    }
    __sync_fetch_and_add(&stats->count, 1);
    __sync_fetch_and_add(&stats->sum_ns, delta);
    __u64 old_max = stats->max_ns;
    if (delta > old_max)
        __sync_val_compare_and_swap(&stats->max_ns, old_max, delta);
    if (ret > 0) {
        __u64 bytes = (__u64)ret;
        __sync_fetch_and_add(&stats->bytes, bytes);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvmsg")
int exit_recvmsg(struct trace_event_raw_sys_exit *ctx) {
    __s64 ret = 0;
    bpf_probe_read(&ret, sizeof(ret), &ctx->ret);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tid = (__u32)pid_tgid;
    __u64 *tsp = bpf_map_lookup_elem(&start_ns_map, &tid);
    if (!tsp) return 0;
    __u64 delta = bpf_ktime_get_ns() - *tsp;
    bpf_map_delete_elem(&start_ns_map, &tid);
    struct syscall_key key = { .pid = pid, .id = SCID_RECVMSG };
    struct syscall_stats zero = {};
    struct syscall_stats *stats = bpf_map_lookup_elem(&syscall_stats_map, &key);
    if (!stats) {
        bpf_map_update_elem(&syscall_stats_map, &key, &zero, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&syscall_stats_map, &key);
        if (!stats) return 0;
    }
    __sync_fetch_and_add(&stats->count, 1);
    __sync_fetch_and_add(&stats->sum_ns, delta);
    __u64 old_max = stats->max_ns;
    if (delta > old_max)
        __sync_val_compare_and_swap(&stats->max_ns, old_max, delta);
    if (ret > 0) {
        __u64 bytes = (__u64)ret;
        __sync_fetch_and_add(&stats->bytes, bytes);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int exit_recvfrom(struct trace_event_raw_sys_exit *ctx) {
    __s64 ret = 0;
    bpf_probe_read(&ret, sizeof(ret), &ctx->ret);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tid = (__u32)pid_tgid;
    __u64 *tsp = bpf_map_lookup_elem(&start_ns_map, &tid);
    if (!tsp) return 0;
    __u64 delta = bpf_ktime_get_ns() - *tsp;
    bpf_map_delete_elem(&start_ns_map, &tid);
    struct syscall_key key = { .pid = pid, .id = SCID_RECVFROM };
    struct syscall_stats zero = {};
    struct syscall_stats *stats = bpf_map_lookup_elem(&syscall_stats_map, &key);
    if (!stats) {
        bpf_map_update_elem(&syscall_stats_map, &key, &zero, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&syscall_stats_map, &key);
        if (!stats) return 0;
    }
    __sync_fetch_and_add(&stats->count, 1);
    __sync_fetch_and_add(&stats->sum_ns, delta);
    __u64 old_max = stats->max_ns;
    if (delta > old_max)
        __sync_val_compare_and_swap(&stats->max_ns, old_max, delta);
    if (ret > 0) {
        __u64 bytes = (__u64)ret;
        __sync_fetch_and_add(&stats->bytes, bytes);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int exit_connect(struct trace_event_raw_sys_exit *ctx) {
    __s64 ret = 0;
    bpf_probe_read(&ret, sizeof(ret), &ctx->ret);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tid = (__u32)pid_tgid;
    __u64 *tsp = bpf_map_lookup_elem(&start_ns_map, &tid);
    if (!tsp) return 0;
    __u64 delta = bpf_ktime_get_ns() - *tsp;
    bpf_map_delete_elem(&start_ns_map, &tid);
    struct syscall_key key = { .pid = pid, .id = SCID_CONNECT };
    struct syscall_stats zero = {};
    struct syscall_stats *stats = bpf_map_lookup_elem(&syscall_stats_map, &key);
    if (!stats) {
        bpf_map_update_elem(&syscall_stats_map, &key, &zero, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&syscall_stats_map, &key);
        if (!stats) return 0;
    }
    __sync_fetch_and_add(&stats->count, 1);
    __sync_fetch_and_add(&stats->sum_ns, delta);
    __u64 old_max = stats->max_ns;
    if (delta > old_max)
        __sync_val_compare_and_swap(&stats->max_ns, old_max, delta);
    if (ret > 0) {
        __u64 bytes = (__u64)ret;
        __sync_fetch_and_add(&stats->bytes, bytes);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_close")
int exit_close(struct trace_event_raw_sys_exit *ctx) {
    __s64 ret = 0;
    bpf_probe_read(&ret, sizeof(ret), &ctx->ret);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tid = (__u32)pid_tgid;
    __u64 *tsp = bpf_map_lookup_elem(&start_ns_map, &tid);
    if (!tsp) return 0;
    __u64 delta = bpf_ktime_get_ns() - *tsp;
    bpf_map_delete_elem(&start_ns_map, &tid);
    struct syscall_key key = { .pid = pid, .id = SCID_CLOSE };
    struct syscall_stats zero = {};
    struct syscall_stats *stats = bpf_map_lookup_elem(&syscall_stats_map, &key);
    if (!stats) {
        bpf_map_update_elem(&syscall_stats_map, &key, &zero, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&syscall_stats_map, &key);
        if (!stats) return 0;
    }
    __sync_fetch_and_add(&stats->count, 1);
    __sync_fetch_and_add(&stats->sum_ns, delta);
    __u64 old_max = stats->max_ns;
    if (delta > old_max)
        __sync_val_compare_and_swap(&stats->max_ns, old_max, delta);
    if (ret > 0) {
        __u64 bytes = (__u64)ret;
        __sync_fetch_and_add(&stats->bytes, bytes);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_close_range")
int exit_close_range(struct trace_event_raw_sys_exit *ctx) {
    __s64 ret = 0;
    bpf_probe_read(&ret, sizeof(ret), &ctx->ret);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tid = (__u32)pid_tgid;
    __u64 *tsp = bpf_map_lookup_elem(&start_ns_map, &tid);
    if (!tsp) return 0;
    __u64 delta = bpf_ktime_get_ns() - *tsp;
    bpf_map_delete_elem(&start_ns_map, &tid);
    struct syscall_key key = { .pid = pid, .id = SCID_CLOSE_RANGE };
    struct syscall_stats zero = {};
    struct syscall_stats *stats = bpf_map_lookup_elem(&syscall_stats_map, &key);
    if (!stats) {
        bpf_map_update_elem(&syscall_stats_map, &key, &zero, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&syscall_stats_map, &key);
        if (!stats) return 0;
    }
    __sync_fetch_and_add(&stats->count, 1);
    __sync_fetch_and_add(&stats->sum_ns, delta);
    __u64 old_max = stats->max_ns;
    if (delta > old_max)
        __sync_val_compare_and_swap(&stats->max_ns, old_max, delta);
    if (ret > 0) {
        __u64 bytes = (__u64)ret;
        __sync_fetch_and_add(&stats->bytes, bytes);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int exit_read(struct trace_event_raw_sys_exit *ctx) {
    __s64 ret = 0;
    bpf_probe_read(&ret, sizeof(ret), &ctx->ret);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tid = (__u32)pid_tgid;
    __u64 *tsp = bpf_map_lookup_elem(&start_ns_map, &tid);
    if (!tsp) return 0;
    __u64 delta = bpf_ktime_get_ns() - *tsp;
    bpf_map_delete_elem(&start_ns_map, &tid);
    struct syscall_key key = { .pid = pid, .id = SCID_READ };
    struct syscall_stats zero = {};
    struct syscall_stats *stats = bpf_map_lookup_elem(&syscall_stats_map, &key);
    if (!stats) {
        bpf_map_update_elem(&syscall_stats_map, &key, &zero, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&syscall_stats_map, &key);
        if (!stats) return 0;
    }
    __sync_fetch_and_add(&stats->count, 1);
    __sync_fetch_and_add(&stats->sum_ns, delta);
    __u64 old_max = stats->max_ns;
    if (delta > old_max)
        __sync_val_compare_and_swap(&stats->max_ns, old_max, delta);
    if (ret > 0) {
        __u64 bytes = (__u64)ret;
        __sync_fetch_and_add(&stats->bytes, bytes);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_readv")
int exit_readv(struct trace_event_raw_sys_exit *ctx) {
    __s64 ret = 0;
    bpf_probe_read(&ret, sizeof(ret), &ctx->ret);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tid = (__u32)pid_tgid;
    __u64 *tsp = bpf_map_lookup_elem(&start_ns_map, &tid);
    if (!tsp) return 0;
    __u64 delta = bpf_ktime_get_ns() - *tsp;
    bpf_map_delete_elem(&start_ns_map, &tid);
    struct syscall_key key = { .pid = pid, .id = SCID_READV };
    struct syscall_stats zero = {};
    struct syscall_stats *stats = bpf_map_lookup_elem(&syscall_stats_map, &key);
    if (!stats) {
        bpf_map_update_elem(&syscall_stats_map, &key, &zero, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&syscall_stats_map, &key);
        if (!stats) return 0;
    }
    __sync_fetch_and_add(&stats->count, 1);
    __sync_fetch_and_add(&stats->sum_ns, delta);
    __u64 old_max = stats->max_ns;
    if (delta > old_max)
        __sync_val_compare_and_swap(&stats->max_ns, old_max, delta);
    if (ret > 0) {
        __u64 bytes = (__u64)ret;
        __sync_fetch_and_add(&stats->bytes, bytes);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int exit_write(struct trace_event_raw_sys_exit *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tid = (__u32)pid_tgid;
    __s64 ret = 0;
    bpf_probe_read(&ret, sizeof(ret), &ctx->ret);
    __u64 *tsp = bpf_map_lookup_elem(&start_ns_map, &tid);
    if (!tsp) return 0;
    __u64 delta = bpf_ktime_get_ns() - *tsp;
    bpf_map_delete_elem(&start_ns_map, &tid);
    struct syscall_key key = { .pid = pid, .id = SCID_WRITE };
    struct syscall_stats zero = {};
    struct syscall_stats *stats = bpf_map_lookup_elem(&syscall_stats_map, &key);
    if (!stats) {
        bpf_map_update_elem(&syscall_stats_map, &key, &zero, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&syscall_stats_map, &key);
        if (!stats) return 0;
    }
    __sync_fetch_and_add(&stats->count, 1);
    __sync_fetch_and_add(&stats->sum_ns, delta);
    __u64 old_max = stats->max_ns;
    if (delta > old_max)
        __sync_val_compare_and_swap(&stats->max_ns, old_max, delta);
    if (ret > 0) {
        __u64 bytes = (__u64)ret;
        __sync_fetch_and_add(&stats->bytes, bytes);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_writev")
int exit_writev(struct trace_event_raw_sys_exit *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tid = (__u32)pid_tgid;
    __s64 ret = 0;
    bpf_probe_read(&ret, sizeof(ret), &ctx->ret);
    __u64 *tsp = bpf_map_lookup_elem(&start_ns_map, &tid);
    if (!tsp) return 0;
    __u64 delta = bpf_ktime_get_ns() - *tsp;
    bpf_map_delete_elem(&start_ns_map, &tid);
    struct syscall_key key = { .pid = pid, .id = SCID_WRITEV };
    struct syscall_stats zero = {};
    struct syscall_stats *stats = bpf_map_lookup_elem(&syscall_stats_map, &key);
    if (!stats) {
        bpf_map_update_elem(&syscall_stats_map, &key, &zero, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&syscall_stats_map, &key);
        if (!stats) return 0;
    }
    __sync_fetch_and_add(&stats->count, 1);
    __sync_fetch_and_add(&stats->sum_ns, delta);
    __u64 old_max = stats->max_ns;
    if (delta > old_max)
        __sync_val_compare_and_swap(&stats->max_ns, old_max, delta);
    if (ret > 0) {
        __u64 bytes = (__u64)ret;
        __sync_fetch_and_add(&stats->bytes, bytes);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_open")
int exit_open(struct trace_event_raw_sys_exit *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tid = (__u32)pid_tgid;
    __s64 ret = 0;
    bpf_probe_read(&ret, sizeof(ret), &ctx->ret);
    __u64 *tsp = bpf_map_lookup_elem(&start_ns_map, &tid);
    if (!tsp) return 0;
    __u64 delta = bpf_ktime_get_ns() - *tsp;
    bpf_map_delete_elem(&start_ns_map, &tid);
    struct syscall_key key = { .pid = pid, .id = SCID_OPEN };
    struct syscall_stats zero = {};
    struct syscall_stats *stats = bpf_map_lookup_elem(&syscall_stats_map, &key);
    if (!stats) {
        bpf_map_update_elem(&syscall_stats_map, &key, &zero, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&syscall_stats_map, &key);
        if (!stats) return 0;
    }
    __sync_fetch_and_add(&stats->count, 1);
    __sync_fetch_and_add(&stats->sum_ns, delta);
    __u64 old_max = stats->max_ns;
    if (delta > old_max)
        __sync_val_compare_and_swap(&stats->max_ns, old_max, delta);
    if (ret > 0) {
        __u64 bytes = (__u64)ret;
        __sync_fetch_and_add(&stats->bytes, bytes);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int exit_openat(struct trace_event_raw_sys_exit *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tid = (__u32)pid_tgid;
    __s64 ret = 0;
    bpf_probe_read(&ret, sizeof(ret), &ctx->ret);
    __u64 *tsp = bpf_map_lookup_elem(&start_ns_map, &tid);
    if (!tsp) return 0;
    __u64 delta = bpf_ktime_get_ns() - *tsp;
    bpf_map_delete_elem(&start_ns_map, &tid);
    struct syscall_key key = { .pid = pid, .id = SCID_OPENAT };
    struct syscall_stats zero = {};
    struct syscall_stats *stats = bpf_map_lookup_elem(&syscall_stats_map, &key);
    if (!stats) {
        bpf_map_update_elem(&syscall_stats_map, &key, &zero, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&syscall_stats_map, &key);
        if (!stats) return 0;
    }
    __sync_fetch_and_add(&stats->count, 1);
    __sync_fetch_and_add(&stats->sum_ns, delta);
    __u64 old_max = stats->max_ns;
    if (delta > old_max)
        __sync_val_compare_and_swap(&stats->max_ns, old_max, delta);
    if (ret > 0) {
        __u64 bytes = (__u64)ret;
        __sync_fetch_and_add(&stats->bytes, bytes);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_newfstat")
int exit_fstat(struct trace_event_raw_sys_exit *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tid = (__u32)pid_tgid;
    __s64 ret = 0;
    bpf_probe_read(&ret, sizeof(ret), &ctx->ret);
    __u64 *tsp = bpf_map_lookup_elem(&start_ns_map, &tid);
    if (!tsp) return 0;
    __u64 delta = bpf_ktime_get_ns() - *tsp;
    bpf_map_delete_elem(&start_ns_map, &tid);
    struct syscall_key key = { .pid = pid, .id = SCID_FSTAT };
    struct syscall_stats zero = {};
    struct syscall_stats *stats = bpf_map_lookup_elem(&syscall_stats_map, &key);
    if (!stats) {
        bpf_map_update_elem(&syscall_stats_map, &key, &zero, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&syscall_stats_map, &key);
        if (!stats) return 0;
    }
    __sync_fetch_and_add(&stats->count, 1);
    __sync_fetch_and_add(&stats->sum_ns, delta);
    __u64 old_max = stats->max_ns;
    if (delta > old_max)
        __sync_val_compare_and_swap(&stats->max_ns, old_max, delta);
    if (ret > 0) {
        __u64 bytes = (__u64)ret;
        __sync_fetch_and_add(&stats->bytes, bytes);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_newfstatat")
int exit_fstatat(struct trace_event_raw_sys_exit *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tid = (__u32)pid_tgid;
    __s64 ret = 0;
    bpf_probe_read(&ret, sizeof(ret), &ctx->ret);
    __u64 *tsp = bpf_map_lookup_elem(&start_ns_map, &tid);
    if (!tsp) return 0;
    __u64 delta = bpf_ktime_get_ns() - *tsp;
    bpf_map_delete_elem(&start_ns_map, &tid);
    struct syscall_key key = { .pid = pid, .id = SCID_FSTATAT };
    struct syscall_stats zero = {};
    struct syscall_stats *stats = bpf_map_lookup_elem(&syscall_stats_map, &key);
    if (!stats) {
        bpf_map_update_elem(&syscall_stats_map, &key, &zero, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&syscall_stats_map, &key);
        if (!stats) return 0;
    }
    __sync_fetch_and_add(&stats->count, 1);
    __sync_fetch_and_add(&stats->sum_ns, delta);
    __u64 old_max = stats->max_ns;
    if (delta > old_max)
        __sync_val_compare_and_swap(&stats->max_ns, old_max, delta);
    if (ret > 0) {
        __u64 bytes = (__u64)ret;
        __sync_fetch_and_add(&stats->bytes, bytes);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_poll")
int exit_poll(struct trace_event_raw_sys_exit *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tid = (__u32)pid_tgid;
    __s64 ret = 0;
    bpf_probe_read(&ret, sizeof(ret), &ctx->ret);
    __u64 *tsp = bpf_map_lookup_elem(&start_ns_map, &tid);
    if (!tsp) return 0;
    __u64 delta = bpf_ktime_get_ns() - *tsp;
    bpf_map_delete_elem(&start_ns_map, &tid);
    struct syscall_key key = { .pid = pid, .id = SCID_POLL };
    struct syscall_stats zero = {};
    struct syscall_stats *stats = bpf_map_lookup_elem(&syscall_stats_map, &key);
    if (!stats) {
        bpf_map_update_elem(&syscall_stats_map, &key, &zero, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&syscall_stats_map, &key);
        if (!stats) return 0;
    }
    __sync_fetch_and_add(&stats->count, 1);
    __sync_fetch_and_add(&stats->sum_ns, delta);
    __u64 old_max = stats->max_ns;
    if (delta > old_max)
        __sync_val_compare_and_swap(&stats->max_ns, old_max, delta);
    if (ret > 0) {
        __u64 bytes = (__u64)ret;
        __sync_fetch_and_add(&stats->bytes, bytes);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_ppoll")
int exit_ppoll(struct trace_event_raw_sys_exit *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tid = (__u32)pid_tgid;
    __s64 ret = 0;
    bpf_probe_read(&ret, sizeof(ret), &ctx->ret);
    __u64 *tsp = bpf_map_lookup_elem(&start_ns_map, &tid);
    if (!tsp) return 0;
    __u64 delta = bpf_ktime_get_ns() - *tsp;
    bpf_map_delete_elem(&start_ns_map, &tid);
    struct syscall_key key = { .pid = pid, .id = SCID_PPOLL };
    struct syscall_stats zero = {};
    struct syscall_stats *stats = bpf_map_lookup_elem(&syscall_stats_map, &key);
    if (!stats) {
        bpf_map_update_elem(&syscall_stats_map, &key, &zero, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&syscall_stats_map, &key);
        if (!stats) return 0;
    }
    __sync_fetch_and_add(&stats->count, 1);
    __sync_fetch_and_add(&stats->sum_ns, delta);
    __u64 old_max = stats->max_ns;
    if (delta > old_max)
        __sync_val_compare_and_swap(&stats->max_ns, old_max, delta);
    if (ret > 0) {
        __u64 bytes = (__u64)ret;
        __sync_fetch_and_add(&stats->bytes, bytes);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_epoll_wait")
int exit_epoll_wait(struct trace_event_raw_sys_exit *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tid = (__u32)pid_tgid;
    __s64 ret = 0;
    bpf_probe_read(&ret, sizeof(ret), &ctx->ret);
    __u64 *tsp = bpf_map_lookup_elem(&start_ns_map, &tid);
    if (!tsp) return 0;
    __u64 delta = bpf_ktime_get_ns() - *tsp;
    bpf_map_delete_elem(&start_ns_map, &tid);
    struct syscall_key key = { .pid = pid, .id = SCID_EPOLL_WAIT };
    struct syscall_stats zero = {};
    struct syscall_stats *stats = bpf_map_lookup_elem(&syscall_stats_map, &key);
    if (!stats) {
        bpf_map_update_elem(&syscall_stats_map, &key, &zero, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&syscall_stats_map, &key);
        if (!stats) return 0;
    }
    __sync_fetch_and_add(&stats->count, 1);
    __sync_fetch_and_add(&stats->sum_ns, delta);
    __u64 old_max = stats->max_ns;
    if (delta > old_max)
        __sync_val_compare_and_swap(&stats->max_ns, old_max, delta);
    if (ret > 0) {
        __u64 bytes = (__u64)ret;
        __sync_fetch_and_add(&stats->bytes, bytes);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
