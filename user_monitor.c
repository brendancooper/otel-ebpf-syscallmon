#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "syscall_monitoring.skel.h"

/* Use dlopen to call libcap at runtime when available so this program
 * can still compile on systems without libcap development headers. */
#include <dlfcn.h>

// Use shared syscall id header to avoid duplication/drift
#include "syscall_ids.h"

// Map older SCID_* names used in this file to the shared header names
#define SCID_SENDMSG    SC_SENDMSG
#define SCID_SENDTO     SC_SENDTO
#define SCID_RECVMSG    SC_RECVMSG
#define SCID_RECVFROM   SC_RECVFROM
#define SCID_CONNECT    SC_CONNECT
#define SCID_CLOSE      SC_CLOSE
#define SCID_CLOSE_RANGE SC_CLOSE_RANGE
#define SCID_READ       SC_READ
#define SCID_READV      SC_READV
#define SCID_WRITE      SC_WRITE
#define SCID_WRITEV     SC_WRITEV
#define SCID_OPEN       SC_OPEN
#define SCID_OPENAT     SC_OPENAT
#define SCID_FSTAT      SC_FSTAT
#define SCID_FSTATAT    SC_FSTATAT
#define SCID_POLL       SC_POLL
#define SCID_PPOLL      SC_PPOLL
#define SCID_EPOLL_WAIT SC_EPOLL_WAIT

// Mirror of kernel structs
struct syscall_stats {
    __u64 count;
    __u64 sum_ns;
    __u64 max_ns;
    __u64 bytes;
};

struct syscall_key {
    __u32 pid;
    __u32 id;
};

static volatile sig_atomic_t exiting = 0;
static void sig_handler(int sig) { exiting = 1; }

// Minimal syscall name table for common syscalls. If not found, print numeric id.
static const char *syscall_name(__u32 id) {
    switch (id) {
    case SCID_SENDMSG:    return "sendmsg";
    case SCID_SENDTO:     return "sendto";
    case SCID_RECVMSG:    return "recvmsg";
    case SCID_RECVFROM:   return "recvfrom";
    case SCID_CONNECT:    return "connect";
    case SCID_CLOSE:      return "close";
    case SCID_CLOSE_RANGE:return "close_range";
    case SCID_READ:       return "read";
    case SCID_READV:      return "readv";
    case SCID_WRITE:      return "write";
    case SCID_WRITEV:     return "writev";
    case SCID_OPEN:       return "open";
    case SCID_OPENAT:     return "openat";
    case SCID_FSTAT:      return "fstat";
    case SCID_FSTATAT:    return "fstatat";
    case SCID_POLL:       return "poll";
    case SCID_PPOLL:      return "ppoll";
    case SCID_EPOLL_WAIT: return "epoll_wait";
    default: return NULL;
    }
}

// Helper: return non-zero if this syscall id has a meaningful "bytes" value
static int syscall_has_bytes(__u32 id) {
    switch (id) {
    case SCID_SENDMSG:
    case SCID_SENDTO:
    case SCID_RECVMSG:
    case SCID_RECVFROM:
    case SCID_READ:
    case SCID_READV:
    case SCID_WRITE:
    case SCID_WRITEV:
        return 1;
    default:
        return 0;
    }
}


int print_and_clear_map(int map_fd) {
    struct syscall_key key, next_key;
    struct syscall_stats stats;

    // Iterate map
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &stats) != 0) {
            // couldn't read, try to continue
            memcpy(&key, &next_key, sizeof(key));
            continue;
        }

        double avg_ns = 0.0;
        if (stats.count)
            avg_ns = (double)stats.sum_ns / (double)stats.count;

        const char *name = syscall_name(next_key.id);
        char name_buf[32];
        if (!name) {
            snprintf(name_buf, sizeof(name_buf), "sys_%u", next_key.id);
            name = name_buf;
        }

     if (syscall_has_bytes(next_key.id)) {
         printf("PID=%u %s count=%llu avg_ms=%.3f max_ms=%.3f bytes=%llu\n",
             next_key.pid,
             name,
             (unsigned long long)stats.count,
             avg_ns / 1e6,
             (double)stats.max_ns / 1e6,
             (unsigned long long)stats.bytes);
     } else {
         printf("PID=%u %s count=%llu avg_ms=%.3f max_ms=%.3f\n",
             next_key.pid,
             name,
             (unsigned long long)stats.count,
             avg_ns / 1e6,
             (double)stats.max_ns / 1e6);
     }

        // delete entry so stats are flushed
        if (bpf_map_delete_elem(map_fd, &next_key) != 0) {
            // couldn't delete, next iteration will try again
        }

        memcpy(&key, &next_key, sizeof(key));
    }

    return 0;
}

/* Try to detect CAP_BPF and CAP_PERFMON at runtime by loading libcap
 * with dlopen. Returns 1 if both effective capabilities are present,
 * 0 otherwise (including when libcap isn't available). */
static int check_caps(void)
{
    /* opaque types */
    typedef void *cap_t;
    typedef int cap_value_t;
    typedef int cap_flag_value_t;

    void *h = dlopen("/lib/x86_64-linux-gnu/libcap.so.2", RTLD_LAZY | RTLD_LOCAL);
    if (!h)
        h = dlopen("/lib64/libcap.so.2", RTLD_LAZY | RTLD_LOCAL);
    if (!h)
        h = dlopen("libcap.so.2", RTLD_LAZY | RTLD_LOCAL);
    if (!h)
        h = dlopen("libcap.so", RTLD_LAZY | RTLD_LOCAL);
    if (!h)
        return 0; /* no libcap available */

    cap_t (*cap_get_proc)(void) = (cap_t(*)(void))dlsym(h, "cap_get_proc");
    int (*cap_get_flag)(cap_t, cap_value_t, int, cap_flag_value_t *) =
        (int(*)(cap_t, cap_value_t, int, cap_flag_value_t *))dlsym(h, "cap_get_flag");
    int (*cap_from_name)(const char *, cap_value_t *) =
        (int(*)(const char *, cap_value_t *))dlsym(h, "cap_from_name");
    void (*cap_free)(void *) = (void(*)(void *))dlsym(h, "cap_free");

    if (!cap_get_proc || !cap_get_flag || !cap_from_name || !cap_free) {
        dlclose(h);
        return 0;
    }

    cap_t caps = cap_get_proc();
    if (!caps) {
        dlclose(h);
        return 0;
    }

    cap_value_t val_bpf_idx = -1, val_perf_idx = -1, val_sys_resource_idx = -1;
    if (cap_from_name("cap_bpf", &val_bpf_idx) != 0 ||
        cap_from_name("cap_perfmon", &val_perf_idx) != 0 ||
        cap_from_name("cap_sys_resource", &val_sys_resource_idx) != 0) {
        cap_free(caps);
        dlclose(h);
        return 0;
    }

    const int CAP_EFFECTIVE = 0; /* libcap enum: CAP_EFFECTIVE */
    cap_flag_value_t flag_bpf = 0, flag_perf = 0, flag_sys_resource = 0;
    int ok = 0;
    if (cap_get_flag(caps, val_bpf_idx, CAP_EFFECTIVE, &flag_bpf) == 0 &&
        cap_get_flag(caps, val_perf_idx, CAP_EFFECTIVE, &flag_perf) == 0 &&
        cap_get_flag(caps, val_sys_resource_idx, CAP_EFFECTIVE, &flag_sys_resource) == 0) {
        if (flag_bpf != 0 && flag_perf != 0 && flag_sys_resource != 0)
            ok = 1;
    }

    cap_free(caps);
    dlclose(h);
    return ok;
}

int main(int argc, char **argv) {
    struct syscall_monitoring_bpf *skel;
    int err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* runtime capability check */
    if (!check_caps()) {
        if (geteuid() != 0) {
            fprintf(stderr, "error: this program must be run with CAP_BPF, CAP_PERFMON and CAP_SYS_RESOURCE (or try: sudo %s)\n", argv[0]);
            return 1;
        }
    }

    skel = syscall_monitoring_bpf__open();
    if (!skel) {
        fprintf(stderr, "failed to open BPF skeleton\n");
        return 1;
    }

    err = syscall_monitoring_bpf__load(skel);
    if (err) {
        fprintf(stderr, "failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    err = syscall_monitoring_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    int map_fd = bpf_map__fd(skel->maps.syscall_stats_map);
    if (map_fd < 0) {
        fprintf(stderr, "failed to get map fd\n");
        goto cleanup;
    }

    printf("syscall monitor started, flushing every 10s. Ctrl-C to exit.\n");

    while (!exiting) {
        for (int i = 0; i < 10 && !exiting; i++)
            sleep(1);

        if (exiting) break;

        time_t t = time(NULL);
        printf("\n=== stats flush @ %s", ctime(&t));
        print_and_clear_map(map_fd);
        fflush(stdout);
    }

cleanup:
    syscall_monitoring_bpf__destroy(skel);
    return err != 0;
}
