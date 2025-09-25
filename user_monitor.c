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

/* libcap runtime checks removed to simplify runtime behavior. */

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
    struct syscall_key prev_key;
    struct syscall_key key;
    struct syscall_key next_key;
    struct syscall_stats stats;

    // Iterate map: start with NULL previous key to get the first entry
    // then repeatedly get the next key using the last seen key.
    // This avoids printing multiple times per PID/Call.
    int res = bpf_map_get_next_key(map_fd, NULL, &key);
    while (res == 0) {
        if (bpf_map_lookup_elem(map_fd, &key, &stats) != 0) {
            // couldn't read this entry, try to advance to next
            res = bpf_map_get_next_key(map_fd, &key, &key);
            continue;
        }

        double avg_ns = 0.0;
        if (stats.count)
            avg_ns = (double)stats.sum_ns / (double)stats.count;

        const char *name = syscall_name(key.id);
        char name_buf[32];
        if (!name) {
            snprintf(name_buf, sizeof(name_buf), "sys_%u", key.id);
            name = name_buf;
        }

        /* Read /proc/<pid>/comm to get the task's command name (TASK_COMM_LEN=16) */
        char comm[16] = "-";
        char comm_path[64];
        snprintf(comm_path, sizeof(comm_path), "/proc/%u/comm", key.pid);
        FILE *f = fopen(comm_path, "r");
        if (f) {
            if (fgets(comm, sizeof(comm), f) != NULL) {
                /* strip trailing newline if present */
                size_t l = strlen(comm);
                if (l && comm[l-1] == '\n') comm[l-1] = '\0';
            }
            fclose(f);
        }

     if (syscall_has_bytes(key.id)) {
         printf("PID=%u comm=%s call=%s count=%llu avg_ms=%.3f max_ms=%.3f bytes=%llu\n",
             key.pid,
             comm,
             name,
             (unsigned long long)stats.count,
             avg_ns / 1e6,
             (double)stats.max_ns / 1e6,
             (unsigned long long)stats.bytes);
     } else {
         printf("PID=%u comm=%s call=%s count=%llu avg_ms=%.3f max_ms=%.3f\n",
             key.pid,
             comm,
             name,
             (unsigned long long)stats.count,
             avg_ns / 1e6,
             (double)stats.max_ns / 1e6);
     }

        // delete entry so stats are flushed
        if (bpf_map_delete_elem(map_fd, &key) != 0) {
            // couldn't delete, nothing more we can do for this entry
        }

        // advance to next key
        prev_key = key;
        res = bpf_map_get_next_key(map_fd, &prev_key, &next_key);
        if (res == 0)
            key = next_key;
    }

    return 0;
}

// Runtime libcap checks removed; permission checks remain when loading/attaching BPF.

int main(int argc, char **argv) {
    struct syscall_monitoring_bpf *skel;
    int err;
    unsigned int interval = 10; /* seconds, default */
    // Simple dynamic array of comm filters (max 64 per BPF map definition)
    const char *comm_filters[64];
    int comm_filter_count = 0;

    /* parse user arguments: --interval / -i <seconds> */
    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interval") == 0) && i + 1 < argc) {
            char *endptr = NULL;
            long val = strtol(argv[i+1], &endptr, 10);
            if (endptr == argv[i+1] || val <= 0) {
                fprintf(stderr, "invalid interval '%s'\n", argv[i+1]);
                return 1;
            }
            interval = (unsigned int)val;
            i++; /* skip value */
            continue;
        }
        if ((strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--comm") == 0) && i + 1 < argc) {
            if (comm_filter_count >= 64) {
                fprintf(stderr, "too many -c/--comm filters (max 64)\n");
                return 1;
            }
            comm_filters[comm_filter_count++] = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("usage: %s [-i|--interval seconds] [-c|--comm name]...\n", argv[0]);
            printf("  -i, --interval <sec>  Flush/aggregation interval (default %u)\n", interval);
            printf("  -c, --comm <name>     Only monitor processes whose task comm matches <name>.\n");
            printf("                       May be supplied multiple times (up to 64). If omitted, monitors all.\n");
            return 0;
        }
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Note: runtime libcap checks were removed. Permissions errors while
     * loading or attaching BPF programs will still be reported below. */

    skel = syscall_monitoring_bpf__open();
    if (!skel) {
        fprintf(stderr, "failed to open BPF skeleton\n");
        return 1;
    }

    err = syscall_monitoring_bpf__load(skel);
    if (err) {
        /* libbpf often returns -1 and prints a helpful message to stderr
         * about the underlying cause; still, provide actionable hints to
         * the user for common causes: missing capabilities / not running
         * as root, or RLIMIT_MEMLOCK too low. */
        fprintf(stderr, "failed to load BPF object: %d\n", err);
        if (errno == EPERM || errno == EACCES) {
            fprintf(stderr, "       Permission denied while loading BPF object.\n");
            fprintf(stderr, "       Try running as root: sudo %s\n", argv[0]);
            fprintf(stderr, "       Or grant capabilities: sudo setcap cap_bpf,cap_perfmon,cap_sys_resource+ep %s\n", argv[0]);
        } else if (errno == ENOMEM) {
            fprintf(stderr, "       Insufficient memory or RLIMIT_MEMLOCK too low. Increase with:\n");
            fprintf(stderr, "         sudo prlimit --pid $$ --memlock=unlimited\n");
            fprintf(stderr, "       Or add to /etc/security/limits.conf: \"* hard memlock unlimited\"\n");
        } else {
            fprintf(stderr, "       See the libbpf output above for details; ensure your kernel supports BPF and that RLIMIT_MEMLOCK is large enough.\n");
        }
        goto cleanup;
    }

    err = syscall_monitoring_bpf__attach(skel);
    if (err) {
        if (err == -EACCES || err == -EPERM) {
            fprintf(stderr, "error: failed to attach BPF programs: permission denied (EACCES/EPERM)\n");
            fprintf(stderr, "       This usually means the process lacks CAP_BPF/CAP_PERFMON or isn't running as root.\n");
            fprintf(stderr, "       You can either run as root (sudo %s) or grant capabilities:\n", argv[0]);
            fprintf(stderr, "         sudo setcap cap_bpf,cap_perfmon,cap_sys_resource+ep %s\n", argv[0]);
            fprintf(stderr, "       On some distros you may also need to enable tracing/proc fs or kernel config for BPF.\n");
        } else {
            fprintf(stderr, "failed to attach BPF programs: %d\n", err);
        }
        goto cleanup;
    }

    int map_fd = bpf_map__fd(skel->maps.syscall_stats_map);
    if (map_fd < 0) {
        fprintf(stderr, "failed to get map fd\n");
        goto cleanup;
    }

    /* Set our own PID into the BPF monitor_pid_map so the BPF program
     * ignores this process (prevents the monitor from monitoring itself).
     */
    int mon_map_fd = bpf_map__fd(skel->maps.monitor_pid_map);
    if (mon_map_fd >= 0) {
        __u32 key = 0;
        __u32 val = (__u32)getpid();
        if (bpf_map_update_elem(mon_map_fd, &key, &val, BPF_ANY) != 0) {
            fprintf(stderr, "warning: failed to populate monitor_pid_map: %s\n", strerror(errno));
            /* Not fatal: continue without self-filtering */
        }
        else {
            /* read back for verification */
            __u32 readback = 0;
            if (bpf_map_lookup_elem(mon_map_fd, &key, &readback) == 0) {
                fprintf(stderr, "monitor_pid_map populated with PID=%u\n", readback);
            } else {
                fprintf(stderr, "warning: failed to read back monitor_pid_map: %s\n", strerror(errno));
            }
        }
    } else {
        /* Not fatal: continue without self-filtering */
    }

    /* Remove any existing stats for the monitor PID so we don't print
     * events that were recorded before we populated the monitor map. */
    if (mon_map_fd >= 0 && map_fd >= 0) {
        __u32 key0 = 0;
        __u32 readback = 0;
        if (bpf_map_lookup_elem(mon_map_fd, &key0, &readback) == 0) {
            struct syscall_key skey;
            struct syscall_key sknext;
            int r = bpf_map_get_next_key(map_fd, NULL, &skey);
            while (r == 0) {
                if (skey.pid == readback) {
                    bpf_map_delete_elem(map_fd, &skey);
                }
                r = bpf_map_get_next_key(map_fd, &skey, &sknext);
                if (r == 0)
                    skey = sknext;
            }
        }
    }

    // Populate allowed comms map if filters provided
    if (comm_filter_count > 0) {
        int comm_map_fd = bpf_map__fd(skel->maps.allowed_comms_map);
        int filter_flag_fd = bpf_map__fd(skel->maps.filter_enabled_map);
        if (comm_map_fd < 0 || filter_flag_fd < 0) {
            fprintf(stderr, "error: BPF object missing required maps for comm filtering\n");
            goto cleanup;
        }
        __u32 zero = 0; __u8 one = 1;
        if (bpf_map_update_elem(filter_flag_fd, &zero, &one, BPF_ANY) != 0) {
            fprintf(stderr, "warning: failed to enable comm filtering: %s\n", strerror(errno));
        }
        for (int j = 0; j < comm_filter_count; j++) {
            char key[16] = {0};
            size_t len = strlen(comm_filters[j]);
            if (len >= sizeof(key)) len = sizeof(key) - 1; // truncate silently to match task comm behavior
            memcpy(key, comm_filters[j], len);
            __u8 val = 1;
            if (bpf_map_update_elem(comm_map_fd, &key, &val, BPF_ANY) != 0) {
                fprintf(stderr, "warning: failed adding comm filter '%s': %s\n", comm_filters[j], strerror(errno));
            }
        }
    }

    printf("syscall monitor started, flushing every %us%s. Ctrl-C to exit.\n",
           interval,
           comm_filter_count ? " (filtered by comm)" : "");

    while (!exiting) {
        for (unsigned int i = 0; i < interval && !exiting; i++)
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
