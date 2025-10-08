package main

import (
    "bufio"
    "encoding/binary"
    "errors"
    "flag"
    "fmt"
    "log"
    "os"
    "os/signal"
    "path/filepath"
    "strings"
    "syscall"
    "time"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/rlimit"
)

// Keep in sync with BPF-side structs and IDs.
type syscallStats struct {
    Count uint64
    SumNs uint64
    MaxNs uint64
    Bytes uint64
}

type syscallKey struct {
    PID uint32
    ID  uint32
}

const (
    scSendmsg   = 1
    scSendto    = 2
    scRecvmsg   = 3
    scRecvfrom  = 4
    scConnect   = 5
    scClose     = 6
    scCloseRng  = 7
    scRead      = 8
    scReadv     = 9
    scWrite     = 10
    scWritev    = 11
    scOpen      = 12
    scOpenat    = 13
    scFstat     = 14
    scFstatat   = 15
    scPoll      = 16
    scPpoll     = 17
    scEpollWait = 18
)

func scName(id uint32) string {
    switch id {
    case scSendmsg:
        return "sendmsg"
    case scSendto:
        return "sendto"
    case scRecvmsg:
        return "recvmsg"
    case scRecvfrom:
        return "recvfrom"
    case scConnect:
        return "connect"
    case scClose:
        return "close"
    case scCloseRng:
        return "close_range"
    case scRead:
        return "read"
    case scReadv:
        return "readv"
    case scWrite:
        return "write"
    case scWritev:
        return "writev"
    case scOpen:
        return "open"
    case scOpenat:
        return "openat"
    case scFstat:
        return "fstat"
    case scFstatat:
        return "fstatat"
    case scPoll:
        return "poll"
    case scPpoll:
        return "ppoll"
    case scEpollWait:
        return "epoll_wait"
    default:
        return fmt.Sprintf("sys_%d", id)
    }
}

func scHasBytes(id uint32) bool {
    switch id {
    case scSendmsg, scSendto, scRecvmsg, scRecvfrom, scRead, scReadv, scWrite, scWritev:
        return true
    default:
        return false
    }
}

// Utilities for interacting with BPF maps without generated bindings.
func mustMap(obj *ebpf.CollectionSpec, name string) *ebpf.MapSpec {
    if ms, ok := obj.Maps[name]; ok {
        return ms
    }
    log.Fatalf("BPF object missing map %q", name)
    return nil
}

func main() {
    // Flags compatible with the C version.
    interval := flag.Uint("interval", 10, "Flush interval in seconds")
    flag.UintVar(interval, "i", 10, "Flush interval in seconds")
    var commFilters multiFlag
    flag.Var(&commFilters, "comm", "Only monitor processes with this comm (repeatable)")
    flag.Var(&commFilters, "c", "Only monitor processes with this comm (repeatable)")
    flag.Parse()

    // Bump RLIMIT_MEMLOCK for older kernels
    _ = rlimit.RemoveMemlock()

    // Load the pre-compiled BPF object file.
    objPath := filepath.Join(".", "syscall_monitoring.bpf.o")
    spec, err := ebpf.LoadCollectionSpec(objPath)
    if err != nil {
        log.Fatalf("failed to load BPF collection spec from %s: %v", objPath, err)
    }

    // Create the collection (maps and programs)
    coll, err := ebpf.NewCollection(spec)
    if err != nil {
        // Common EPERM hints similar to C tool
        if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
            log.Fatalf("permission denied creating BPF collection: %v\nTry: sudo setcap cap_bpf,cap_perfmon,cap_sys_resource+ep <this_binary> or run as root.", err)
        }
        log.Fatalf("failed to create BPF collection: %v", err)
    }
    defer coll.Close()

    // Attach tracepoint programs. Iterate the loaded collection's programs
    // (coll.Programs) and derive the tracepoint event name from the
    // program name. Use an exceptions map for cases where the tracepoint
    // name differs from the simple convention (e.g. fstat -> newfstat).
    var links []link.Link
    exceptions := map[string]string{
        "enter_fstat":  "sys_enter_newfstat",
        "exit_fstat":   "sys_exit_newfstat",
        "enter_fstatat": "sys_enter_newfstatat",
        "exit_fstatat":  "sys_exit_newfstatat",
    }

    for name, prog := range coll.Programs {
        var ev string
        if e, ok := exceptions[name]; ok {
            ev = e
        } else if strings.HasPrefix(name, "enter_") {
            ev = "sys_enter_" + strings.TrimPrefix(name, "enter_")
        } else if strings.HasPrefix(name, "exit_") {
            ev = "sys_exit_" + strings.TrimPrefix(name, "exit_")
        } else {
            // Not a tracepoint program we expect to attach
            continue
        }

        cat := "syscalls"
        evPath := filepath.Join("/sys/kernel/tracing/events", cat, ev, "id")
        if _, err := os.Stat(evPath); err != nil {
            log.Printf("skipping attach syscalls/%s via program %s: tracepoint not present (%v)", ev, name, err)
            continue
        }

        l, err := link.Tracepoint(cat, ev, prog, nil)
        if err != nil {
            log.Printf("attach syscalls/%s via program %s failed: %v", ev, name, err)
            continue
        }
        links = append(links, l)
    }
    defer func() {
        for _, l := range links {
            _ = l.Close()
        }
    }()

    // Convenience handles for maps we need to touch directly
    statsMap := coll.Maps["syscall_stats_map"]
    monMap := coll.Maps["monitor_pid_map"]
    allowedComms := coll.Maps["allowed_comms_map"]
    filterEnabled := coll.Maps["filter_enabled_map"]
    if statsMap == nil || monMap == nil || allowedComms == nil || filterEnabled == nil {
        // allowed_comms_map/filter_enabled_map may be needed only if filtering used, but assert presence like C.
        log.Fatalf("BPF maps missing: stats:%v mon:%v comms:%v filter:%v", statsMap != nil, monMap != nil, allowedComms != nil, filterEnabled != nil)
    }

    // Set monitor PID to avoid self-monitoring (ouroborus effect)
    key32 := uint32(0)
    self := uint32(os.Getpid())
    if err := monMap.Update(&key32, &self, ebpf.UpdateAny); err != nil {
        log.Printf("warning: failed to populate monitor_pid_map: %v", err)
    } else {
        var rb uint32
        if err := monMap.Lookup(&key32, &rb); err == nil {
            log.Printf("monitor_pid_map populated with PID=%d", rb)
        }
    }

    // Clear any existing stats that already recorded our PID
    if err := clearStatsForPID(statsMap, self); err != nil {
        log.Printf("warning: failed to clear initial stats for self: %v", err)
    }

    // If comm filters provided, enable filtering and populate map
    if len(commFilters) > 0 {
        one := uint8(1)
        if err := filterEnabled.Update(&key32, &one, ebpf.UpdateAny); err != nil {
            log.Printf("warning: enabling comm filter failed: %v", err)
        }
        for _, c := range commFilters {
            k := fixed16(c)
            v := uint8(1)
            if err := allowedComms.Update(&k, &v, ebpf.UpdateAny); err != nil {
                log.Printf("warning: adding comm filter %q failed: %v", c, err)
            }
        }
    }

    log.Printf("syscall monitor started, flushing every %ds%s. Ctrl-C to exit.", *interval, func() string {
        if len(commFilters) > 0 { return " (filtered by comm)" }
        return ""
    }())

    // Ticker loop and signal handling
    sigCh := make(chan os.Signal, 2)
    signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

    ticker := time.NewTicker(time.Duration(*interval) * time.Second)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            fmt.Printf("\n=== stats flush @ %s", time.Now().Format(time.RFC1123))
            if err := dumpAndClearStats(statsMap); err != nil {
                log.Printf("flush error: %v", err)
            }
        case <-sigCh:
            return
        }
    }
}

// Iterate a hash map by repeatedly calling NextKey and Lookup, printing and then deleting each entry.
func dumpAndClearStats(m *ebpf.Map) error {
    it := m.Iterate()
    var key syscallKey
    var val syscallStats
    var entries []struct{
        k syscallKey
        v syscallStats
    }
    for it.Next(&key, &val) {
        // copy key/val because iterator reuses the memory
        entries = append(entries, struct{ k syscallKey; v syscallStats }{k: key, v: val})
    }
    if err := it.Err(); err != nil {
        return err
    }

    // Now print and delete outside of the iterator to avoid aborting it
    for _, e := range entries {
        comm := readComm(int(e.k.PID))
        avgMs := 0.0
        if e.v.Count > 0 {
            avgMs = float64(e.v.SumNs) / float64(e.v.Count) / 1e6
        }
        maxMs := float64(e.v.MaxNs) / 1e6
        name := scName(e.k.ID)

        if scHasBytes(e.k.ID) {
            fmt.Printf("PID=%d comm=%s call=%s count=%d avg_ms=%.3f max_ms=%.3f bytes=%d\n",
                e.k.PID, comm, name, e.v.Count, avgMs, maxMs, e.v.Bytes)
        } else {
            fmt.Printf("PID=%d comm=%s call=%s count=%d avg_ms=%.3f max_ms=%.3f\n",
                e.k.PID, comm, name, e.v.Count, avgMs, maxMs)
        }

        kcopy := e.k
        if err := m.Delete(&kcopy); err != nil {
            // Not fatal, continue
        }
    }
    return nil
}

func clearStatsForPID(m *ebpf.Map, pid uint32) error {
    it := m.Iterate()
    var key syscallKey
    var val syscallStats
    var keysToDelete []syscallKey
    for it.Next(&key, &val) {
        if key.PID == pid {
            keysToDelete = append(keysToDelete, key)
        }
    }
    if err := it.Err(); err != nil {
        return err
    }
    for _, k := range keysToDelete {
        kk := k
        _ = m.Delete(&kk)
    }
    return nil
}

// fixed16 returns a 16-byte array filled with the string bytes, truncated or zero-padded.
func fixed16(s string) [16]byte {
    var b [16]byte
    copy(b[:], []byte(s))
    return b
}

// readComm reads /proc/<pid>/comm up to 16 chars similar to C version.
func readComm(pid int) string {
    f, err := os.Open(filepath.Join("/proc", fmt.Sprint(pid), "comm"))
    if err != nil {
        return "-"
    }
    defer f.Close()
    rd := bufio.NewReader(f)
    line, _ := rd.ReadString('\n')
    line = strings.TrimSpace(line)
    if len(line) > 16 {
        line = line[:16]
    }
    return line
}

// multiFlag supports repeated -c/--comm options.
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
    *m = append(*m, v)
    return nil
}

// Ensure struct layout matches C. Add a sanity check using binary size.
func init() {
    if binary.Size(syscallStats{}) != 8*4 {
        // Four uint64 fields
        panic("syscallStats size mismatch; check field types and packing")
    }
    if binary.Size(syscallKey{}) != 8 {
        // two uint32
        panic("syscallKey size mismatch; check field types and packing")
    }
}
