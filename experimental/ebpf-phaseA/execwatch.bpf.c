// execwatch — host-side process-exec telemetry for the process guardrail
// (#2637; design: docs/architecture/process-exec-guardrail.md, component 1).
//
// A SECOND BPF object next to netpolicy.bpf.o, deliberately not merged into
// it: this program is host-global (one tracepoint) where the network program
// is per-veth, it needs a newer kernel (see the floor below) and kernel BTF,
// and a verifier rejection or missing BTF here must never take flow
// enforcement down with it. Same `make build-bpf`, same `embed_bpf` tag,
// same CI loading lane; only the failure domain is split.
//
// Attach point: tracepoint sched/sched_process_exec — fires once per
// SUCCESSFUL exec (after the new image is installed), with the resolved
// filename. Not sys_enter_execve: that records attempts and would need
// sys_exit pairing to know the exec happened.
//
// Filtering is in-kernel: userspace fills `watched_cgroups` with the cgroup
// id (the inode of /sys/fs/cgroup/<path>) of every running tenant container,
// resolved from the container's init PID. The program walks the exec'ing
// task's cgroup ancestors (levels 1..EXEC_CGROUP_LEVELS) and looks each id
// up; a miss at every level is a host or core-infra process and nothing is
// emitted — the ring only ever carries tenant-box execs. The matched
// ancestor id (the one userspace registered) is what the event reports, so
// userspace maps it straight back to the container.
//
// argv is read from the task's mm (arg_start..arg_end) via CO-RE, capped at
// EXEC_ARGV_LEN bytes with a truncation flag. The environment block
// (env_start..env_end) is NEVER read: the read window is bounded by arg_end.
//
// Build: `make build-bpf` generates vmlinux.h from the build host's kernel
// BTF (`bpftool btf dump file /sys/kernel/btf/vmlinux format c`) into
// internal/netbpf/ — gitignored, never checked in (decided on #2711 Q1) —
// then runs:
//   clang -O2 -g -target bpfel -I internal/netbpf -c execwatch.bpf.c -o execwatch.bpf.o
//
// Kernel floor: 5.8 (BPF_MAP_TYPE_RINGBUF, and with it the BPF_RB_NO_WAKEUP
// submit flag), 5.6 (bpf_get_current_ancestor_cgroup_id),
// and CONFIG_DEBUG_INFO_BTF for the CO-RE relocations (task_struct, mm_struct,
// the tracepoint context). Ubuntu 22.04 and 24.04 LTS ship all three. The
// network object keeps its own 5.4 floor: a host below 5.8 loses exec
// telemetry, not flow detection.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define EXEC_COMM_LEN      16
#define EXEC_FILENAME_LEN  256
#define EXEC_ARGV_LEN      512
#define EXEC_CGROUP_LEVELS 12
#define EXEC_RING_BYTES    (1 << 20) /* 1 MiB */

// No per-record wakeup (#2774). A plain bpf_ringbuf_submit(ev, 0) wakes the
// consumer whenever it has caught up, which for a consumer that keeps up is
// EVERY record: irq_work plus, on a VM, an IPI per exec, and one epoll
// wakeup + context switch per event in the daemon. Measured on an 8-vCPU
// KVM guest that was ~7 % of host CPU at 800 execs/s, against a < 1 % bar.
// Records are submitted with BPF_RB_NO_WAKEUP instead, and the daemon polls
// the ring on a short timer (netbpf.ExecDrainInterval, tens of
// milliseconds — far inside the < 10 s detection budget), draining
// everything queued in one batch and re-draining at once while the backlog
// is large. Nothing ever waits on the ring's wait queue, so a forced wakeup
// would buy nothing.

// Wire shape of one exec event. This is the kernel ↔ daemon contract; the Go
// decoder (internal/netbpf/execwatch.go, ParseExecEvent) pins the size and
// every offset below in TestExecEventWireLayout. The layout is FIXED: append
// new fields at the end, never reorder or resize these.
//
//   offset  size  field
//        0     4  host_pid        tgid in the host pid namespace
//        4     4  ppid            parent's tgid (host pid namespace)
//        8     4  uid             real uid of the exec'ing task
//       12     4  (pad)           natural alignment for cgroup_id
//       16     8  cgroup_id       the matched watched_cgroups key
//       24    16  comm            task comm after exec, NUL-terminated
//       40   256  filename        resolved path from the tracepoint, NUL-terminated
//      296   512  argv            NUL-separated argv bytes (not NUL-terminated when capped)
//      808     1  argv_truncated  1 when argv exceeded EXEC_ARGV_LEN bytes
//      809     7  (pad)           struct tail padding
//     sizeof = 816
struct exec_event {
    __u32 host_pid;
    __u32 ppid;
    __u32 uid;
    __u32 pad0;
    __u64 cgroup_id;
    char  comm[EXEC_COMM_LEN];
    char  filename[EXEC_FILENAME_LEN];
    char  argv[EXEC_ARGV_LEN];
    __u8  argv_truncated;
    __u8  pad1[7];
};

// watched_cgroups: cgroup id → container index. Userspace owns the contents;
// the value is opaque to the kernel (the daemon maps the id, not the index,
// back to a container — the index exists so a future program can carry a
// per-container knob without a layout change). Upserted on every enforcer
// reconcile for running containers, deleted for stopped ones.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u32);
    __uint(max_entries, 4096);
} watched_cgroups SEC(".maps");

// exec_events: the ring buffer the daemon's consumer reads. One
// struct exec_event per record. 1 MiB holds ~1,280 events; a burst beyond
// what the consumer drains fails bpf_ringbuf_reserve and is COUNTED (below),
// never blocks the exec. Records are submitted without a wakeup and drained
// on a timer (see above).
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, EXEC_RING_BYTES);
} exec_events SEC(".maps");

// exec_stats: 0 = events emitted, 1 = events lost (ring full). The daemon
// reports [1] as GetSentryStatus.exec_events_lost.
#define EXEC_STAT_EMITTED 0
#define EXEC_STAT_LOST    1

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 2);
} exec_stats SEC(".maps");

// exec_wakeup_per_record restores the pre-#2774 submit (default wakeup)
// when set. A load-time constant (.rodata, frozen at load, so the verifier
// sees a known value and drops the dead branch); the daemon never sets it.
// The loading lane's overhead test loads a copy with it set to measure the
// per-event-wakeup shape side by side with the batched one
// (execwatch_load_test.go).
volatile const __u8 exec_wakeup_per_record = 0;

static __always_inline void exec_bump(__u32 idx) {
    __u64 *v = bpf_map_lookup_elem(&exec_stats, &idx);
    if (v)
        __sync_fetch_and_add(v, 1);
}

// watched_ancestor returns the first ancestor cgroup id (level 1 outward to
// EXEC_CGROUP_LEVELS) present in watched_cgroups, or 0 when none is — i.e. a
// host or core-infra process. Level 0 is the root cgroup and is never
// registered. The loop is fully unrolled with a constant bound so the
// verifier sees straight-line code; the early exit below is a plain
// forward jump out of it.
//
// The helper returns 0 for a level deeper than the task's own cgroup, and
// every level past that is 0 too, so the first 0 ends the walk: on a host
// exec (the common case — a host process sits a few levels deep and matches
// nothing) this saves the remaining helper calls and lookups.
static __always_inline __u64 watched_ancestor(void) {
#pragma unroll
    for (int level = 1; level <= EXEC_CGROUP_LEVELS; level++) {
        __u64 id = bpf_get_current_ancestor_cgroup_id(level);
        if (id == 0)
            break; // past the task's depth: no deeper ancestor exists
        if (bpf_map_lookup_elem(&watched_cgroups, &id))
            return id;
    }
    return 0;
}

SEC("tp/sched/sched_process_exec")
int execwatch(struct trace_event_raw_sched_process_exec *ctx) {
    __u64 cgroup_id = watched_ancestor();
    if (cgroup_id == 0)
        return 0; // host / core-infra exec: nothing to report

    struct exec_event *ev = bpf_ringbuf_reserve(&exec_events, sizeof(*ev), 0);
    if (!ev) {
        exec_bump(EXEC_STAT_LOST);
        return 0;
    }
    // Ring memory is not zeroed by reserve; the decoder reads comm/filename
    // up to the first NUL and argv up to the last NUL, so stale bytes must
    // not survive a shorter write.
    __builtin_memset(ev, 0, sizeof(*ev));

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    ev->host_pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    ev->ppid = (__u32)BPF_CORE_READ(task, real_parent, tgid);
    ev->uid = (__u32)bpf_get_current_uid_gid();
    ev->cgroup_id = cgroup_id;
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

    // filename is a __data_loc field: the low 16 bits are the offset of the
    // string within the tracepoint record.
    unsigned int fname_off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_kernel_str(&ev->filename, sizeof(ev->filename), (void *)ctx + fname_off);

    // argv: the new image's argument block, [arg_start, arg_end). The
    // environment follows at env_start and is outside this window by
    // construction — the read length is bounded by arg_end, never by
    // env_end.
    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    unsigned long arg_start = BPF_CORE_READ(mm, arg_start);
    unsigned long arg_end = BPF_CORE_READ(mm, arg_end);
    if (arg_end > arg_start) {
        unsigned long span = arg_end - arg_start;
        __u32 len = span > EXEC_ARGV_LEN ? EXEC_ARGV_LEN : (__u32)span;
        // len is provably in [1, EXEC_ARGV_LEN] here, which is what the
        // verifier needs for a variable-size user read into a fixed buffer.
        // The truncation flag is set only once the capped read succeeded:
        // a failed read (the argument pages are not resident) leaves argv
        // empty and unflagged rather than claiming a cut-off vector.
        if (len > 0 && len <= EXEC_ARGV_LEN &&
            bpf_probe_read_user(&ev->argv, len, (const void *)arg_start) == 0 &&
            span > EXEC_ARGV_LEN)
            ev->argv_truncated = 1;
    }

    __u64 wake = exec_wakeup_per_record ? 0 : BPF_RB_NO_WAKEUP;
    bpf_ringbuf_submit(ev, wake);
    exec_bump(EXEC_STAT_EMITTED);
    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
