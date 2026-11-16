// SPDX-License-Identifier: GPL-2.0-only OR MIT
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/eprobe_tracepoint.h>
#include <bpf/eprobe_cgroup.h>

typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;
typedef long long s64;

// -----------------------------------------------------------------------------
// Constants & Futex Definitions
// -----------------------------------------------------------------------------

#define TASK_RUNNING         0x0000
#define TASK_INTERRUPTIBLE   0x0001
#define TASK_UNINTERRUPTIBLE 0x0002

#define FUTEX_WAIT           0
#define FUTEX_WAKE           1
#define FUTEX_FD             2
#define FUTEX_REQUEUE        3
#define FUTEX_CMP_REQUEUE    4
#define FUTEX_WAKE_OP        5
#define FUTEX_LOCK_PI        6
#define FUTEX_UNLOCK_PI      7
#define FUTEX_TRYLOCK_PI     8
#define FUTEX_WAIT_BITSET    9
#define FUTEX_WAKE_BITSET    10
#define FUTEX_WAIT_REQUEUE_PI 11
#define FUTEX_CMP_REQUEUE_PI 12
#define FUTEX_PRIVATE_FLAG   128
#define FUTEX_CLOCK_REALTIME 256
#define FUTEX_CMD_MASK       (~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME))

// -----------------------------------------------------------------------------
// Telemetry Structs (Strictly Packed to Guarantee 1:1 Schema Offset Parity)
// -----------------------------------------------------------------------------

// Ringbuffer discrete stall spike event (exact 212 bytes matching manifest.yaml)
struct stall_event_t {
    u32 pid;
    u32 tid;
    u32 ppid;
    char comm[16];
    char container_id[16];
    char stall_type[16];
    u64 duration_us;
    u64 runq_latency_us;
    char level[8];
    char message[128];
} __attribute__((packed));

// Ringbuffer lock contention event (exact 212 bytes matching manifest.yaml)
struct contention_event_t {
    u32 pid;
    u32 tid;
    u32 ppid;
    char comm[16];
    char container_id[16];
    char op_type[16];
    u64 lock_addr;
    u64 duration_us;
    char level[8];
    char message[128];
} __attribute__((packed));

// In-kernel aggregated process stall metrics (exact 36 bytes matching manifest.yaml)
struct proc_key_t {
    char comm[16];
} __attribute__((packed));

struct proc_stat_t {
    u64 total_stall_ns;
    u64 dstate_ns;
    u64 runq_latency_ns;
    u64 futex_wait_ns;
    u32 stall_count;
} __attribute__((packed));

// In-kernel aggregated container stall metrics (exact 36 bytes matching manifest.yaml)
struct container_key_t {
    char container_id[16];
} __attribute__((packed));

struct container_stat_t {
    u64 total_stall_ns;
    u64 dstate_ns;
    u64 runq_latency_ns;
    u64 futex_wait_ns;
    u32 stall_count;
} __attribute__((packed));

// Internal tracking models
struct offcpu_entry_t {
    u64 start_ts;
    long prev_state;
    u32 pid;
    u32 ppid;
    char comm[16];
};

struct futex_entry_t {
    u64 start_ts;
    u64 uaddr;
    int op;
    u32 pid;
    u32 ppid;
    char comm[16];
};

// Scratchpad per-CPU buffer to eliminate stack frame limit exhaustion
struct scratch_buffer_t {
    struct stall_event_t event;
    struct contention_event_t contention;
    char comm[16];
    char container_id[16];
};

// -----------------------------------------------------------------------------
// BPF Maps
// -----------------------------------------------------------------------------

// Continuous metric hash maps (polled at 1 Hz by CLI/SaaS)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct proc_key_t);
    __type(value, struct proc_stat_t);
} proc_stall_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct container_key_t);
    __type(value, struct container_stat_t);
} container_stall_stats SEC(".maps");

// Ringbuffer streams for discrete high-latency stall events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); // 4MB ring buffer
} stall_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 21); // 2MB ring buffer
} contention_events SEC(".maps");

// Internal correlation state maps (LRU prevents exited-TID exhaustion)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, u32); // tid
    __type(value, struct offcpu_entry_t);
} offcpu_start_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, u32); // tid
    __type(value, u64); // wakeup_ts
} wakeup_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, u32); // tid
    __type(value, struct futex_entry_t);
} futex_start_map SEC(".maps");

// Per-CPU scratchpad memory
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct scratch_buffer_t);
} scratch_map SEC(".maps");

// -----------------------------------------------------------------------------
// Configuration Variables (injected via CLI runtime)
// -----------------------------------------------------------------------------

volatile const u64 threshold_ms = 20;    // Default: 20ms sensitivity for actionable stall diagnostics
volatile const u32 filter_pid = 0;        // 0 = all processes
volatile const u32 filter_stall_type = 0; // 0 = all, 1 = dstate, 2 = runq, 3 = futex
volatile const u32 filter_kthreads = 1;   // Default 1: filter out kernel workqueue threads (kworker, rcu) from discrete alerts

// -----------------------------------------------------------------------------
// CO-RE Definitions for Task Traversal
// -----------------------------------------------------------------------------

struct mm_struct___local {
    unsigned long flags;
} __attribute__((preserve_access_index));

struct task_struct___local {
    struct task_struct___local *real_parent;
    struct task_struct___local *group_leader;
    int tgid;
    int pid;
    char comm[16];
    struct mm_struct___local *mm;
} __attribute__((preserve_access_index));

// -----------------------------------------------------------------------------
// Helper Functions
// -----------------------------------------------------------------------------

static __always_inline int is_kernel_task(struct task_struct___local *task) {
    if (!task) return 0;
    void *mm = BPF_CORE_READ(task, mm);
    if (!mm) return 1;
    char c0 = BPF_CORE_READ(task, comm[0]);
    char c1 = BPF_CORE_READ(task, comm[1]);
    char c2 = BPF_CORE_READ(task, comm[2]);
    if (c0 == 'k' && c1 == 'w' && c2 == 'o') return 1; // kworker
    if (c0 == 'r' && c1 == 'c' && c2 == 'u') return 1; // rcu_preempt / rcu_sched
    if (c0 == 'k' && c1 == 's' && c2 == 'o') return 1; // ksoftirqd
    return 0;
}

// Self-exclusion filter: prevent eprobe from monitoring its own Go runtime
static __always_inline int is_eprobe_comm(const char *comm) {
    if (comm[0] == 'e' && comm[1] == 'p' && comm[2] == 'r' && comm[3] == 'o' && comm[4] == 'b' && comm[5] == 'e') {
        return 1;
    }
    return 0;
}

// Record cumulative metrics in BPF Hash Maps
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
#pragma clang diagnostic ignored "-Wsync-alignment"
static __always_inline void record_stall_metrics(const char *comm, const char *cid, u64 total_stall_ns, u64 dstate_ns, u64 runq_ns, u64 futex_ns) {
    if (is_eprobe_comm(comm)) {
        return;
    }

    // 1. Process breakdown
    struct proc_key_t pkey = {0};
    __builtin_memcpy(pkey.comm, comm, 16);

    struct proc_stat_t *pst = bpf_map_lookup_elem(&proc_stall_stats, &pkey);
    if (pst) {
        __sync_fetch_and_add(&pst->total_stall_ns, total_stall_ns);
        __sync_fetch_and_add(&pst->dstate_ns, dstate_ns);
        __sync_fetch_and_add(&pst->runq_latency_ns, runq_ns);
        __sync_fetch_and_add(&pst->futex_wait_ns, futex_ns);
        __sync_fetch_and_add(&pst->stall_count, 1);
    } else {
        struct proc_stat_t new_pst = {
            .total_stall_ns = total_stall_ns,
            .dstate_ns = dstate_ns,
            .runq_latency_ns = runq_ns,
            .futex_wait_ns = futex_ns,
            .stall_count = 1,
        };
        bpf_map_update_elem(&proc_stall_stats, &pkey, &new_pst, BPF_ANY);
    }

    // 2. Container breakdown (if inside a container)
    if (cid && cid[0] != '\0') {
        struct container_key_t ckey = {0};
        __builtin_memcpy(ckey.container_id, cid, 16);

        struct container_stat_t *cst = bpf_map_lookup_elem(&container_stall_stats, &ckey);
        if (cst) {
            __sync_fetch_and_add(&cst->total_stall_ns, total_stall_ns);
            __sync_fetch_and_add(&cst->dstate_ns, dstate_ns);
            __sync_fetch_and_add(&cst->runq_latency_ns, runq_ns);
            __sync_fetch_and_add(&cst->futex_wait_ns, futex_ns);
            __sync_fetch_and_add(&cst->stall_count, 1);
        } else {
            struct container_stat_t new_cst = {
                .total_stall_ns = total_stall_ns,
                .dstate_ns = dstate_ns,
                .runq_latency_ns = runq_ns,
                .futex_wait_ns = futex_ns,
                .stall_count = 1,
            };
            bpf_map_update_elem(&container_stall_stats, &ckey, &new_cst, BPF_ANY);
        }
    }
}
#pragma clang diagnostic pop

// -----------------------------------------------------------------------------
// Raw Tracepoints: sched_wakeup & sched_wakeup_new (BTF CO-RE Powered)
// -----------------------------------------------------------------------------

static __always_inline int handle_raw_wakeup(struct task_struct___local *p) {
    if (!p) return 0;
    u32 pid = (u32)BPF_CORE_READ(p, tgid);
    if (filter_pid != 0 && pid != filter_pid) return 0;
    char comm[16] = {0};
    BPF_CORE_READ_STR_INTO(&comm, p, comm);
    if (is_eprobe_comm(comm)) return 0;
    u32 tid = (u32)BPF_CORE_READ(p, pid);
    if (tid == 0) return 0;
    u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&wakeup_map, &tid, &now, BPF_ANY);
    return 0;
}

SEC("raw_tracepoint/sched_wakeup")
int raw_trace_sched_wakeup(struct bpf_raw_tracepoint_args *ctx) {
    struct task_struct___local *p = (struct task_struct___local *)ctx->args[0];
    return handle_raw_wakeup(p);
}

SEC("raw_tracepoint/sched_wakeup_new")
int raw_trace_sched_wakeup_new(struct bpf_raw_tracepoint_args *ctx) {
    struct task_struct___local *p = (struct task_struct___local *)ctx->args[0];
    return handle_raw_wakeup(p);
}

// -----------------------------------------------------------------------------
// Raw Tracepoint: sched_switch (Direct Kernel task_struct Pointers)
// -----------------------------------------------------------------------------

SEC("raw_tracepoint/sched_switch")
int raw_trace_sched_switch(struct bpf_raw_tracepoint_args *ctx) {
    // raw_tracepoint/sched_switch prototype:
    // ctx->args[0]: bool preempt
    // ctx->args[1]: struct task_struct *prev
    // ctx->args[2]: struct task_struct *next
    // ctx->args[3]: unsigned int prev_state
    struct task_struct___local *prev = (struct task_struct___local *)ctx->args[1];
    struct task_struct___local *next = (struct task_struct___local *)ctx->args[2];
    unsigned int prev_state = (unsigned int)ctx->args[3];

    u64 now = bpf_ktime_get_ns();

    // -------------------------------------------------------------------------
    // 1. Process Switched-Out Task (prev) -> Record Off-CPU Start Time
    // -------------------------------------------------------------------------
    if (prev) {
        u32 prev_pid = (u32)BPF_CORE_READ(prev, tgid);
        u32 prev_tid = (u32)BPF_CORE_READ(prev, pid);

        // Ignore idle task (PID 0) and apply early filter_pid before map writes
        if (prev_pid > 0 && prev_tid > 0 && (filter_pid == 0 || prev_pid == filter_pid)) {
            u32 ppid = 0;
            struct task_struct___local *parent = BPF_CORE_READ(prev, real_parent);
            if (parent) {
                ppid = (u32)BPF_CORE_READ(parent, tgid);
            }

            struct offcpu_entry_t entry = {
                .start_ts = now,
                .prev_state = (long)prev_state,
                .pid = prev_pid,
                .ppid = ppid,
            };
            BPF_CORE_READ_STR_INTO(&entry.comm, prev, comm);
            if (!is_eprobe_comm(entry.comm)) {
                bpf_map_update_elem(&offcpu_start_map, &prev_tid, &entry, BPF_ANY);
            }
        }
    }

    // -------------------------------------------------------------------------
    // 2. Process Switched-In Task (next) -> Calculate Stall Durations
    // -------------------------------------------------------------------------
    if (!next) return 0;

    u32 next_pid = (u32)BPF_CORE_READ(next, tgid);
    u32 next_tid = (u32)BPF_CORE_READ(next, pid);
    if (next_pid == 0 || next_tid == 0) {
        return 0; // Switched to idle thread
    }
    if (filter_pid != 0 && next_pid != filter_pid) {
        return 0;
    }

    // Calculate runqueue latency (how long thread was waiting after wakeup)
    u64 runq_latency_ns = 0;
    u64 *w_ts = bpf_map_lookup_elem(&wakeup_map, &next_tid);
    if (w_ts) {
        if (now > *w_ts) {
            runq_latency_ns = now - *w_ts;
        }
        bpf_map_delete_elem(&wakeup_map, &next_tid);
    }

    // Calculate Off-CPU duration
    struct offcpu_entry_t *entry = bpf_map_lookup_elem(&offcpu_start_map, &next_tid);
    if (!entry) {
        return 0;
    }

    u64 delta_ns = 0;
    if (now > entry->start_ts) {
        delta_ns = now - entry->start_ts;
    }

    long task_prev_state = entry->prev_state;
    u32 cur_pid = entry->pid;
    u32 cur_ppid = entry->ppid;

    char comm[16] = {0};
    __builtin_memcpy(comm, entry->comm, 16);

    // Done with correlation entry
    bpf_map_delete_elem(&offcpu_start_map, &next_tid);

    // Self-exclusion filter for next task
    if (is_eprobe_comm(comm)) {
        return 0;
    }

    // Optional PID filtering
    if (filter_pid > 0 && cur_pid != filter_pid) {
        return 0;
    }

    // Extract container ID from next task
    char container_id[16] = {0};
    parse_container_id_from_task(next, container_id);

    // Determine stall category
    u64 dstate_ns = 0;
    u64 runq_ns = runq_latency_ns;
    int is_dstate = 0;
    int is_runq = 0;

    // Check if task entered D-state (TASK_UNINTERRUPTIBLE = 0x0002)
    if (task_prev_state & TASK_UNINTERRUPTIBLE) {
        dstate_ns = delta_ns;
        is_dstate = 1;
    } else if (task_prev_state == TASK_RUNNING) {
        // Preempted involuntarily while still runnable
        is_runq = 1;
    }

    // Extract process leader name to aggregate thread pools under the application binary
    char proc_comm[16] = {0};
    struct task_struct___local *leader = BPF_CORE_READ(next, group_leader);
    if (leader) {
        bpf_probe_read_kernel_str(proc_comm, sizeof(proc_comm), leader->comm);
    }
    if (proc_comm[0] == '\0') {
        __builtin_memcpy(proc_comm, comm, 16);
    }

    // Filter kernel threads from both continuous metrics and discrete spikes if filter_kthreads is enabled
    if (filter_kthreads && is_kernel_task(next)) {
        return 0;
    }

    // Update continuous metrics in BPF Hash Maps (aggregated by application process)
    record_stall_metrics(proc_comm, container_id, delta_ns, dstate_ns, runq_ns, 0);

    // -------------------------------------------------------------------------
    // 3. Emit Discrete Stall Spike Event to Ring Buffer
    // -------------------------------------------------------------------------

    u64 threshold_ns = threshold_ms * 1000000ULL;
    if (threshold_ns < 10000000ULL) threshold_ns = 10000000ULL; // Floor at 10ms (10,000,000 ns)

    // Real stalls: D-State (uninterruptible sleep) or Runqueue Starvation
    int emit_spike = 0;
    if (is_dstate && delta_ns >= threshold_ns) {
        emit_spike = 1;
    } else if (runq_latency_ns >= threshold_ns) {
        emit_spike = 1;
    } else if (is_runq && delta_ns >= threshold_ns) {
        emit_spike = 1;
    }

    if (!emit_spike) {
        return 0;
    }

    // Filter stall type if requested
    if (filter_stall_type == 1 && !is_dstate) return 0;
    if (filter_stall_type == 2 && !is_runq && runq_latency_ns < threshold_ns) return 0;

    // Allocate from ringbuffer directly
    struct stall_event_t *e = bpf_ringbuf_reserve(&stall_events, sizeof(struct stall_event_t), 0);
    if (!e) {
        return 0; // Ringbuffer full
    }

    e->pid = cur_pid;
    e->tid = next_tid;
    e->ppid = cur_ppid;
    __builtin_memcpy(e->comm, comm, 16);
    __builtin_memcpy(e->container_id, container_id, 16);
    e->duration_us = delta_ns / 1000ULL;
    e->runq_latency_us = runq_latency_ns / 1000ULL;

    // Classify stall type and severity
    if (is_dstate) {
        __builtin_memcpy(e->stall_type, "D_STATE_IO", 11);
        if (e->duration_us >= 100000) { // >= 100ms
            __builtin_memcpy(e->level, "CRITICAL", 8);
        } else {
            __builtin_memcpy(e->level, "WARN", 5);
        }
        const char msg[] = "Uninterruptible sleep (D-state) stall on disk I/O, sync, or page writeback";
        __builtin_memcpy(e->message, msg, sizeof(msg) < 128 ? sizeof(msg) : 127);
    } else {
        __builtin_memcpy(e->stall_type, "RUNQ_STARVE", 12);
        if (e->runq_latency_us >= 100000) { // >= 100ms
            __builtin_memcpy(e->level, "CRITICAL", 8);
        } else {
            __builtin_memcpy(e->level, "WARN", 5);
        }
        const char msg[] = "Runnable queue starvation (CPU saturation or container CFS quota throttled)";
        __builtin_memcpy(e->message, msg, sizeof(msg) < 128 ? sizeof(msg) : 127);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// -----------------------------------------------------------------------------
// Tracepoints: sys_enter_futex / sys_exit_futex (Lock Contention)
// -----------------------------------------------------------------------------

static __always_inline int handle_futex_enter(u64 uaddr, int op) {
    int cmd = op & FUTEX_CMD_MASK;
    // Only trace lock wait / acquire operations (exclude instant FUTEX_WAKE)
    if (cmd != FUTEX_WAIT && cmd != FUTEX_WAIT_BITSET && cmd != FUTEX_LOCK_PI && cmd != FUTEX_WAIT_REQUEUE_PI) {
        return 0;
    }

    char comm[16] = {0};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (is_eprobe_comm(comm)) {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    if (filter_pid > 0 && pid != filter_pid) {
        return 0;
    }

    struct task_struct___local *task = (struct task_struct___local *)bpf_get_current_task();
    u32 ppid = 0;
    if (task) {
        struct task_struct___local *parent = BPF_CORE_READ(task, real_parent);
        if (parent) {
            ppid = (u32)BPF_CORE_READ(parent, tgid);
        }
    }

    u64 now = bpf_ktime_get_ns();
    struct futex_entry_t entry = {
        .start_ts = now,
        .uaddr = uaddr,
        .op = op,
        .pid = pid,
        .ppid = ppid,
    };
    __builtin_memcpy(entry.comm, comm, sizeof(entry.comm));

    bpf_map_update_elem(&futex_start_map, &tid, &entry, BPF_ANY);
    return 0;
}

static __always_inline int handle_futex_exit(long ret) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;

    struct futex_entry_t *entry = bpf_map_lookup_elem(&futex_start_map, &tid);
    if (!entry) {
        return 0;
    }

    // Always clean up correlation state
    bpf_map_delete_elem(&futex_start_map, &tid);

    // Filter out intentional periodic heartbeat / sleep timers (-ETIMEDOUT = -110)
    // Only genuine lock contention (woken up by FUTEX_WAKE when ret == 0 or ret > 0) is tracked
    if (ret == -110) {
        return 0;
    }

    u64 now = bpf_ktime_get_ns();
    u64 wait_ns = 0;
    if (now > entry->start_ts) {
        wait_ns = now - entry->start_ts;
    }

    u64 uaddr = entry->uaddr;
    int op = entry->op;
    u32 pid = entry->pid;
    u32 ppid = entry->ppid;

    char comm[16] = {0};
    __builtin_memcpy(comm, entry->comm, 16);

    if (is_eprobe_comm(comm)) {
        return 0;
    }

    struct task_struct___local *task = (struct task_struct___local *)bpf_get_current_task();
    if (filter_kthreads && is_kernel_task(task)) {
        return 0;
    }

    char container_id[16] = {0};
    parse_container_id_from_task(task, container_id);

    // Extract process leader name to aggregate thread pools under the application binary
    char proc_comm[16] = {0};
    struct task_struct___local *leader = BPF_CORE_READ(task, group_leader);
    if (leader) {
        bpf_probe_read_kernel_str(proc_comm, sizeof(proc_comm), leader->comm);
    }
    if (proc_comm[0] == '\0') {
        __builtin_memcpy(proc_comm, comm, 16);
    }

    // Record in continuous metrics (aggregated by application process)
    record_stall_metrics(proc_comm, container_id, wait_ns, 0, 0, wait_ns);

    // Check spike threshold (floor at 10ms to eliminate fast normal runtime sync)
    u64 threshold_ns = threshold_ms * 1000000ULL;
    if (threshold_ns < 10000000ULL) threshold_ns = 10000000ULL;

    if (wait_ns < threshold_ns) {
        return 0;
    }

    if (filter_stall_type != 0 && filter_stall_type != 3) {
        return 0;
    }

    // Emit dedicated contention event strictly to contention_events (Page 3)
    struct contention_event_t *e = bpf_ringbuf_reserve(&contention_events, sizeof(struct contention_event_t), 0);
    if (e) {
        e->pid = pid;
        e->tid = tid;
        e->ppid = ppid;
        __builtin_memcpy(e->comm, comm, 16);
        __builtin_memcpy(e->container_id, container_id, 16);
        e->lock_addr = uaddr;
        e->duration_us = wait_ns / 1000ULL;

        int cmd = op & FUTEX_CMD_MASK;
        if (cmd == FUTEX_LOCK_PI) {
            __builtin_memcpy(e->op_type, "LOCK_PI", 8);
        } else if (cmd == FUTEX_WAIT_BITSET) {
            __builtin_memcpy(e->op_type, "WAIT_BITSET", 12);
        } else {
            __builtin_memcpy(e->op_type, "FUTEX_WAIT", 11);
        }

        if (e->duration_us >= 100000) { // >= 100ms lock freeze
            __builtin_memcpy(e->level, "CRITICAL", 8);
        } else {
            __builtin_memcpy(e->level, "WARN", 5);
        }

        const char msg[] = "Mutex/rwlock contention wait exceeded stall threshold";
        __builtin_memcpy(e->message, msg, sizeof(msg) < 128 ? sizeof(msg) : 127);

        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_futex")
int trace_sys_enter_futex(struct trace_event_raw_sys_enter *ctx) {
    return handle_futex_enter((u64)ctx->args[0], (int)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_exit_futex")
int trace_sys_exit_futex(struct trace_event_raw_sys_exit *ctx) {
    return handle_futex_exit(ctx->ret);
}

// -----------------------------------------------------------------------------
// Tracepoints: futex_waitv (Linux 5.16+ modern runtime support)
// -----------------------------------------------------------------------------

SEC("tracepoint/syscalls/sys_enter_futex_waitv")
int trace_sys_enter_futex_waitv(struct trace_event_raw_sys_enter *ctx) {
    return handle_futex_enter((u64)ctx->args[0], FUTEX_WAIT);
}

SEC("tracepoint/syscalls/sys_exit_futex_waitv")
int trace_sys_exit_futex_waitv(struct trace_event_raw_sys_exit *ctx) {
    return handle_futex_exit(ctx->ret);
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
