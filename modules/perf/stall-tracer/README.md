# perf/stall-tracer: Kernel Off-CPU Stall & Scheduler Contention Diagnostics

The **`perf/stall-tracer`** module is an ephemeral, tactical eBPF incident response utility engineered to diagnose unexplained server hangs, thread pool freezes, and tail-latency spikes. In production environments, standard metrics utilities like `top`, `htop`, or APM agents alert that a system is degraded or load averages are climbing, but fail to explain *why* because the CPU appears idle or under-utilized. 

More than 80% of severe production stalls occur **Off-CPU**: worker threads blocked in uninterruptible disk sleep (`TASK_UNINTERRUPTIBLE` / D-state), serialized on user-space synchronization primitives (`futex`), delayed in direct page memory reclaim, or starved on the Linux runqueue waiting for available CPU time slices. Traditional diagnostics like `strace` attach via `ptrace`, imposing up to a 100x overhead penalty that risks crashing production databases and services.

`perf/stall-tracer` instruments the Linux kernel scheduler and locking subsystems non-invasively using read-only CO-RE eBPF probes, extracting microsecond-resolution telemetry with `<1%` CPU overhead across terminal TUI and browser-based diagnostic views.

---

## 1. Tactical Incident Scope & Target Personas

* **Target Roles**: Site Reliability Engineers (SREs), L3 Escalation Engineers, Database Administrators (DBAs), and Platform DevOps.
* **Target Workloads**: Multi-threaded application runtimes (Go, Node.js, Java JVM, Rust, Python, PHP-FPM), databases (MySQL, MariaDB, PostgreSQL, Redis, MongoDB), and containerized environments (Docker, containerd, Kubernetes).
* **Core Incident Scenarios**:
  - **The Ghost Bottleneck**: Host CPU is at 3% and load average is soaring, but application throughput drops to 0 QPS due to `futex` rwlock contention.
  - **Storage Controller Stalls**: Database flusher threads blocked in D-state sleep waiting on physical block I/O writeback or cloud volume throttles.
  - **CPU Starvation / CFS Quota Throttling**: Runnable threads stalled in queue (`RUNQ_STARVE`) waiting for CPU cores or restricted by container CFS bandwidth limits.
* **Overhead Profile**: In-kernel hash map aggregation handles 200,000+ scheduler switches per second with `<1%` CPU utilization. Rings buffer emissions are gated behind production-grade latency thresholds (`--threshold-ms`, default 20ms, hardware floor 10ms). Clean detach on `Ctrl+C` leaves zero host sidecars or background agents behind.

---

## 2. Key Technical Capabilities

### Observer Effect Elimination (Collector Self-Exclusion)
Because `eprobe` runs a compiled Go runtime utilizing channels, garbage collection, and runtime scheduling (`sysmon`), an unoptimized tracer measuring futex locks and scheduler switches can inadvertently profile itself. `perf/stall-tracer` eliminates this observer effect in kernel space (`is_eprobe_comm`):
- All collector threads (`eprobe`, `eprobe-cli`, `eprobe-pack`) are checked at the BPF probe entry point.
- The collector's own scheduling events and futex calls are filtered from continuous hash maps (`proc_stall_stats`) and discrete alert streams (`stall_events`, `contention_events`), guaranteeing that telemetry strictly reflects monitored target workloads.

### True Lock Contention Engine (Filtering Periodic Sleep Timers)
Modern asynchronous runtimes and databases (MongoDB, Tokio, Java JVM, Go) employ `pthread_cond_timedwait` or `futex(..., timeout)` for periodic timer heartbeats (e.g. MongoDB `ThroughputMonitor` running every 100ms, `JournalFlusher` waking every 100ms). When these timers expire without an explicit wake, the kernel returns `-ETIMEDOUT` (`-110`). `perf/stall-tracer` inspects the return code:
- If `ret == -110` (`-ETIMEDOUT`), the event is discarded as an intentional voluntary sleep timer.
- If `ret == 0` (or `ret > 0` in `waitv`), the thread was actively blocked waiting for a synchronization primitive released by another thread calling `FUTEX_WAKE`, isolating true user-space lock contention.

### Kernel Thread Workqueue Noise Gating (`--filter-kthreads`)
Linux `kworker`, `migration/`, and `rcu_preempt` threads routinely spend 100ms–1000ms in `TASK_UNINTERRUPTIBLE` waiting for physical disk DMA completions and dirty page writebacks. While normal for the kernel, these events can flood diagnostic streams. `perf/stall-tracer` implements kernel thread gating:
- Tasks with `task->mm == NULL` or matching kernel thread signatures (`kworker/`, `rcu_`, `ksoftirqd/`, `migration/`) are gated by `filter_kthreads` (default: 1).
- Gating applies to **both continuous metric leaderboards** (`proc_stall_stats`) and **discrete alert streams** (`stall_events`), strictly surfacing user-space application bottlenecks (MySQL, MongoDB, PostgreSQL, Redis, Docker, Node.js), while still allowing full kernel inspection via `--filter-kthreads 0`.

### Application-Level Process Leader Aggregation
In Linux, `task->comm` is limited to 16 bytes and often reflects thread worker names (`Through.Monitor`, `tokio-rt-worker`). `perf/stall-tracer` resolves the process group leader (`task->group_leader->comm`), aggregating all worker threads under the parent application binary (e.g. `mongod`, `mariadbd`) in `proc_stall_stats`.

### Production-Grade Noise Filtering & Anomaly Classification
In multi-tenant server workloads, sub-millisecond or 1–3ms thread yield times are normal cooperative runtime operations (e.g. Go goroutine parking, Java thread yields). Treating these as stalls creates telemetry noise. `perf/stall-tracer` implements an intelligent multi-tier filtering model:
- **Diagnostic Noise Floor:** The minimum alert threshold is bounded to 10ms in kernel bytecode, with a default `--threshold-ms` of **20ms**.
- **Severity Classification:** Stalls are dynamically classified with standard anomaly tokens:
  - `>= 100ms`: Tagged as `CRITICAL` (indicates severe user-impacting freezes, e.g. journal flusher lockouts, storage controller pauses).
  - `>= 20ms`: Tagged as `WARN` (actionable latency spikes requiring investigation).
  - `< 20ms`: Filtered out of discrete spike streams to maintain clean, high-signal alerts.
- **Runqueue Preemption Diagnostic Token:** `RUNQ_STARVE` events explicitly annotate: `"Runnable queue starvation (CPU saturation or container CFS quota throttled)"`.

### Strict Subsystem Telemetry Isolation
To prevent cross-contamination across diagnostic inspector views:
- **`stall_events` Ring Buffer:** Dedicated strictly to kernel scheduler stalls (`D_STATE_IO` and `RUNQ_STARVE`). This ensures Page 2 ("Uninterruptible Sleep & Block I/O Diagnostics") displays exclusively disk, I/O, and runnable starvation freezes without pollution from mutex locks.
- **`contention_events` Ring Buffer:** Dedicated strictly to user-space synchronization primitives (`syscalls/sys_enter_futex`, `sys_enter_futex_waitv`). This feeds Page 3 ("Mutex & Futex Contention Triage").
- Continuous metric maps (`proc_stall_stats` and `container_stall_stats`) track all stall dimensions aggregated in kernel space.

### Universal Kernel Hook Strategy (Raw Tracepoints & Zero `CONFIG_SCHEDSTATS` Dependency)
Traditional tracing tools often require the optional kernel config flag `CONFIG_SCHEDSTATS=y` (commonly disabled in enterprise and cloud kernels such as AWS AL2/AL2023, Debian, and RHEL). Furthermore, standard tracepoints (`tracepoint/sched/*`) suffer from kernel ABI struct layout shifts across kernel versions.

`perf/stall-tracer` implements an unconditionally compatible `raw_tracepoint` hook strategy with direct BTF CO-RE `task_struct` traversal:
1. **Off-CPU & Uninterruptible Sleep (D-State):** Hooks `raw_tracepoint/sched_switch`. Traverses direct kernel `task_struct` pointers (`ctx->args[1]` for `prev`, `ctx->args[2]` for `next`). When a task is switched out, it stores `start_ts` and `prev_state`. When the task is switched back in, it calculates the elapsed duration. If `prev_state & TASK_UNINTERRUPTIBLE` (`0x0002`), the stall is classified as `D_STATE_IO`. If `prev_state == TASK_RUNNING`, it is classified as `RUNQ_STARVE`.
2. **Runqueue Latency:** Hooks `raw_tracepoint/sched_wakeup` and `raw_tracepoint/sched_wakeup_new` directly reading `ctx->args[0]` to stamp runnable timestamps, computing exact queue wait delays inside `raw_tracepoint/sched_switch`.
3. **Universal Mutex & Lock Contention:** Hooks `syscalls/sys_enter_futex` and `syscalls/sys_exit_futex`, as well as modern Linux 5.16+ `syscalls/sys_enter_futex_waitv` (syscall 449) used by modern Go, glibc 2.34+, and Rust runtimes.

### Dual-Plane Telemetry Engine
To eliminate ring buffer saturation during scheduler storms while guaranteeing immediate UI interactivity:
* **Fast Plane (Continuous Aggregation):** Maintains cumulative nanosecond counters in `proc_stall_stats` and `container_stall_stats` BPF Hash Maps. Polled at 1 Hz by `eprobe-cli` and `eprobe-saas` for smooth, zero-drop rate leaderboards.
* **Slow Plane (Spike Alert Ring Buffer):** Only emits discrete `stall_event_t` and `contention_event_t` records when stall durations exceed `--threshold-ms` (default 20ms, floor 10ms), capturing actionable incident data without noise.

---

## 3. Exported Telemetry Maps & Schemas

### 1. BPF Maps Overview

| Map Name | Map Type | Key Struct / Type | Value Struct / Type | Role & Description |
| :--- | :--- | :--- | :--- | :--- |
| **`proc_stall_stats`** | `BPF_MAP_TYPE_HASH` | `struct proc_key_t` (`comm[16]`) | `struct proc_stat_t` | Cumulative stall, D-state, runqueue, and futex nanoseconds grouped by process name. |
| **`container_stall_stats`**| `BPF_MAP_TYPE_HASH` | `struct container_key_t` (`container_id[16]`) | `struct container_stat_t` | Cumulative stall metrics aggregated by 12-char container identifier. |
| **`stall_events`** | `BPF_MAP_TYPE_RINGBUF` | N/A (Event Capture) | `struct stall_event_t` | Discrete stream of threshold-exceeding Off-CPU, D-state, and runqueue starvation incidents. |
| **`contention_events`** | `BPF_MAP_TYPE_RINGBUF` | N/A (Event Capture) | `struct contention_event_t` | Discrete stream of high-latency user-space mutex and futex lock acquisition delays. |

### 2. Event Struct Schemas

#### `struct stall_event_t` (Event Ring Buffer - Exact 212 Bytes)
```c
struct stall_event_t {
    u32 pid;              // Userspace Process ID
    u32 tid;              // Thread ID experiencing the stall
    u32 ppid;             // Parent Process ID
    char comm[16];        // Command executable name
    char container_id[16];// 12-char hex container identifier
    char stall_type[16];  // D_STATE_IO, RUNQ_STARVE, LOCK_FUTEX
    u64 duration_us;      // Total stall duration in microseconds
    u64 runq_latency_us;  // Runnable queue wait delay in microseconds
    char level[8];        // CRITICAL, WARN, INFO
    char message[128];    // Actionable human-readable diagnostic message
} __attribute__((packed));
```

#### `struct contention_event_t` (Contention Ring Buffer - Exact 212 Bytes)
```c
struct contention_event_t {
    u32 pid;              // Userspace Process ID
    u32 tid;              // Thread ID waiting on lock
    u32 ppid;             // Parent Process ID
    char comm[16];        // Command executable name
    char container_id[16];// 12-char hex container identifier
    char op_type[16];     // FUTEX_WAIT, LOCK_PI, WAIT_BITSET
    u64 lock_addr;        // Virtual address of contended user-space lock
    u64 duration_us;      // Lock acquisition delay in microseconds
    char level[8];        // CRITICAL, WARN, INFO
    char message[128];    // Diagnostic anomaly message
} __attribute__((packed));
```

---

## 4. Multi-Page Diagnostic Views & Inspector Panes

`perf/stall-tracer` provides a structured 4-page diagnostic layout conforming to `eprobe`'s dynamic presentation standard:

### Page 1: "System Off-CPU & Scheduler Overview"
* **System Stall Event Rate (`sparkline`):** Real-time trend of stall spike frequency per second over a rolling 60-second window.
* **Stall Latency Distribution (`histogram`):** Logarithmic distribution curve (`buckets: [20000, 50000, 100000, 250000, 500000, 1000000, 2000000]`) in microseconds.
* **Top Stalled Processes (`top`):** Real-time leaderboard of processes ranked by continuous rate of off-CPU stall time (backed by `proc_stall_stats` BPF hash map, formatted in `s/s`).
* **Top Stalled Containers (`top`):** Leaderboard of containers ranked by cumulative off-CPU stall rate (backed by `container_stall_stats`).
* **Stall Cause Breakdown (`top`):** Relative breakdown between `D_STATE_IO`, `RUNQ_STARVE`, and `LOCK_FUTEX`.

### Page 2: "Uninterruptible Sleep & Block I/O Diagnostics (D-State)"
* **Top Processes Blocked in D-State (`top`):** Processes ranked by continuous D-state stall rate (`s/s`) spent in `TASK_UNINTERRUPTIBLE`.
* **D-State Duration Distribution (`histogram`):** Latency spectrum of storage writeback, fsync, and memory reclaim delays (`buckets: 20ms to 2s`).
* **Severe D-State Freeze Stream (`stream`):** Live chronological table of application disk and paging stalls with container names, thread IDs, and durations.

### Page 3: "Mutex & Futex Contention Triage"
* **Top Lock Contention Victims (`top`):** Processes waiting longest for user-space synchronization primitives.
* **Futex Wait Latency Distribution (`histogram`):** Microsecond distribution of genuine lock acquisition wait times (`buckets: 20ms to 2s`), highlighting anomalous tail-latency buckets.
* **Lock Contention Incident Stream (`stream`):** Chronological stream of lock contention incidents displaying lock addresses, futex operation types, and thread IDs (excluding timer heartbeats).

### Page 4: "Thread Pool Diagnostic Tree & Trace Hierarchy"
* **Process & Worker Thread Bottleneck Tree (`tree`):** Hierarchical process tree configured with `node_id: tid` and `parent_id: pid`. Synthesizes virtual process leader roots so worker threads group under their parent application binary with latency badges and warning chips (`⚠️`).
* **Stall Incident Audit Stream (`stream`):** Chronological audit log of all system stall anomalies.

---

## 5. Tactical Incident Workflows & CLI Usage

### 1. Interactive Terminal TUI Triage
```bash
# Launch stall-tracer with default 20ms threshold and kernel thread gating
sudo eprobe run perf/stall-tracer

# Isolate stalls for a specific target process PID during a live incident
sudo eprobe run perf/stall-tracer --pid 4120

# Filter exclusively for D-state (disk / block I/O) stalls
sudo eprobe run perf/stall-tracer --stall-type 1

# Launch with custom sensitivity threshold (e.g. 50ms for coarse anomaly triage)
sudo eprobe run perf/stall-tracer --threshold-ms 50

# Include Linux kernel worker threads (kworker, rcu) in discrete alert streams
sudo eprobe run perf/stall-tracer --filter-kthreads 0
```

### 2. Collaborative Browser Diagnostic View & Incident Telemetry
```bash
# Extract telemetry to browser-based collaborative diagnostic view
sudo eprobe run perf/stall-tracer --stream-token <YOUR_TOKEN>
```

### 3. Air-Gapped BYO-LLM Root Cause Analysis
During an active triage session in the Web Inspector, click **`Offline AI Bundle`** in the top navigation bar. 
- Generates a local, sanitized `.zip` archive containing `00_PROMPT_COPY_PASTE.md` and statistical health profiles (`01_EXECUTIVE_SUMMARY.md`).
- Designed for zero cloud egress: paste directly into your private ChatGPT, Claude, or local Ollama instance for instant root-cause analysis without leaking credentials, PII, or internal host topologies.

### 4. Non-Interactive NDJSON Forwarding
```bash
# Export structured JSON for triage pipelines (jq, ripgrep, SIEM)
sudo eprobe run perf/stall-tracer -output json
```

### 5. Compilation & Verification
```bash
# Compile eBPF C code and verify cryptographic signing
cd eprobe-modules
make compile
go test -v ./...
```
