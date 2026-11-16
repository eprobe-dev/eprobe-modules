# sys/syscall-xray: Production-Safe Syscall Failure & Latency X-Ray (`strace` Alternative)

The **`sys/syscall-xray`** module is an ephemeral, read-only CO-RE eBPF replacement for `strace -p <PID>` and `strace -c -T`. While `strace` attaches via `ptrace`—stopping the target thread twice on every syscall and imposing severe latency spikes under load—`syscall-xray` captures syscall failures, slow calls, file paths (`openat`/`openat2`), socket connect targets, and cumulative per-syscall histograms in kernel space with minimal host impact.

---

## 1. Module Overview & Scope

* **Target Roles**: Site Reliability Engineers (SREs), L3 Escalation Engineers, and Linux Systems Developers.
* **Target Workloads**: High-throughput HTTP/RPC services, databases, CLI workers, and containerized daemons experiencing `ENOENT`, `EACCES`, `ECONNREFUSED`, `ETIMEDOUT`, or mysterious tail latency.
* **Overhead Profile**:
  * In-kernel hash map aggregation (`syscall_stats`) tracks call counts, error counts, and cumulative nanoseconds with zero per-call user-space context switches.
  * Ring buffer emissions (`syscall_events`) fire only on failures (`ret < 0`, filtering out `-EAGAIN`/`-EINPROGRESS` noise by default) or syscalls slower than `--slow-us` (default `10000` µs = 10ms).
  * Early `filter_pid` and `is_eprobe_comm()` checks run at probe entry before map writes.

---

## 2. Key Technical Capabilities

### 1. Rich Path & Socket Target Capture
* **`openat` & `openat2`**: Captures up to 128 bytes of the requested filesystem path alongside `errno` (`ENOENT`, `EACCES`, `EMFILE`, `ENAMETOOLONG`).
* **`connect`**: Decodes `AF_INET` (`daddr` + `dport`), `AF_INET6` (`dport`), and `AF_UNIX` (`sun_path` / abstract socket labels) without unbounded loops to pinpoint `ECONNREFUSED` and `ETIMEDOUT` connection failures.

### 2. In-Kernel `strace -c -T` Summary Map (`syscall_stats`)
* Hooks `raw_tracepoint/sys_enter` and `raw_tracepoint/sys_exit` to record `total_ns`, `call_count`, and `error_count` per syscall into a `BPF_MAP_TYPE_HASH` map polled at 1 Hz by `eprobe`.
* Uses `BPF_MAP_TYPE_LRU_HASH` for in-flight tracking (`inflight_syscalls`, `spec_args_map`) so short-lived or crashing threads never exhaust map capacity.

### 3. Noise Suppression & Transient Errno Gating
* Suppresses benign non-blocking socket polling noise (`-EAGAIN`, `-EINPROGRESS`) from the discrete failure stream unless `--include-transient 1` is passed.
* Excludes normal idle sleep syscalls (`epoll_wait`, `futex`, `poll`, `nanosleep`) from slow-syscall alerts unless they return a non-transient error.

---

## 3. Exported Telemetry Maps & Schemas

| Map Name | Type | Key / Value Struct | Description |
| :--- | :--- | :--- | :--- |
| **`syscall_events`** | `ringbuf` (4 MB) | `struct syscall_event_t` (236B) | Failed (`ret < 0`) and slow (`>= slow_threshold_us`) syscalls with PID, TID, PPID, `comm`, `container_id`, `syscall`, `target`, `daddr`, `dport`, `errno_code`, `errno_name`, `duration_us`, and `level`. |
| **`syscall_stats`** | `hash` (512 entries) | `syscall_stat_key_t` (20B) $\to$ `syscall_stat_t` (24B) | Cumulative nanoseconds (`total_ns`), total calls (`call_count`), and error count (`error_count`) per syscall (`strace -c` equivalent). |

---

## 4. Multi-Page Dashboard & Pane Breakdown

### Page 1: "Syscall Failure & Slow Stream"
* **Failing & Slow Syscall Rate (`sparkline`)**: Real-time events/sec trend of emitted syscall errors and slow calls.
* **Syscall Latency Distribution (`histogram`)**: Microsecond distribution across buckets `[100, 500, 1000, 5000, 10000, 50000, 250000]`.
* **Syscall Failure & Slow Stream (`stream`)**: Live table of failing and slow syscalls with searchable `comm`, `syscall`, `target`, `errno_name`, and `container_id`.

### Page 2: "Syscall Summary Leaderboard"
* **Top Syscalls by Cumulative Time (`top`, `delta_rate`)**: Ranked by `total_ns` rate (`s/s`).
* **Top Syscalls by Call Count (`top`, `value`)**: Ranked by cumulative `call_count`.
* **Top Syscalls by Error Count (`top`, `value`)**: Ranked by cumulative `error_count`.
* **Top Failing Error Codes (`top`, `count`)**: Distribution of `ENOENT`, `EACCES`, `ECONNREFUSED`, `ETIMEDOUT`, etc.

---

## 5. Usage & CLI Options

```bash
# Trace syscall failures & >10ms calls for a specific PID
sudo eprobe run sys/syscall-xray --pid <PID>

# Emit strictly failing syscalls (skip slow-threshold non-error events)
sudo eprobe run sys/syscall-xray --pid <PID> --errors-only

# Lower slow-syscall threshold to 1ms (1000 us) and emit NDJSON
sudo eprobe run sys/syscall-xray --pid <PID> --slow-us 1000 -output json

# Include transient EAGAIN / EINPROGRESS errors
sudo eprobe run sys/syscall-xray --pid <PID> --include-transient 1

# Run locally compiled unsigned module without network registry access
sudo eprobe run --module-file ./dist/sys-syscall-xray.epm --pid <PID>
```
