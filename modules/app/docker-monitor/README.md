# app/docker-monitor: Container Runtime & Cgroup Throttling Diagnostics

The **`app/docker-monitor`** module is an ephemeral, tactical eBPF incident response utility engineered for **Docker, containerd, and Kubernetes (CRI-O)** on Linux. It isolates container execution freezes, Out-of-Memory (OOM) kills, silent container crashes, cgroup CPU bandwidth throttling, and inter-container network bottlenecks with zero container modification or sidecar injection.

---

## 1. Tactical Incident Scope & Target Personas

* **Target Roles**: Site Reliability Engineers (SREs), Kubernetes Platform Engineers, and Incident Escalation Teams.
* **Target Runtimes**: Docker Engine, containerd, Podman, and Kubernetes worker nodes running CRI-O.
* **Core Incident Scenarios**:
  - **The Container Black Box**: A microservice container crashes or enters a restart loop. Standard container metrics report high memory usage right before death, but cannot identify which specific subprocess triggered the kernel OOM killer or exit code.
  - **CFS Quota CPU Throttling**: Applications experience unexplained multi-second latency spikes because container CPU limits (`cpu.cfs_quota_us`) throttle execution threads while the physical host has ample idle CPU capacity.
  - **Inter-Container Network Stalls**: Slow response times between frontend proxies and backend worker containers with unclear network transit latency.
* **Overhead Profile**: Read-only CO-RE eBPF hooks attach dynamically to host kernel tracepoints. Employs dual-plane telemetry (1Hz continuous BPF hash maps and discrete 16MB ring buffers) with `<1%` CPU utilization. Clean detach with `Ctrl+C` leaves zero background agents on the host.

---

## 2. Key Technical Capabilities

### 1. Zero-Instrumentation Container Auto-Discovery
- **Kernel-Level Cgroup Resolution**: Hooks `cgroup_mkdir` and `cgroup_rmdir` raw tracepoints to track container lifecycle events (creation, initialization, destroy) in real time.
- **Dynamic Container ID Extraction**: Reads container IDs directly from task cgroup paths (`/docker/<id>`, `/kubepods/.../<id>`) in kernel space, isolating telemetry across multi-tenant worker nodes without requiring sidecars or host namespace mapping.
- **User-Space Container Resolution**: Interacts with local container runtime sockets (`/var/run/docker.sock`, containerd, and `/proc` cgroups) to translate raw 12-char/64-char container hexadecimal hashes into human-readable container names (`komodo-core`, `frontend-nginx`) and image tags.
- **Universal Multi-Pane Entity Resolution Parity**: Conforms to Section 1.3 of the eProbe Protocols specification. Container hashes (`container_id`) are dynamically resolved into human-readable container names across all 5 visual primitives: Leaderboards (`top`), Stream Tables (`stream`), Process Trees (`tree`), Network Topology Graphs, and Inspect Modals on both Web Inspector and Terminal TUI without kernel bytecode overhead.

### 2. Decoupled OOM Kill & Process Crash Detection
- **Out-of-Memory (OOM) Hook**: Hooks `oom_kill_process` to strictly capture Linux kernel Out-of-Memory terminations (SIGKILL 137), recording the victim container ID, process comm, and OOM event details directly to `oom_events`.
- **Process Exit Auditing**: Hooks `sched/sched_process_exit` to decode POSIX exit statuses (`task->exit_code`), filtering out clean terminations (`exit 0`) and routing non-zero script failures and fatal signal crashes (SIGSEGV, SIGABRT) to the dedicated `app_crash_events` stream.

### 3. Container Resource Saturation (Hash Map Polling)
- **CPU Scheduling Profiling (`cpu_stats`)**: Hooks `sched/sched_stat_runtime` to calculate delta CPU utilization (`CPU %`) per container.
- **Memory Tracking (`mem_stats`)**: Hooks `kmem/mm_page_alloc` and `kmem/mm_page_free` to track live Resident Set Size (`rss_bytes`) per container.
- **Network Bandwidth (`net_stats`)**: Tracks transmitted (`tx_bytes`) and received (`rx_bytes`) throughput per container using BPF hash maps polled on a 1-second ticker.
- **Block I/O Throughput (`io_stats`)**: Aggregates read and write throughput per container (`nr_sector * 512`) for disk storage operations using CO-RE `trace_event_raw_block_rq_completion___local` (`__attribute__((preserve_access_index))`) across Linux 5.x, 6.x, and 7.0+ kernels.

### 4. Inter-Container Network Latency & Topology
- **TCP Connection Flow Tracing**: Hooks `tcp_v4_connect`, `tcp_sendmsg`, and `tcp_recvmsg` to record connection handshakes, source/destination IPs, and target ports.
- **Microsecond Round-Trip Latency**: Measures round-trip network response times (`latency_us`) for inter-container service communication and outbound API requests.

### 5. Stdout/Stderr Diagnostic Log Interception & Pure eBPF "docker logs" Parity
- **Container Stdio Inode Gating**: Hooks `sys_enter_write` and `sys_enter_writev` for file descriptors 1 (`stdout`) and 2 (`stderr`). Tracks the container root entrypoint's stdout/stderr pipe inodes in `container_stdio_map`, automatically dropping writes from internal subprocesses using anonymous pipes.
- **Smart Stream Classification & Noise Pruning**: Discards sub-3-byte status digit noise (e.g. bare exit codes `0`, `4` and bare newlines) and classifies lines into `INFO` (stdout), `STDERR` (standard stderr), and `ERROR` (payloads containing `ERR`, `FATAL`, `CRIT`, `FAIL`), eliminating false alarm red badges for normal stderr output.

---

## 3. Exported Telemetry Maps & Schemas

| Map Name | Type | Key / Value Struct | Description |
| :--- | :--- | :--- | :--- |
| **`proc_events`** | `ringbuf` (16 MB) | `struct proc_event_t` | Real-time process execution events (`execve`) with PID, PPID, UID, COMM, filename, and container ID. |
| **`oom_events`** | `ringbuf` (16 MB) | `struct oom_event_t` | Kernel OOM kill events strictly invoked by `oom_kill_process` (SIGKILL 137). |
| **`app_crash_events`** | `ringbuf` (16 MB) | `struct app_crash_event_t` | Container non-zero process exits (`exit_code != 0`), command failures, and signal crashes. |
| **`log_events`** | `ringbuf` (16 MB) | `struct log_event_t` | Container stdout and stderr diagnostic log stream intercepted from kernel write syscalls. |
| **`net_events`** | `ringbuf` (16 MB) | `struct net_event_t` | Inter-container TCP network connections with source, destination, port, and microsecond latency. |
| **`io_events`** | `ringbuf` (16 MB) | `struct io_event_t` | Block storage request stream with read/write flags, bytes, and latency. |
| **`lifecycle_events`** | `ringbuf` (16 MB) | `struct lifecycle_event_t` | Chronological audit log of container cgroup creation and destruction events. |
| **`cpu_stats`** | `hash` (1024 entries) | `container_key_t` $\to$ `cpu_stat_t` | Instantaneous CPU runtime utilization delta statistics aggregated per container. |
| **`mem_stats`** | `hash` (1024 entries) | `container_key_t` $\to$ `mem_stat_t` | Resident memory size (RSS bytes) aggregated per container. |
| **`net_stats`** | `hash` (1024 entries) | `container_key_t` $\to$ `net_stat_t` | Transmitted and received network throughput (Bytes/sec) per container. |
| **`io_stats`** | `hash` (1024 entries) | `container_key_t` $\to$ `io_stat_t` | Disk read and write throughput (Bytes/sec) per container. |

---

## 4. Multi-Page Diagnostic Views & Inspector Panes

### Page 1: Container Health & Anomaly Triage
- **Container Event Throughput**: Real-time event throughput sparkline (events/sec) over a rolling 60-second window.
- **Network Latency Distribution**: Histogram of container network round-trip latencies (`100µs`, `500µs`, `2ms`, `10ms`, `50ms`).
- **Top OOM-Killed Containers**: Real-time leaderboard ranking containers experiencing kernel Out-of-Memory killer terminations.
- **Top Log Events by Container**: Leaderboard ranking containers generating the highest volume of log messages.

### Page 2: Unified Container Inspector (Drill-Down)
- **Target Container Executions**: Live stream of commands executed within an investigated container.
- **Target Container Logs**: Live stdout/stderr diagnostics stream for an investigated container.
- **Target Container Network**: Outbound and inbound network connections for an investigated container.

### Page 3: Container Resource & Block I/O Saturation
- **Top CPU Consuming Containers**: Instantaneous CPU utilization (`CPU %`) leaderboard.
- **Top Memory Consuming Containers**: Memory resident set size (`RSS Bytes`) leaderboard.
- **Top Network Throughput Containers**: Transmitted network throughput (`TX B/s`) leaderboard.
- **Top Disk I/O Throughput Containers**: Block I/O read throughput (`Read B/s`) leaderboard.
- **Block I/O Disk Operations Stream**: Real-time block storage read/write requests.

### Page 4: Process Execution & Lifecycle Audit
- **Container Process Hierarchy Tree**: Interactive process execution tree showing parent-child relationships (`PID` $\to$ `PPID`) within containers. Configured with `views: ["tree"]` to maximize hierarchy width.
- **Container Process Crash & Failure Stream**: Real-time audit of non-zero process exits (`exit_code != 0`), script failures, and fatal termination signals.
- **Container Lifecycle Audit Log**: Chronological audit log of container creation and termination events.

### Page 5: Network Topology & Flow Analysis
- **Global Inter-Container Connection Stream**: Real-time stream of all inter-container network flows.
- **Top Network Destinations**: Heaviest communication links grouped by target destination IP.

---

## 5. Tactical Incident Workflows & CLI Usage

### 1. Interactive Terminal TUI Triage
```bash
# Launch container diagnostics in the interactive terminal TUI
sudo eprobe run app/docker-monitor

# Isolate diagnostics to a specific container process PID
sudo eprobe run app/docker-monitor --pid 14208

# Filter network events to a specific port (e.g. 80, 443, 3306)
sudo eprobe run app/docker-monitor --port 3306
```

### 2. Collaborative Browser Diagnostic View
```bash
# Extract telemetry to browser-based collaborative diagnostic view
sudo eprobe run app/docker-monitor --stream-token <UUID>
```

### 3. Air-Gapped BYO-LLM Root Cause Analysis
During an active triage session in the Web Inspector, click **`Offline AI Bundle`** in the top navigation bar to generate a client-side sanitized `.zip` archive containing `00_PROMPT_COPY_PASTE.md` and `01_EXECUTIVE_SUMMARY.md`. Paste into private Claude/ChatGPT/Ollama to analyze OOM crashes and container resource contention without data leaks.
