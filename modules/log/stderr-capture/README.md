# log/stderr-capture: Standard Error Forensics & Crash Diagnostic Sink

The **`log/stderr-capture`** module is an ephemeral, tactical eBPF incident response utility engineered to intercept and isolate application crashes, unhandled exceptions, panic stack traces, and daemon diagnostic errors. By hooking file descriptor 2 (`fd == 2`) directly at the Linux kernel boundary across traditional writes (`write`) and vectorized writes (`writev`), it captures critical error events across bare-metal host daemons and container runtimes with zero sidecars and zero configuration changes.

---

## 1. Tactical Incident Scope & Target Personas

* **Target Roles**: Site Reliability Engineers (SREs), Incident Escalation Engineers, and DevOps Operators.
* **Target Workloads**: Host system daemons (systemd units, databases, web proxies) and containerized workloads (Docker, containerd, Kubernetes).
* **Core Incident Scenarios**:
  - **Silent Application Crashes**: A containerized application panics and dies immediately. Standard log aggregation agents fail to ship the crash dump before the container cgroup is destroyed; `stderr-capture` catches the panic bytes at the kernel boundary in real time.
  - **Diagnostic Signal-to-Noise Isolation**: Production logs contain millions of debug/info stdout lines, burying fatal stack traces. `stderr-capture` acts as a pure error sink, strictly isolating file descriptor 2 output.
* **Overhead Profile**: Direct memory reservation in a 16MB ring buffer (`bpf_ringbuf_reserve`) eliminates stack limitations. Bitwise bounds masking (`count &= 0x1FF`) guarantees verifier safety with `<1%` CPU utilization. Clean detach with `Ctrl+C` leaves zero host sidecars or background agents behind.

---

## 2. Key Technical Capabilities

### 1. Dual-Syscall Stderr Capture (`write` & `writev`)
- Intercepts both `sys_enter_write` and `sys_enter_writev` filtered specifically to file descriptor 2 (`fd == 2`).
- Provides native coverage for modern compiled and interpreted languages (Rust `tracing`, Go `log`, Node.js `process.stderr`, Python `sys.stderr`, JVM) that emit structured stderr logs via vectorized `iovec` memory buffers.

### 2. Intelligent Severity Classification & Anomaly Tokens
- Dynamically scans message payloads for standard severity tokens (`FATAL`, `CRITICAL`, `ERROR`, `WARN`, `INFO`), categorizing outputs to feed the Universal Anomaly Engine.
- Classifies genuine fatal errors appropriately while allowing non-fatal warning messages on stderr to render distinct severity badges.

### 3. Noise & Fragment Elimination
- In-kernel heuristic filtering (`is_noise_fragment`) discards non-error writes under 16 bytes (including 1-byte curl progress meter updates, 6-byte FastCGI/PHP-FPM socket control pings, 8-9 byte bracketed paste escape sequences, and terminal clearing codes) unless they explicitly contain recognized error tokens (`FATAL`, `ERROR`, `WARN`).
- Real multiline error traces, exceptions, and CLI diagnostics ($\ge 16$ bytes) pass through uninhibited with full payload inspection.

### 4. Universal Container ID Resolution
- Identifies container execution context by scanning cgroup namespaces across Docker, containerd, CRI-O, and Podman.
- Emits standard 12-character hex hashes tagged with `format: container_id`, enabling instant container pill resolution across Web Inspector and Terminal TUI dashboards while transparently labeling host daemons as `"host"`.

### 5. Verifier Safety & Direct Ring Buffer Memory Reservation
- Reserves event memory directly within the 16MB ring buffer (`bpf_ringbuf_reserve`), bypassing restricted 512-byte eBPF stack limits.
- Enforces strict bitwise bounds masking (`count &= 0x1FF`, `read_size &= 0xFF`) to prevent negative scalar extensions and state explosions during kernel loading.

---

## 3. Exported Telemetry Maps & Schemas

| Map Name | Type | Key / Value Struct | Description |
| :--- | :--- | :--- | :--- |
| **`stderr_events`** | `ringbuf` (16 MB) | `struct stderr_event_t` | Real-time stream of intercepted stderr events with PID, Comm, Container ID, Severity Level, Byte Length, and Payload. |

### Event Schema (`struct stderr_event_t`)

| Field | Type | Length | Format / Role | Description |
| :--- | :--- | :--- | :--- | :--- |
| `pid` | `uint32` | 4 | Entity | Process Identifier |
| `uid` | `uint32` | 4 | Security | Real User Identifier |
| `comm` | `string` | 16 | Entity | Command name / binary basename |
| `container_id` | `string` | 16 | `container_id` | 12-char hex container ID or `"host"` |
| `level` | `string` | 8 | Anomaly Token | Classified Severity (`FATAL`, `CRITICAL`, `ERROR`, `WARN`, `INFO`) |
| `len` | `uint32` | 4 | Metric (`_bytes`) | Captured payload length in bytes |
| `trunc` | `uint32` | 4 | Flag | Truncation flag (1 if payload exceeded 255 bytes) |
| `payload` | `string` | 256 | Payload | Stderr message text (null-terminated) |

---

## 4. Multi-Page Diagnostic Views & Inspector Panes

### Page 1: Host & Container Error Analytics
- **Error Log Rate (50% × 50%)**: Continuous sparkline graph rendering stderr error event bursts per second (`unit: qps`) over a rolling 60-second window.
- **Error Output Length (50% × 50%)**: Histogram displaying payload length distribution (`unit: bytes`) across standard bucket thresholds (`[32, 128, 256, 512, 1024]`).
- **Top Error Binaries (50% × 50%)**: Real-time leaderboard ranking host processes producing the highest volume of stderr writes.
- **Top Error Containers (50% × 50%)**: Leaderboard aggregating error event frequency by container ID, instantly resolved into container name pills.

### Page 2: Live Stderr Forensic Console
- **Stderr Events Stream (100% × 100%)**: Full-width virtualized stream table displaying raw stderr messages with microsecond timestamps, PIDs, Command basenames, Container badges, and Severity indicators.
- **Interactive Search (`/`)**: Dynamically filter stderr lines by typing `/` across `comm`, `payload`, or `container_id`.
- **Payload Inspection (`Enter`)**: Pressing `Enter` on any row opens the full-screen Inspector Modal to examine multi-line stack traces or long error outputs.

---

## 5. Tactical Incident Workflows & CLI Usage

### 1. Interactive Terminal TUI Triage
```bash
# Capture system-wide stderr writes across host daemons and containers
sudo eprobe run log/stderr-capture

# Filter stderr capture to a specific process PID
sudo eprobe run log/stderr-capture --pid 14208
```

### 2. Collaborative Browser Diagnostic View
```bash
# Extract live telemetry to the browser-based collaborative diagnostic view
sudo eprobe run log/stderr-capture --stream-token <UUID>
```

### 3. Air-Gapped BYO-LLM Root Cause Analysis
During an active outage with application panics, open the Web Inspector and click **`Offline AI Bundle`** in the top navigation bar to generate an air-gapped, sanitized `.zip` archive containing `00_PROMPT_COPY_PASTE.md` and `01_EXECUTIVE_SUMMARY.md`. Paste into private Claude/ChatGPT/Ollama to analyze stack traces and panic reasons with zero data egress.
