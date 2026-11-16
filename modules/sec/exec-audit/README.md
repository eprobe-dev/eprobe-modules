# sec/exec-audit: Process Execution Forensics & Privilege Escalation Triage

The **`sec/exec-audit`** module is an ephemeral, tactical eBPF incident response utility engineered for Linux security forensics and runtime process auditing. It intercepts process creation (`execve` / `execveat`), full command-line arguments, root privilege escalations, parent-child process lineages, and container namespaces with zero application overhead and zero daemon bloat.

---

## 1. Tactical Incident Scope & Target Personas

* **Target Roles**: Security Incident Responders, Site Reliability Engineers (SREs), and L3 Escalation Teams.
* **Target Scenarios**:
  - **The Silent Intrusion**: Suspicious binary execution or unexpected sub-shell spawns within production containers or host instances. Traditional `auditd` logging imposes severe performance overhead, while `top` misses short-lived ephemeral processes (`<100ms`).
  - **Privilege Escalation Forensics**: Operators or attackers executing commands through `sudo` or setuid binaries; `exec-audit` captures the authentic `loginuid` to identify the original user behind the escalation.
  - **Obfuscated Argument Inspection**: Capturing interactive subcommands (`bash -c "..."`, `curl | sh`, Python one-liners) rather than merely recording static binary basenames.
* **Overhead Profile**: Bypasses the 512-byte eBPF stack limit by reserving directly in a 16MB ring buffer (`bpf_ringbuf_reserve`), executing bounded scalar loops with `<1%` CPU utilization. Clean detach with `Ctrl+C` leaves zero host sidecars or background agents behind.

---

## 2. Key Technical Capabilities

### 1. Dual-Syscall Execution Trapping (`execve` & `execveat`)
- Hooks both `tracepoint/syscalls/sys_enter_execve` and `tracepoint/syscalls/sys_enter_execveat`.
- Guarantees 100% execution coverage across modern Linux systems where glibc, systemd, and container runtimes (runc, crun) invoke `execveat(dirfd, pathname, argv, envp, flags)`.

### 2. Full Command-Line Argument Capture (`args`)
- Extracts up to 256 bytes of command-line arguments directly from user-space `argv` pointers with zero pointer arithmetic passed to BPF helpers.
- Unveils obfuscated commands, interactive shell invocations (`sh -c "..."`), script arguments, and CLI options rather than only the static binary filename.

### 3. Security Context & Privilege Escalation Tracking
- **Audit Login UID (`loginuid`)**: Extracts `task->loginuid.val` via BPF CO-RE to identify the authentic original user who logged in via SSH or console, tracking identity through `sudo` or `su` sessions.
- **Privilege Severity Classification**: Automatically assigns `level: WARN` for root/privileged executions (`uid == 0`) and `level: INFO` for standard user operations, feeding the Universal Anomaly Engine.

### 4. In-Kernel Container Namespace Resolution
- Implements an in-kernel short container ID extractor (`parse_container_id`) across Docker, containerd, CRI-O, and Podman cgroups.
- Emits standard 12-character hex hashes tagged with `format: container_id`, enabling dynamic resolution into human-readable container name badges across Web Inspector and Terminal TUI without kernel string bloat.
- Non-containerized executions are automatically tagged as `"host"`.

### 5. Verifier Optimization & Stack Safety
- Directly reserves memory on the 16MB ring buffer (`bpf_ringbuf_reserve`), bypassing the restricted 512-byte eBPF stack limit.
- Employs fixed-size argument buffers, unroll-disabled bounded loops, and mathematical bitmask clamping (`& 0xFF`, `& 0x7F`) to guarantee linear instruction evaluation and zero verifier state explosions.

---

## 3. Exported Telemetry Maps & Schemas

| Map Name | Type | Key / Value Struct | Description |
| :--- | :--- | :--- | :--- |
| **`events`** | `ringbuf` (16 MB) | `struct event_t` | Real-time stream of process execution events containing PID, PPID, UID, Login UID, Comm, Container ID, Filename, Arguments, and Severity Level. |

### Event Schema (`struct event_t`)

| Field | Type | Length | Format / Role | Description |
| :--- | :--- | :--- | :--- | :--- |
| `pid` | `uint32` | 4 | Entity (`node_id`) | Process Identifier |
| `ppid` | `uint32` | 4 | Entity (`parent_id`) | Parent Process Identifier |
| `uid` | `uint32` | 4 | Security | Real User Identifier |
| `loginuid` | `uint32` | 4 | Security | Audit Login User Identifier (pre-sudo identity) |
| `comm` | `string` | 16 | Entity | Command name / binary basename |
| `container_id` | `string` | 16 | `container_id` | 12-char hex container ID or `"host"` |
| `filename` | `string` | 256 | Path | Path to executable file |
| `args` | `string` | 256 | Payload | Executed command-line arguments |
| `level` | `string` | 8 | Anomaly Token | Severity classification (`WARN` / `INFO`) |

---

## 4. Multi-Page Diagnostic Views & Inspector Panes

### Page 1: Process Lineage & Execution Velocity
- **Execution Tree (60% × 60%)**: Interactive hierarchical process tree (`PID -> PPID`) showing full process lineage. Configured with `views: ["tree"]` to dedicate 100% width to the process tree and suppress irrelevant APM waterfall tabs. Navigate with `Up`/`Down`, expand/collapse with `Left`/`Right`, and press `Enter` to inspect.
- **Top Executed Binaries (40% × 60%)**: Real-time leaderboard aggregating executions by binary command name (`comm`).
- **Execution Frequency (100% × 40%)**: Continuous sparkline graph rendering process creations per second (`unit: qps`) over a rolling 60-second window.

### Page 2: Live Process Execution Stream
- **Exec Events Stream (100% × 100%)**: Full-width virtualized stream table displaying execution events with microsecond timestamps, PIDs, PPIDs, UIDs, Login UIDs, Comm, Container Badges, and Full Arguments.
- **Interactive Search (`/`)**: Dynamically filter live events by typing `/` across `comm`, `filename`, `args`, or `container_id`.
- **Payload Inspection (`Enter`)**: Pressing `Enter` on any row opens the full-screen Inspector Modal displaying complete command-line arguments, security credentials, and process metadata.

---

## 5. Tactical Incident Workflows & CLI Usage

### 1. Interactive Terminal TUI Forensics
```bash
# Launch real-time process execution forensics on the local host
sudo eprobe run sec/exec-audit

# Filter execution events for a specific target process PID
sudo eprobe run sec/exec-audit --pid 4092
```

### 2. Collaborative Browser Diagnostic View
```bash
# Extract live telemetry to the browser-based collaborative diagnostic view
sudo eprobe run sec/exec-audit --stream-token <UUID>
```

### 3. Air-Gapped BYO-LLM Root Cause Analysis
During an active security investigation, click **`Offline AI Bundle`** in the Web Inspector top navigation bar to generate an air-gapped, sanitized `.zip` archive containing `00_PROMPT_COPY_PASTE.md` and `01_EXECUTIVE_SUMMARY.md`. Paste into private Claude/ChatGPT/Ollama to analyze execution trees and privilege escalation vectors with zero cloud data leaks.

### 4. Non-Interactive NDJSON Forwarding
```bash
# Export structured NDJSON to SIEM or log triage pipelines
sudo eprobe run sec/exec-audit -output json
```
