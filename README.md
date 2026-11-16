# eprobe Diagnostic Modules & Packaging Pipeline (`eprobe-pack`)

This repository contains the open-source CO-RE eBPF **Diagnostic Modules** (`modules/**/*.c` + `manifest.yaml`) and the `eprobe-pack` build/packaging toolchain for [`eprobe`](https://github.com/eprobe-dev/eprobe), the on-demand Linux incident and security diagnostics toolkit.

### Dual Licensing Model
* **eBPF Kernel Probes (`modules/**/*.c`, `include/bpf/eprobe_*.h`)**: Dual-licensed under **`GPL-2.0-only OR MIT`** (`SPDX-License-Identifier: GPL-2.0-only OR MIT`, `SEC("license") = "Dual MIT/GPL"`) — see [LICENSE-BPF](LICENSE-BPF).
* **Packager, Build Tooling & Schemas (`cmd/eprobe-pack/`, `Makefile`, `manifest.yaml`)**: Licensed under the **Apache License 2.0** — see [LICENSE](LICENSE).

---

## Included Open-Source Diagnostic Modules (8 Probes)

| Domain | Module | Description |
| :--- | :--- | :--- |
| **`perf/`** | `perf/stall-tracer` | Off-CPU scheduler stalls, D-state storage sleep, runqueue delay & futex contention |
| **`sys/`** | `sys/syscall-xray` | Production-safe `strace` alternative: failing/slow syscalls (`openat`, `connect`, `raw_tracepoint/sys_*`) |
| **`app/`** | `app/docker-monitor` | Container CPU %, memory RSS, OOM kills, cgroup lifecycle, block I/O & network latency |
| **`app/`** | `app/http-tracer` | HTTP/1.1 latency, microsecond TTFB, virtual hosts, W3C trace spans & 5xx cascades |
| **`app/`** | `app/mysql-monitor` | MySQL/MariaDB query latencies, 512B SQL capture, deadlocks (1213/1205) & InnoDB I/O |
| **`app/`** | `app/universal-tls-sniffer` | Plaintext HTTPS/HTTP2 decryption via OpenSSL uprobes with SNI host resolution |
| **`sec/`** | `sec/exec-audit` | Process execution forensics, 256B args, parent-child lineage & `loginuid` tracking |
| **`log/`** | `log/stderr-capture` | Kernel-level capture of `stderr` (`fd == 2`) `write`/`writev` error streams |

---

## 1. Core Architecture & Incident Response Doctrine

`eprobe` is an **open-source, on-demand Linux incident and security diagnostic tool** built for **Site Reliability Engineers (SREs), L3 Escalation Engineers, and Platform DevOps**:
- **Collect** system, application, and security signals in one click (no 24/7 background agent).
- **Analyze** real-time incident data locally (`eprobe` Text Console) or online (`eprobe.io` Web Console) in a **Single Pane of Glass**.
- **Export** an **Anonymized AI Bundle** (IPs & secrets masked) for root-cause evaluation with **Claude, ChatGPT, Gemini & Ollama**.

Standard monitoring platforms (Datadog, Grafana) alert when a production system is failing, but rarely show the kernel-level root cause. Legacy diagnostic tools (`strace`, `tcpdump`, `top`) are fragmented, risky to run under production load (`strace` imposes a 100x overhead penalty), or produce high-volume packet dumps disconnected from container contexts.

Every **Diagnostic Module** authored in this repository adheres to the **Three Core Pillars**:
1. **On-Demand & Zero Agents Left Behind**: Single static binary (`<25MB`), read-only CO-RE eBPF injection (compatible across Linux kernels `5.8` through `7.0+` including Proxmox VE 9.2 `7.0.14-25-pve`), self-exclusion (`is_eprobe_comm()`) to prevent feedback loops, zero sidecars or background daemons, and immediate clean detach on `Ctrl+C`.
2. **Single Pane of Glass Correlation**: Direct in-kernel correlation of CPU & thread locks, system security & audit, disk I/O, network/TLS traffic, and Docker/MySQL apps to PIDs/TIDs with `<1%` CPU overhead.
3. **Anonymized AI Bundle Ready**: Declarative schemas feed client-side sanitized `.zip` bundle generation (`00_PROMPT_COPY_PASTE.md` and `01_EXECUTIVE_SUMMARY.md`) with IPs and secrets masked for **Claude, ChatGPT, Gemini & Ollama**.

---

## 2. 📁 Directory & File Conventions

All module sources reside inside the `modules/` directory structured by category and module name:
```
modules/
└── <category>/
    └── <module-name>/
        ├── manifest.yaml
        └── <matching_source>.c
```

### Naming Conventions
- **Module Category**: The domain namespace (e.g., `perf` for performance, `app` for applications, `sec` for security, `log` for error sinks).
- **Module Directory Name**: Lowercase words separated by hyphens (e.g., `stall-tracer`, `docker-monitor`, `exec-audit`).
- **Source File Name**: Resolved dynamically by replacing all hyphens (`-`) in the directory base name with underscores (`_`) and appending `.c` (e.g., `stall_tracer.c`, `docker_monitor.c`, `exec_audit.c`).
- **Manifest File**: Must be named exactly `manifest.yaml`.
- **Output Package**: Saved in the output directory as `<category>-<module-name>.epm` (e.g., `perf-stall-tracer.epm`, `app-docker-monitor.epm`).

---

## 3. 📝 Manifest Schema (`manifest.yaml`)

Every module directory must contain a `manifest.yaml` using the following dynamic schema:
```yaml
name: <category>/<module-name>   # String, e.g., perf/stall-tracer
version: <semantic-version>      # String, e.g., 1.0.0
author: <author-name>            # String
sha256: <bytecode-sha256-hex>   # Calculated and dynamically updated by eprobe-pack
description: <desc-string>       # Actionable mission statement of the module's diagnostic scope
attach_points:                   # Sequence of hooks executed by the runtime loader
  - type: <tracepoint|raw_tracepoint|kprobe|uprobe|uretprobe>
    symbol: <kernel-symbol>      # Kernel symbol to hook (e.g., sched_switch or sys_enter_execve)
    section: <elf-sec-name>      # ELF section name (e.g., raw_trace_sched_switch)
maps:                            # Map definitions matching BPF map declarations
  - name: <map-name>             # e.g., stall_events, proc_stall_stats
    type: <ringbuf|hash>         # ringbuf for event capture, hash for continuous stateful metrics
    # --- Ringbuf-only fields ---
    event_struct: <c-type-name>  # Layout specification for user-space decoding
    event_schema:                # Offset spec for dynamic parsing
      - name: <field-json-key>
        type: <uint8|uint16|uint32|uint64|string|ipv4|ipv6>
        [length]: <bytes-count>  # Required for string type
        [format]: <port|ip|hex|container_id>  # Optional format helper
    # --- Hash-only fields (for in-kernel aggregation maps) ---
    key_struct: <c-type-name>    # Key struct name matching C definition
    key_schema:
      - name: <field-name>
        type: <uint8|uint16|uint32|uint64|string>
        [length]: <bytes-count>
        [format]: <port|ip|hex|container_id>
    value_struct: <c-type-name>  # Value struct name matching C definition
    value_schema:
      - name: <field-name>
        type: <uint8|uint16|uint32|uint64>
variables:                       # (Optional) Configuration variables
  - name: <bpf-var-name>         # Variable name in C
    type: <uint8|uint16|uint32|uint64>
    cli_flag: <flag-name>        # CLI parameter mapping
    description: <help-text>
tui_hints:                       # Multi-Page Diagnostic Presentation Layout
  pages:                         # Array of diagnostic view pages
    - name: <page-name>          # e.g., "System Off-CPU & Stall Overview"
      layout: <grid|flex>        # Layout engine mode
      panes:                     # Array of simultaneous inspector sectors within this page
        - name: <pane-name>      # e.g., proc_stall_stats
          type: <stream|top|histogram|sparkline|tree> # Inspector rendering type
          map_name: <map-name>   # Binds pane to a ringbuf or hash map
          position:              # Grid coordinates
            row: <int>
            col: <int>
            width: <percentage>  # e.g., "50%" or "100%"
            height: <percentage> # e.g., "50%" or "100%"
          summary: <help-text>   # Legend description for this pane
          inspect_payload: <field-name|raw|*> # Field to inspect on 'Enter'
          searchable_fields: [<field1>, <field2>] # Fields substring-searched when user presses `/`
          version_field: <field-name> # Software/product version field (e.g., server_version)
          proto_field: <field-name>   # Protocol/dialect field (e.g., proto, dialect)
          request_payload_field: <field-name> # Request/Input payload field (e.g., query, req_payload)
          response_payload_field: <field-name> # Response/Output payload field (e.g., resp_payload)
          columns:               # For `stream` pane type
            - field: <field-name>
              width: <chars-width>
              [bold]: <boolean>
              [color]: <hex-color-code>
          aggregate_by:          # For `top` pane type
            - field: <field-name>
              label: <tab-label-text>
              type: <count|value|delta_rate> # count = event accumulation, value = gauge, delta_rate = rate
              [value_field]: <field-name>
          # Histogram configuration (`type: histogram`)
          [histogram_field]: <numerical-field-name> # e.g., duration_us, latency_us
          [buckets]: [<b1>, <b2>, ...] # Explicit bucket thresholds
          [unit]: <unit-str>     # e.g., ms, us, bytes, %, qps
          # Sparkline configuration (`type: sparkline`)
          [metric_field]: <field-name|count>
          [aggregation]: <rate|avg|max|sum>
          [time_window_sec]: <int> # Rolling time window size in seconds (default: 60)
          # Trace Tree configuration (`type: tree`)
          [node_id]: <field-name> # Node ID key (e.g. pid, tid, req_id)
          [parent_id]: <field-name> # Parent ID key (e.g. ppid, parent_req_id)
          [label_fields]: [<f1>, <f2>] # Fields composing tree node title
          [badge_field]: <field-name>
          [token_field]: <field-name>
          [status_field]: <field-name>
          [duration_field]: <field-name>
          [views]: ["tree", "graph", "timeline"] # Supported trace view modes
```

---

## 4. 🧠 Manifest Authoring Best Practices for Diagnostic Modules & Anonymized AI Bundles

The `manifest.yaml` is the **declarative contract** consumed by the CLI terminal TUI, the Web Inspector (`eprobe-saas`), and the **Universal AI Prompt Synthesizer**. The AI bundle compiler reads the manifest schema to generate targeted LLM diagnostic prompts (`00_PROMPT_COPY_PASTE.md`) and statistical profiles (`01_EXECUTIVE_SUMMARY.md`).

To ensure the highest fidelity incident triage and automated root-cause analysis, module authors must follow these standards:

### 1. Operational Mission Statement in `description`
- **Rule**: `description` must declare the target application/daemon, primary performance metrics, and fault-detection scope. Avoid generic labels like `"Process auditor"` or `"App troubleshooter"`.
- **Why**: The AI Prompt Synthesizer extracts `manifest.description` directly into the LLM **System Role & Objective**, establishing domain-specific diagnostic personas (e.g., DBA, Web Architect, Security Incident Responder).
- **Good Example**:
  ```yaml
  description: "High-resolution off-CPU and scheduler stall diagnostics: microsecond D-state storage sleep, futex mutex contention, runnable queue starvation, and thread pool bottle-necking"
  ```

### 2. Architectural Subsystems as Pages (`tui_hints.pages[].name`)
- **Rule**: Group diagnostic view pages into logical architectural tiers rather than generic tab names (avoid `"Page 1"`, `"Overview"`).
  - *Tier 1 (Health & Throughput)*: Ingress event rates, RED metrics, latency histograms (e.g. `"System Off-CPU & Scheduler Overview"`).
  - *Tier 2 (Active Incident Stream)*: Chronological incident logs, query streams, trace trees (e.g. `"Live SQL Statement Stream & Query Inspector"`).
  - *Tier 3 (Contention, Locks & Errors)*: Deadlocks, futex contention, 5xx cascades (e.g. `"Mutex & Futex Contention Triage"`).
  - *Tier 4 (Storage, Resources & Deep Hierarchy)*: Block I/O, memory reclaim, worker thread CPU utilization (e.g. `"Thread Pool Diagnostic Tree & Trace Hierarchy"`).
- **Why**: The AI synthesizer partitions telemetry into distinct **subsystem diagnostic chapters** named directly after each page.

### 3. Explicit Metric Units & Schema Suffixes
- **Rule**:
  1. Always declare `unit:` on histogram and sparkline panes (`unit: us`, `unit: ms`, `unit: bytes`, `unit: %`, `unit: qps`, `unit: s/s`).
  2. Suffix numerical schema fields with explicit unit tags: `_us`, `_ms`, `_ns`, `_bytes` (e.g., `duration_us`, `runq_latency_us`, `cpu_time_ns`, `rx_bytes`).
- **Why**: Prevents unscaled integer confusion in LLM prompts. The compiler automatically computes scaled percentiles (p50, p95, p99) and converts nanoseconds/bytes into human-readable engineering units.

### 4. Strict Entity vs. Metric Separation (`format: ip`, `format: port`)
- **Rule**:
  - Annotate network address fields (`saddr`, `daddr`, `source`, `destination`) with `format: ip`.
  - Annotate port fields (`sport`, `dport`) with `format: port`.
  - Name entity keys with standard suffixes: `*_id` (`container_id`, `req_id`), `pid`, `ppid`, `comm`.
- **Why**: The AI engine uses these annotations to classify fields into **Entities / Talkers** (evaluating unique cardinality and top talkers) vs. **Continuous Metrics** (calculating distribution percentiles). Ports and IPs are never misclassified as arithmetic quantities.

### 5. Standardized Severity Tokens & Status Codes
- **Rule**:
  - For log/event streams: use field `level` with uppercase standard tokens (`FATAL`, `CRITICAL`, `ERROR`, `WARN`, `INFO`, `DEBUG`).
  - For request/command streams: use `status_code` (e.g. HTTP `500`, `404`) or `error_code` (e.g. MySQL `1213` Deadlock, `1205` Timeout) or `exit_code` / `ret`.
- **Why**: Feeds the **Universal Anomaly Engine** to automatically extract critical incidents and generate focused diagnostic questions for the LLM.

### 6. Deep Payloads & Protocol Negotiation Fields
- **Rule**:
  - When an inspector pane displays request/response data, declare `request_payload_field` and `response_payload_field`.
  - When tracing daemons with protocol negotiation, declare `version_field` (e.g. `server_version`) and `proto_field` (e.g. `proto`).
  - For SQL, command, or message streams, set `inspect_payload: query` (or `payload` / `message`).
- **Why**: Powers the Web Inspector's side-by-side payload viewer, syntax-highlighted statement viewers, and runtime version chips.

### 7. Universal Entity Resolution Contract (`format: container_id`)
- **Rule**:
  - eBPF kernel probes should emit compact 12-byte hex hash strings (`container_id`) or truncated 64-char hashes extracted from cgroup paths, NEVER variable-length container string names inside ringbuf streams.
  - In `manifest.yaml`, annotate container identifier fields with `format: container_id`.
- **Why**: Keeps eBPF kernel memory overhead minimal and prevents verifier instruction explosion. The collector (`eprobe-cli`) discovers container names once via Docker/containerd/cgroup sockets and transmits them in `host.containers`. The presentation layers (`eprobe-saas` and `eprobe-cli`) resolve container hashes dynamically across all 5 visual primitives (Leaderboards, Stream Tables, Process Trees, Topology Graphs, Inspect Modals).

### 8. Process Tree vs. Distributed Trace Waterfall Guidelines (`type: tree`)
- **Rule**:
  1. For **Process Execution Trees** (`PID -> PPID`, e.g. `sec/exec-audit`, `app/docker-monitor`):
     - Declare `views: ["tree"]`.
     - Omit `duration_field` (or leave undefined). The Web Inspector automatically dedicates 100% of the pane width to the full command-line hierarchy and suppresses the empty `0ms` Gantt waterfall column and irrelevant web DAG tabs.
  2. For **Distributed Request Tracing** (`req_id -> parent_req_id`, e.g. `app/http-tracer`):
     - Declare `views: ["tree", "graph", "timeline"]`.
     - Always declare `duration_field` (e.g. `duration_us`, `latency_us`) and `status_field` (`status_code`). This automatically activates the synchronized 58% / 42% Gantt waterfall timeline, latency chips, warning indicators, and the Service DAG dependency view.
- **Why**: Keeps system audit modules focused on clean process ancestry without non-functional web DAG tabs, while providing full APM capabilities for distributed network and microservice modules.

---

## 5. 🛠️ Compilation & Packaging Tool (`eprobe-pack`)

`eprobe-pack` is a Go utility designed for targeting a specific module and automating its compilation, hashing, signing, and packaging.

### Command Line Interface & Flags
```bash
./eprobe-pack --dir <module-path> [--output-dir <output-path>] [--unsigned]
```
- **`--dir`** (Required): Path to the target subdirectory containing the raw C files and `manifest.yaml` (e.g., `--dir modules/perf/stall-tracer`).
- **`--output-dir`** (Optional): Path to the directory where the compiled `.epm` package is saved (default: `./dist`).
- **`--unsigned`** (Optional): Compile and pack `.epm` locally (`manifest.yaml` + `program.o` with updated `sha256`) without requiring `EPROBE_SIGNING_KEY` or generating `manifest.sig`. Run locally with `sudo eprobe run --module-file ./dist/<module>.epm`.

### Compilation Process
1. **Verification**: Checks that `--dir` exists, contains `manifest.yaml`, and resides strictly within the workspace boundaries.
2. **Subprocess Compilation**: Invokes `clang` as a subprocess to compile the `.c` file to a relocatable BPF target `program.o` inside a temporary build workspace:
   ```bash
   clang -target bpf -O2 -g -Wall -Iinclude -D__TARGET_ARCH_x86 -c <src.c> -o <temp_program.o>
   ```
3. **Checksum Calculation**: Computes the SHA256 checksum of the compiled `program.o` object.
4. **Manifest Update**: Dynamically updates (or inserts) the `sha256:` field in both the local source `manifest.yaml` and the packaged manifest.
5. **Cryptographic Signing**:
   - Reads the private key from the `EPROBE_SIGNING_KEY` environment variable. The key can be either a **32-byte seed** (64 hex characters) or a **64-byte private key** (128 hex characters). If a 32-byte seed is provided, it is dynamically expanded to 64 bytes using `ed25519.NewKeyFromSeed()`.
   - Signs the exact byte contents of the updated `manifest.yaml` using Ed25519.
   - Outputs the signature to `manifest.sig` in the package workspace.
6. **Archive Packaging**: Bundles the following files into a gzip-compressed tarball named `<category>-<module-name>.epm` in the output directory:
   - `manifest.yaml`
   - `manifest.sig`
   - `program.o`

---

## 6. ⚙️ Unified Gitea CI/CD Pipeline & Secrets

The repository uses a unified continuous integration and deployment pipeline (Gitea Actions) that builds, tests, syncs sanitized open-source modules, and uploads signed packages:

### Workflow Execution Stages:
1. **Lint and Test (All Push/Tag events)**:
   - Installs compiler dependencies (`clang`, `llvm`, `make`, `gcc-multilib`, and standard `asm/` include links).
   - Builds the `eprobe-pack` tool.
   - Runs Go unit tests (`go test -v ./...`) to dynamically walk the `modules/` directory, compile all diagnostic BPF modules, and verify cryptographic signatures and hashes.
2. **Dynamic Packaging & Delivery (Only on pushes to `main` or release tags `v*`)**:
   - Executes automatically only if the test stage passes.
   - Scans the `modules/` directory to discover and package all modules dynamically.
   - Uploads all generated `.epm` packages to the remote `eprobe-registry` server via a `multipart/form-data` POST request.

### Required Gitea Secrets & Variables
- **`EPROBE_SIGNING_KEY`** (Secret): The production Ed25519 key used to sign manifests.
- **`AUTHTOKEN`** (Secret): Bearer write authorization token for the remote `eprobe-registry` server.
- **`vars.REGISTRY_URL`** (Variable): The base URL of the remote `eprobe-registry`.

---

## 7. 💻 Local Development & Testing

### 1. Build the Packaging Tool
```bash
make build
```
This compiles the binary locally as `eprobe-pack`.

### 2. Test the Tool and Modules
```bash
go test -v ./...
```
*Note: Unit tests dynamically search, compile, package, and cryptographically verify all modules in the repository.*

### 3. Build Unsigned Packages Offline (No Private Key Required)
Anyone cloning this repository can compile all 8 eBPF modules locally into `./dist/*.epm` and verify them offline using `eprobe --module-file`:
```bash
make build-unsigned
sudo eprobe run --module-file ./dist/sys-syscall-xray.epm --pid <PID>
```

### 4. Generate Signed Packages Locally
```bash
make registry-data
```
Dynamically scans `modules/`, compiles all modules, signs them using `EPROBE_SIGNING_KEY`, and outputs packages to `./registry-data/`.

Alternatively, compile a single target module directly:
```bash
EPROBE_SIGNING_KEY=<key> ./eprobe-pack --dir modules/perf/stall-tracer --output-dir dist
```

See the companion CLI & kernel loader repository at [github.com/eprobe-dev/eprobe](https://github.com/eprobe-dev/eprobe).
