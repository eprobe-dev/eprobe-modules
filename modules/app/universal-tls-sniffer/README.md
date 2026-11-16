# app/universal-tls-sniffer: Zero-Cert HTTPS & TLS Wire Diagnostics

The **`app/universal-tls-sniffer`** module is an ephemeral, tactical eBPF incident response utility engineered to diagnose encrypted HTTPS and HTTP/2 communication failures. By attaching dynamic user-space eBPF uprobes to system OpenSSL shared libraries (`libssl.so`), it captures and decrypts live application payloads in real time without setting up proxy servers (mitmproxy, Charles), installing custom CA root certificates, or altering application source code.

---

## 1. Tactical Incident Scope & Target Personas

* **Target Roles**: Site Reliability Engineers (SREs), Network Engineers, Security Incident Responders, and Backend Developers.
* **Target Runtimes**: Any Linux process utilizing OpenSSL 1.1 or 3.x for TLS encryption (`curl`, `python`, `node`, `nginx`, `ruby`, `php`, `envoy`).
* **Core Incident Scenarios**:
  - **The Encrypted Packet Dump Firehose**: `tcpdump` captures gigabytes of encrypted traffic, but cannot inspect HTTP status codes, request paths, or JSON payloads without decrypting session keys.
  - **Certificate Pinning Conflicts**: Installing corporate proxy certificates breaks applications enforcing strict certificate pinning or mTLS; `universal-tls-sniffer` captures payloads *after* local decryption inside user-space memory, bypassing certificate requirements completely.
  - **API Contract Failures**: Upstream payment gateways or microservices return unhandled errors; `universal-tls-sniffer` extracts side-by-side request and response bodies while automatically masking secret authentication headers.
* **Overhead Profile**: Dynamic uprobes hook `SSL_write` and `SSL_read` functions. Utilizes per-CPU scratch maps to stay within 512-byte stack limits, and bounds string scans with bitwise masking (`count &= 0x1FF`). Maintains `<1%` CPU utilization. Clean detach with `Ctrl+C` leaves zero host sidecars or background agents behind.

---

## 2. Key Technical Capabilities

### 1. Zero-Proxy, Zero-Certificate Plaintext Decryption
- **User-Space OpenSSL Interception**: Attaches non-invasive dynamic uprobes and uretprobes to system `libssl.so` functions (`SSL_write`, `SSL_write_ex`, `SSL_read`, `SSL_read_ex`).
- **Cryptographic Boundary Tapping**: Intercepts application buffers *immediately before* encryption on outbound transmission, and *immediately after* decryption on inbound reception.
- **Universal Multi-Distro Library Discovery**: Automatically resolves standard OpenSSL binary paths across Debian/Ubuntu (`/usr/lib/x86_64-linux-gnu/libssl.so.3`), RHEL/Rocky/Fedora (`/usr/lib64/libssl.so.3`), and Alpine (`/lib/libssl.so.3`), with custom path overrides via `--libssl <path>`.

### 2. Full-Duplex Request & Response Correlation
- **Bidirectional In-Flight Matching**: Matches outbound HTTP requests with incoming server responses across thread and process boundaries using in-kernel tracking maps (`inflight_reqs` and `active_reads`).
- **TTFB & Round-Trip Latency**: Measures precise Time To First Byte (TTFB) and total server processing latency in microseconds (`duration_us`).
- **Dual Payload Inspection**: Emits both the original client request payload (`req_payload`, up to 256 bytes) and server response body (`resp_payload`, up to 256 bytes) side-by-side in a single correlated event record.

### 3. Credential Sanitization by Default
- **Automatic Secret Masking**: Enabled by default to protect credentials, masking `Bearer <token>`, `Basic <token>`, API keys (`api_key=...`, `key=...`), and authorization headers with `Bearer **********`.
- **Operator Opt-Out (`--no-sanitize`)**: Can be disabled when explicit authentication header debugging is required during an authorized investigation.

### 4. Zero-Loop Single-Pass HTTP/1.1 & Native HTTP/2 Parsing
- **HTTP/1.1 Protocol Classification**: Decodes HTTP/1.1 request lines (`GET /endpoint HTTP/1.1`), `Host:` headers, and HTTP response status codes (`200 OK`, `404 Not Found`, `500 Server Error`).
- **Native HTTP/2 (RFC 7540) Frame Engine**: Automatically detects binary HTTP/2 client connection prefaces (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`), HEADERS frames (`type == 0x01`), and DATA frames (`type == 0x00`) without forcing clients to fallback to `--http1.1`.
- **RFC 7541 Static Table Zero-Loop Extraction**: Directly maps single-byte static HPACK indices (`0x82` -> `GET`, `0x83` -> `POST`, `0x88` -> `200`, `0x8D` -> `404`, `0x8E` -> `500`) and extracts `:authority` / `host` pseudo-headers without dynamic HPACK decompression state bloat.
- **Role Detection**: Classifies traffic as `client` (outbound API calls from `curl`, `node`, `python`) or `server` (inbound requests handled by local daemons).

### 5. OpenSSL 3.x Native Re-entrancy & ABI Defense
- **Dual Symbol Compatibility**: Full support for both classic OpenSSL (`SSL_read`, `SSL_write`) and OpenSSL 3.x extended APIs (`SSL_read_ex`, `SSL_write_ex`).
- **In-Kernel Re-entrancy Suppression**: OpenSSL 3.x implements legacy `SSL_write` and `SSL_read` as wrappers around `SSL_write_ex` and `SSL_read_ex`. Dedicated kernel tracking maps (`active_writes` and `active_reads.in_read`) suppress recursive nested calls, eliminating duplicate event emission and inflated leaderboard metrics.
- **ABI Pointer Dereferencing**: Recognizes that `SSL_read_ex` returns a boolean success status (`rax = 1`) while the actual received byte length resides in a user-space pointer passed in argument 4 (`PT_REGS_PARM4`). The kernel probe dereferences `*readbytes` via `bpf_probe_read_user` to preserve exact frame length.

---

## 3. Exported Telemetry Maps & Schemas

| Map Name | Type | Key / Value Struct | Description |
| :--- | :--- | :--- | :--- |
| **`tls_events`** | `ringbuf` (16 MB) | `struct tls_event_t` | Stream of decrypted HTTP/HTTPS transactions with PID, PPID, comm, container ID, role, method, path, host, status code, latency, and full request/response payloads. |
| **`host_stats`** | `hash` (1024 entries) | `struct host_key_t` $\to$ `struct host_stat_t` | In-kernel request volume statistics aggregated by remote destination API domain or SNI. |
| **`status_stats`** | `hash` (128 entries) | `struct status_key_t` $\to$ `struct status_stat_t` | In-kernel HTTP response count distribution aggregated by status code (200, 301, 400, 404, 500). |
| **`inflight_reqs`** | `hash` (10240 entries) | `u64` (pid_tgid) $\to$ `struct in_flight_tls_t` | Internal tracking map correlating outbound requests with incoming decrypted responses. |
| **`active_reads`** | `hash` (10240 entries) | `u64` (pid_tgid) $\to$ `struct active_read_t` | Internal tracking map holding user-space buffer pointers between `SSL_read` entry and return. |
| **`active_writes`** | `hash` (10240 entries) | `u64` (pid_tgid) $\to$ `u8` | Internal tracking map suppressing recursive OpenSSL 3.x re-entrant calls. |
| **`ssl_hosts`** | `hash` (10240 entries) | `u64` (ssl_ptr) $\to$ `struct host_val_t` | Internal tracking map correlating OpenSSL `SSL*` connection handles with SNI target hostnames. |
| **`pid_hosts`** | `hash` (10240 entries) | `u32` (pid) $\to$ `struct host_val_t` | Process-level fallback map storing SNI target hostnames set via `SSL_ctrl` or `SSL_set1_host`. |
| **`scratch_map`** | `percpu_array` (1 entry) | `u32` $\to$ `struct scratch_t` | Per-CPU buffer providing safe temporary memory for payload copying without stack overflow. |

---

## 4. Multi-Page Diagnostic Views & Inspector Panes

### Page 1: HTTPS RED Metrics & Traffic Overview
- **HTTPS Request Throughput**: Real-time rolling request-per-second sparkline (`unit: qps`) with live throughput metrics.
- **HTTPS TTFB Latency Distribution**: Microsecond latency tier histogram (`unit: us`, buckets: 500us, 2ms, 10ms, 50ms, 200ms, 1s).
- **Top Remote API Destinations**: Live ranking of remote target hosts and external API endpoints (`api.stripe.com`, `api.github.com`, etc.).
- **HTTP Status Code Breakdown**: Top response distribution grouped by HTTP status code (`200 OK`, `400 Bad Request`, `404 Not Found`, `500 Server Error`).

### Page 2: Live Decrypted Stream & Payload Console
- **Top Accessed Endpoints (30% Height)**: Leaderboard of most frequently called URI routes and endpoints.
- **Live Decrypted TLS Traffic Stream (70% Height)**: High-speed real-time stream showing timestamp, PID, container ID, process name, role (`client`/`server`), HTTP method, status code, latency, target host, and path.
- **Interactive Dual-Payload Inspect Modal (`Enter`)**: Pressing `Enter` on any row opens a side-by-side viewer presenting both the decrypted request headers/body and the server response payload, with credentials safely sanitized.

### Page 3: Microservice Call Hierarchy & Latency
- **Decrypted Call Hierarchy (70% Width)**: Interactive tree visualizer (`views: ["tree", "graph", "timeline"]`) mapping parent caller processes to child processes and downstream microservices.
- **Process Traffic Leaderboard (30% Width)**: Ranked breakdown of local processes generating TLS network traffic (`curl`, `python`, `node`, `nginx`).

---

## 5. Tactical Incident Workflows & CLI Usage

### 1. Interactive Terminal TUI Triage
```bash
# Capture and decrypt all TLS traffic system-wide
sudo eprobe run app/universal-tls-sniffer

# Filter by client executable name (e.g. trace only curl or python)
sudo eprobe run app/universal-tls-sniffer --comm curl

# Filter by target host / API domain
sudo eprobe run app/universal-tls-sniffer --host api.github.com

# Filter and display only failing requests (HTTP 4xx & 5xx)
sudo eprobe run app/universal-tls-sniffer --errors-only

# Filter by remote or local TCP port
sudo eprobe run app/universal-tls-sniffer --port 8443

# Filter by process PID
sudo eprobe run app/universal-tls-sniffer --pid 12345

# Disable credential sanitization (reveal raw Bearer tokens and passwords)
sudo eprobe run app/universal-tls-sniffer --no-sanitize
```

### 2. Collaborative Browser Diagnostic View
```bash
# Extract live telemetry to the browser-based collaborative diagnostic view
sudo eprobe run app/universal-tls-sniffer --stream-token <YOUR_TOKEN>
```

### 3. Air-Gapped BYO-LLM Root Cause Analysis
During an active encrypted microservice outage, open the Web Inspector and click **`Offline AI Bundle`** in the top navigation bar to generate an air-gapped, sanitized `.zip` archive containing `00_PROMPT_COPY_PASTE.md` and `01_EXECUTIVE_SUMMARY.md`. Paste into private Claude/ChatGPT/Ollama to analyze decrypted API errors without leaking corporate secrets or user tokens.
