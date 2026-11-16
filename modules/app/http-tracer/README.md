# app/http-tracer: HTTP Ingress Diagnostics & TTFB Latency Triage

The **`app/http-tracer`** module is an ephemeral, tactical eBPF incident response utility engineered for **Web Gateways, Reverse Proxies, and Microservices** (Nginx, Node.js, Go, Python Gunicorn/Uvicorn, PHP-FPM, Caddy, Envoy, Apache). It isolates HTTP tail-latency spikes, microsecond Time to First Byte (TTFB) delays, 5xx server error cascades, slow request bottlenecks, and web worker CPU saturation with zero application modification and zero SDK instrumentation.

---

## 1. Tactical Incident Scope & Target Personas

* **Target Roles**: Site Reliability Engineers (SREs), Platform DevOps, API Gateways Engineers, and Backend Systems Engineers.
* **Target Services**: Edge proxies (Nginx, Envoy, Caddy, HAProxy, Apache) and backend application runtimes (Node.js, Go, Python, Java, PHP-FPM).
* **Core Incident Scenarios**:
  - **The 5xx Cascade**: Reverse proxies return 502 Bad Gateway or 504 Gateway Timeout during peak traffic. Standard access logs are only flushed after connection termination; `http-tracer` captures in-flight request stalls and backend error payloads in real time.
  - **TTFB & Handler Bottlenecks**: Distinguishing network transit delay from internal backend application handler processing time.
  - **Microservice Trace Tree Lineage**: Triage distributed request flows across parent-child service calls using W3C trace context and correlation headers.
* **Overhead Profile**: Intercepts socket read/write operations at the kernel level using bounded $O(N)$ scanners with bitwise bounds masking (`len &= 0x1FF`). Maintains `<1%` CPU utilization. Clean detach with `Ctrl+C` leaves zero host sidecars or background agents behind.

---

## 2. Key Technical Capabilities

### 1. Ingress & Egress HTTP Payload Decoding
- **Full Path & Query String Capture**: Inspects up to **512 bytes** of HTTP request/response payloads, extracting full URL query parameters (e.g. `/api/v1/users?limit=10&page=2`) with exact boundary clamping (`path_idx &= 0xFF`).
- **Virtual Host (`Host:`) & Routing Auto-Discovery**: Automatically decodes target domain names and virtual hosts (`api.example.com`, `auth.internal`), organizing traffic across multi-tenant environments and API gateways.
- **Client & Media Classification**: Identifies `User-Agent` (browsers, bots, mobile apps, curl) and `Content-Type` headers (`application/json`, `text/html`, `multipart/form-data`, `application/grpc`).

### 2. Microsecond Latency & Round-Trip Correlation
- Correlates request transmission (`sys_enter_write`, `tcp_sendmsg`) with response arrival (`sys_enter_read`, `tcp_recvmsg`).
- Measures:
  - **TTFB (Time to First Byte)**: Processing time spent in backend application handlers before sending response headers.
  - **Total Round-Trip Duration (`duration_us`)**: End-to-end execution time in microseconds.
  - **Payload Metrics**: Exact bytes transmitted (`tx_bytes`) and received (`rx_bytes`).

### 3. W3C Distributed Tracing & Trace Tree Spans
- Decodes standard distributed tracing headers:
  - **W3C Trace Context**: `traceparent: 00-<trace_id>-<span_id>-<flags>`
  - **Microservice Headers**: `X-Request-ID`, `X-Correlation-ID`
- Generates hierarchical span IDs (`req_id` $\to$ `parent_req_id`), rendering interactive parent-child microservice trees across asynchronous and multi-threaded servers.

### 4. Product Runtime Version & Protocol Inspection
- **Runtime Daemon Version**: Automatically extracts product and version banners from `Server:` (`Apache/2.4.58 (Ubuntu)`, `nginx/1.24.0`) and `X-Powered-By:` (`PHP/8.2.16`, `Express`) headers with zero configuration.
- **HTTP Protocol Version**: Captures the exact protocol dialect (`HTTP/1.1`, `HTTP/1.0`, `HTTP/2.0`) directly from the request stream line.
- **Deep Payload & Response Inspection**: Captures up to 256 bytes of unmasked request bodies (POST JSON, form data, JSON-RPC) and response payloads (API results, JSON errors, HTML snippets).

### 5. Dedicated Diagnostics & Slow Request Alerts
- **Slow Request Alerts**: Requests taking longer than the configurable `--slow-us` threshold (default: 50ms) are immediately emitted to the `slow_events` ring buffer.
- **4xx/5xx Error Stream**: Captures client errors (400, 401, 403, 404, 422, 429) and backend server errors (500, 502, 503, 504) with human-readable error descriptions.

### 6. Web Server Worker CPU Profiling & Error Logs
- **Worker CPU Scheduling**: Hooks `sched/sched_stat_runtime` to aggregate instantaneous runtime CPU utilization (`cpu_time_ns`) per web worker process/thread (`nginx: worker`, `node`, `gunicorn`, `php-fpm`).
- **Diagnostic Framework Logs**: Captures `stderr` and daemon log writes into `log_events`.

---

## 3. Exported Telemetry Maps & Schemas

| Map Name | Type | Key / Value Struct | Description |
| :--- | :--- | :--- | :--- |
| **`http_events`** | `ringbuf` (16 MB) | `struct http_event_t` | Stream of completed HTTP transactions with method, path, host, status, duration, client IP, protocol, server version, request payload, and response body. |
| **`slow_events`** | `ringbuf` (16 MB) | `struct slow_event_t` | Stream of HTTP requests taking longer than `--slow-us`, including full payloads and runtime versions. |
| **`error_events`** | `ringbuf` (16 MB) | `struct error_event_t` | Stream of requests returning 4xx client errors or 5xx server errors with error classifications. |
| **`log_events`** | `ringbuf` (16 MB) | `struct log_event_t` | Web server and framework error logs captured from `stderr` (`fd = 2`) and log descriptors. |
| **`cpu_stats`** | `hash` (1024 entries) | `cpu_stat_key_t` $\to$ `cpu_stat_t` | In-kernel runtime CPU delta statistics aggregated by web worker thread name. |
| **`host_stats`** | `hash` (1024 entries) | `host_stat_key_t` $\to$ `host_stat_t` | In-kernel request volume statistics aggregated per Virtual Host / Domain. |

---

## 4. Multi-Page Diagnostic Views & Inspector Panes

### Page 1: HTTP Ingress Health & TTFB Latency Spectrum
- **HTTP Request Throughput**: Real-time rolling requests-per-second sparkline with Min, Max, and Avg badges.
- **HTTP Response Latency**: Microsecond latency tier histogram (`<1ms`, `1–5ms`, `5–20ms`, `20–100ms`, `100–500ms`, `>500ms`).
- **HTTP Status Code Breakdown**: Top leaderboard ranking responses by status code (`200 OK`, `304 Not Modified`, `400 Bad Request`, `404 Not Found`, `500 Internal Error`, `502 Bad Gateway`).
- **Top Virtual Hosts & Domains**: Traffic leaderboard grouped by discovered domain name (`api.payments.internal`, `auth.internal`, etc.).

### Page 2: Live HTTP Request Stream & Header Inspector
- **Top Active Endpoints (30% Height)**: Most frequently hit route paths.
- **Live HTTP Events Stream (70% Height)**: Real-time query execution stream with color-coded method badges, status codes, latency, and full URL paths.
- **Interactive Inspect Modal (`Enter`)**: Pressing `Enter` on any row opens the full-screen JSON inspector displaying all extracted HTTP headers, client IP, payload byte size, and timing breakdown.

### Page 3: Slow Requests & 5xx Cascade Triage
- **Slow Request Alerts (> Threshold)**: Real-time stream of slow requests with execution durations and exact paths.
- **4xx/5xx HTTP Error Stream**: Stream of failed requests highlighting client blocks (401/403), missing routes (404), and unhandled server exceptions (500/502).
- **Top Failing Endpoints**: Leaderboard ranking the routes generating the most errors.

### Page 4: Upstream Dependencies & Distributed Trace Hierarchy
- **Distributed Trace Hierarchy (70% Width)**: Interactive hierarchical tree visualizing Ingress Request $\to$ Backend Handler $\to$ Upstream Microservice calls with synchronized Gantt latency waterfall bars.
- **Top Target Hosts (30% Width)**: Leaderboard of external APIs and upstream microservices by volume.

### Page 5: Web Server Workers & Framework Logs
- **Top CPU Consuming Worker Threads**: Live CPU % utilization per web server worker (`nginx: worker`, `node`, `gunicorn`, `php-fpm`).
- **Web Server & Framework Diagnostic Logs**: Live tail of stdout/stderr messages and framework exceptions.

---

## 5. Tactical Incident Workflows & CLI Usage

### 1. Interactive Terminal TUI Triage
```bash
# Launch interactive terminal TUI (auto-detects HTTP ports 80, 443, 3000, 8080)
sudo eprobe run app/http-tracer

# Isolate diagnostics to a specific HTTP port
sudo eprobe run app/http-tracer --port 3000

# Target a specific web server process PID
sudo eprobe run app/http-tracer --pid 14208

# Set custom slow request alert threshold (e.g. 20ms)
sudo eprobe run app/http-tracer --slow-ms 20
```

### 2. Collaborative Browser Diagnostic View
```bash
# Extract live telemetry to the browser-based collaborative diagnostic view
sudo eprobe run app/http-tracer --stream-token <YOUR_TOKEN>
```

### 3. Air-Gapped BYO-LLM Root Cause Analysis
During an active API degradation or 5xx cascade, open the Web Inspector and click **`Offline AI Bundle`** in the top navigation bar to generate a client-side sanitized `.zip` archive containing `00_PROMPT_COPY_PASTE.md` and `01_EXECUTIVE_SUMMARY.md`. Paste into private Claude/ChatGPT/Ollama for automated 5xx cascade diagnosis with zero cloud egress.
