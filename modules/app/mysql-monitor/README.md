# app/mysql-monitor: MySQL & MariaDB Engine Diagnostics & Latency Triage

The **`app/mysql-monitor`** module is an ephemeral, tactical eBPF incident response utility engineered for **MySQL 5.7, 8.0, 8.4, and MariaDB**. It isolates slow SQL query statements, microsecond latency distributions, transaction deadlocks, InnoDB storage block I/O bottlenecks, and connection worker CPU saturation with zero application overhead and zero configuration changes to `my.cnf`.

---

## 1. Tactical Incident Scope & Target Personas

* **Target Roles**: Database Administrators (DBAs), Site Reliability Engineers (SREs), and L3 Escalation Teams.
* **Target Engines**: MySQL 5.7, 8.0, 8.4 LTS, and MariaDB running in bare-metal, virtualized, or containerized environments.
* **Core Incident Scenarios**:
  - **Query Latency Spikes**: Applications experience database timeouts, but enabling the MySQL `slow_query_log` or `general_log` creates dangerous disk I/O overhead and mutex contention in high-throughput production databases.
  - **Deadlock Cascades**: Transactions abort with error `1213` (Deadlock) or `1205` (Lock wait timeout exceeded); `mysql-monitor` captures the exact contending SQL statements and rollback events in real time.
  - **InnoDB Storage Saturation**: Database flusher threads blocked on storage controller writebacks, redo log buffer contention, or tablespace page writes.
* **Overhead Profile**: Intercepts socket read/write syscalls directly at the kernel boundary without inspecting in-memory database structures or attaching debuggers. Employs dual-plane telemetry (1Hz continuous BPF hash maps and discrete 16MB ring buffers) with `<1%` CPU utilization. Clean detach with `Ctrl+C` leaves zero host sidecars or background agents behind.

---

## 2. Key Technical Capabilities

### 1. Ingress Database Auto-Discovery (2-Tier Resolution Engine)
- **Automatic Handshake Decoding**: Inspects client `HandshakeResponse41` packets upon TCP connection establishment (`CLIENT_CONNECT_WITH_DB = 0x0008`), automatically extracting the database schema name (e.g. `payments_db`, `wordpress`, `shop_db`) before queries begin.
- **Dual-Tier Resolution**:
  - **Tier 1 (Thread-Scoped)**: Uses `active_db[&tid]` to maintain isolated database context for individual connection worker threads.
  - **Tier 2 (Process Connection Pool Default)**: If a pre-existing connection pool thread has no thread-specific override, it falls back to `proc_default_db[&pid]`, ensuring all persistent pool workers inherit the correct application schema without requiring service restarts.
  - **Runtime SQL Tracking**: Dynamically updates active schemas whenever `USE <db>` statements or binary `COM_INIT_DB` packets are executed.

### 2. Dual-Framing MySQL Protocol Parser
- **Pattern A (Full Packets)**: Decodes complete 5-byte framed packets from client `write()` and `sendto()` syscalls (`[3 len][1 seq_id][1 cmd_byte][query...]`).
- **Pattern B (Segmented Reads)**: Handles MySQL Server's internal two-stage segmented socket reads (`net_serv.cc`), parsing raw payload buffers where the 4-byte header was already consumed in a preceding syscall.

### 3. Full 512-Byte SQL Statement Capture & Exact Boundary Clamping
- Captures up to **512 bytes** of SQL query text across complex `JOIN`, subquery, and `WHERE IN (...)` clauses.
- Mathematically clamps query strings at the exact packet payload boundary (`query_len = len - 5` / `len - 1` with `query_len &= 0x1FF`), eliminating socket buffer noise.

### 4. Zero-Loop SQL Classification & Verifier Safety
- **Single-Pass $O(1)$ Classification**: Categorizes SQL commands (`SELECT`, `INSERT`, `UPDATE`, `DELETE`, `COMMIT`, `ROLLBACK`, `BEGIN`, `CREATE`, `ALTER`, `DROP`, `CALL`, etc.) using instant direct scalar comparisons on keyword character prefixes.
- **Linear Verifier Complexity**: Masks all scalar lengths with bitwise AND (`len &= 0x1FF`) and isolates stack structs inside `BPF_MAP_TYPE_PERCPU_ARRAY` (`req_scratch`), guaranteeing zero kernel verifier rejections.

### 5. Storage Engine & Subsystem Diagnostics
- **InnoDB Block I/O Tracing**: Hooks `block_rq_issue` and `block_rq_complete` with CO-RE `trace_event_raw_block_rq_completion___local` (`__attribute__((preserve_access_index))`) to trace disk read/write latencies and byte throughput (`nr_sector * 512`) for redo logs, doublewrite buffers, and tablespace pages across Linux 5.x, 6.x, and 7.0+ kernels.
- **Worker Thread CPU Profiling**: Hooks `sched/sched_stat_runtime` to aggregate runtime CPU utilization for MySQL connection workers (`conn_...`, `connection`) and internal background threads (`ib_io_wr`, `ib_page_flush`).
- **Diagnostic Log Stream**: Captures daemonized error log writes (`/var/log/mysql/mysqld.log`, MariaDB logs, stderr) using signature pattern matching.

---

## 3. Exported Telemetry Maps & Schemas

| Map Name | Type | Key / Value Struct | Description |
| :--- | :--- | :--- | :--- |
| **`sql_events`** | `ringbuf` (16 MB) | `struct sql_event_t` | Real-time stream of executed SQL queries with duration, PID, client IP, database name, and status. |
| **`lock_events`** | `ringbuf` (16 MB) | `struct lock_event_t` | Real-time alerts for Deadlocks (1213), Lock Timeouts (1205), Duplicate Keys (1062), and Rollbacks. |
| **`log_events`** | `ringbuf` (16 MB) | `struct log_event_t` | MySQL daemon error log entries filtered from log files (`fd >= 3`) and stderr. |
| **`io_events`** | `ringbuf` (16 MB) | `struct io_event_t` | Individual disk block request latency and throughput events. |
| **`cpu_stats`** | `hash` (1024 entries) | `mysql_thread_key_t` $\to$ `cpu_stat_t` | In-kernel runtime CPU delta statistics aggregated by MySQL thread name. |
| **`io_stats`** | `hash` (1024 entries) | `mysql_io_key_t` $\to$ `io_stat_t` | In-kernel read/write throughput delta statistics per thread comm. |

---

## 4. Multi-Page Diagnostic Views & Inspector Panes

### Page 1: MySQL Ingress Health & Latency Distribution
- **MySQL QPS Throughput**: Real-time rolling queries-per-second sparkline with Min, Max, and Avg badges.
- **Query Latency Distribution**: Microsecond latency tier histogram (`100–500µs`, `500–1000µs`, `1–5ms`, `5–20ms`, `20–100ms`, `>100ms`).
- **SQL Command Breakdown**: Top leaderboard ranking query types (`COMMIT`, `UPDATE`, `INSERT`, `BEGIN`, `SELECT`, `SET`).
- **Top Active Databases**: Live query volume leaderboard grouped by discovered database schema (`payments_db`, `wordpress`, etc.).

### Page 2: Live SQL Statement Stream & Query Inspector
- **Top Slowest Queries (100% Width)**: Leaderboard of slow/frequent queries with execution history. Clicking any row opens the Dedicated SQL Statement Inspector.
- **Live SQL Stream (100% Width)**: Real-time query execution stream with streamlined columns (`TIME`, `DB_NAME`, `SQL_CMD`, `DURATION`, `QUERY` allocating ~75% widescreen width to the SQL statement).

### Page 3: Transaction Deadlocks & Lock Contention Triage
- **Deadlock & Lock Timeout Alerts**: Real-time alerts displaying error codes, statement text, and transaction rollback events.
- **Transaction Command Breakdown**: Distribution of transaction control statements (`COMMIT`, `ROLLBACK`, `START`, `PREPARE`).

### Page 4: InnoDB Storage & Block I/O Diagnostics
- **Top Disk I/O MySQL Threads**: Read/Write throughput leaderboard for database workers.
- **Disk Latency Histogram**: Kernel block-level I/O response time distribution.
- **Live InnoDB Disk Events**: Real-time stream of individual page read/write requests.

### Page 5: Server Diagnostic Logs & Worker Thread CPU Profiling
- **Top CPU Consuming MySQL Threads**: Live CPU utilization percentage by thread identifier.
- **mysqld Server Diagnostic Logs**: Live tail of server error logs and daemon notifications.

---

## 5. Tactical Incident Workflows & CLI Usage

### 1. Interactive Terminal TUI Triage
```bash
# Launch interactive terminal TUI targeting default MySQL port 3306
sudo eprobe run app/mysql-monitor

# Target custom MySQL / MariaDB port
sudo eprobe run app/mysql-monitor --port 3307

# Isolate diagnostics to a specific mysqld process PID
sudo eprobe run app/mysql-monitor --pid 951267

# Set custom slow query latency alert threshold (in microseconds, default: 10000 = 10ms)
sudo eprobe run app/mysql-monitor --slow-us 5000
```

### 2. Collaborative Browser Diagnostic View
```bash
# Extract telemetry to browser-based collaborative diagnostic view
sudo eprobe run app/mysql-monitor --stream-token <YOUR_TOKEN>
```

### 3. Air-Gapped BYO-LLM Root Cause Analysis
During an active database stall, open the browser Web Inspector and click **`Offline AI Bundle`** in the top bar to export a client-side sanitized `.zip` archive containing `00_PROMPT_COPY_PASTE.md` and `01_EXECUTIVE_SUMMARY.md`. Paste directly into private Claude/ChatGPT/Ollama for immediate SQL optimization and deadlock remediation recommendations with zero data egress.
