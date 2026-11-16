// SPDX-License-Identifier: GPL-2.0-only OR MIT
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/eprobe_tracepoint.h>

typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;

struct pt_regs {
    unsigned long r15;
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long rbp;
    unsigned long rbx;
    unsigned long r11;
    unsigned long r10;
    unsigned long r9;
    unsigned long r8;
    unsigned long rax;
    unsigned long rcx;
    unsigned long rdx;
    unsigned long rsi;
    unsigned long rdi;
    unsigned long orig_rax;
    unsigned long rip;
    unsigned long cs;
    unsigned long eflags;
    unsigned long rsp;
    unsigned long ss;
};

// Partial definition of sock structure for CO-RE read
struct sock___local {
    struct {
        union {
            struct {
                __be32 skc_daddr;
                __be32 skc_rcv_saddr;
            };
        };
        union {
            struct {
                __be16 skc_dport;
                __u16 skc_num;
            };
        };
    } __sk_common;
} __attribute__((preserve_access_index));

struct mm_struct___local {
    unsigned long arg_start;
} __attribute__((preserve_access_index));

struct task_struct___local {
    struct mm_struct___local *mm;
    struct task_struct___local *group_leader;
    struct task_struct___local *real_parent;
    u32 tgid;
    u32 pid;
    char comm[16];
} __attribute__((preserve_access_index));

struct iovec___local {
    void *iov_base;
    unsigned long iov_len;
} __attribute__((preserve_access_index));

struct sql_event_t {
    u32 pid;
    u32 tid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    char comm[16];
    char cmd_type[16];
    char sql_cmd[16];
    char query[512];
    char db_name[32];
    u64 duration_us;
    u16 status_code;
    u32 affected_rows;
    u32 tx_bytes;
    u32 rx_bytes;
} __attribute__((packed));

struct lock_event_t {
    u32 pid;
    u32 saddr;
    char event_type[16];
    u16 error_code;
    u64 duration_us;
    char query[512];
    char message[128];
} __attribute__((packed));

struct log_event_t {
    u32 pid;
    char level[8];
    char message[256];
} __attribute__((packed));

struct io_event_t {
    u32 pid;
    char comm[16];
    char rwflag[8];
    u32 bytes;
    u64 latency_us;
} __attribute__((packed));

struct mysql_thread_key_t {
    char title[64];
};

struct mysql_io_key_t {
    char comm[16];
};

struct cpu_stat_t {
    u64 cpu_time_ns;
};

struct io_stat_t {
    u64 read_bytes;
    u64 write_bytes;
};

struct sql_req_t {
    u64 start_ns;
    u32 pid;
    u32 tid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    char comm[16];
    char cmd_type[16];
    char sql_cmd[16];
    char query[512];
    char db_name[32];
    u32 rx_bytes;
};

struct client_ip_t {
    u32 ip;
};

struct db_name_t {
    char name[32];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB ring buffer
} sql_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} lock_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} log_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} io_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct mysql_thread_key_t);
    __type(value, struct cpu_stat_t);
} cpu_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct mysql_io_key_t);
    __type(value, struct io_stat_t);
} io_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64); // pid_tgid
    __type(value, struct sql_req_t);
} in_flight_queries SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct sql_req_t);
} req_scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32); // pid
    __type(value, struct client_ip_t);
} proc_client_ip SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct client_ip_t);
} last_external_ip SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32); // tid (thread ID / connection worker)
    __type(value, struct db_name_t);
} active_db SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32); // pid (process ID / connection pool default)
    __type(value, struct db_name_t);
} proc_default_db SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64); // pid_tgid
    __type(value, const char *);
} read_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64); // pid_tgid
    __type(value, const char *);
} recvfrom_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64); // pid_tgid
    __type(value, u64); // start_ns
} io_start SEC(".maps");

volatile const u16 filter_port = 0;
volatile const u32 filter_pid = 0;
volatile const u64 slow_query_us = 10000;

static __always_inline int is_mysql_comm(const char *comm) {
    if (comm[0] == 'm' && comm[1] == 'y' && comm[2] == 's' && comm[3] == 'q' && comm[4] == 'l') return 1; // mysqld, mysql
    if (comm[0] == 'm' && comm[1] == 'a' && comm[2] == 'r' && comm[3] == 'i' && comm[4] == 'a') return 1; // mariadbd
    if (comm[0] == 'p' && comm[1] == 'r' && comm[2] == 'o' && comm[3] == 'x' && comm[4] == 'y') return 1; // proxysql
    if (comm[0] == 'c' && comm[1] == 'o' && comm[2] == 'n' && comm[3] == 'n') return 1; // connection, conn_
    if (comm[0] == 't' && comm[1] == 'h' && comm[2] == 'd') return 1; // thd_
    return 0;
}

static __always_inline int is_target_process(const char *comm, u32 pid) {
    if (comm[0] == 'e' && comm[1] == 'p' && comm[2] == 'r' &&
        comm[3] == 'o' && comm[4] == 'b' && comm[5] == 'e') {
        return 0;
    }
    if (filter_pid != 0 && pid == filter_pid) return 1;
    if (is_mysql_comm(comm)) return 1;

    struct task_struct___local *task = (struct task_struct___local *)bpf_get_current_task();
    if (task) {
        struct task_struct___local *leader = BPF_CORE_READ(task, group_leader);
        if (leader) {
            char leader_comm[16] = {0};
            bpf_probe_read_kernel_str(leader_comm, sizeof(leader_comm), leader->comm);
            if (is_mysql_comm(leader_comm)) return 1;
        }
    }
    return 0;
}

// Fast O(1) SQL keyword classifier (Zero loop instructions, zero stack pointer math)
static __always_inline void classify_sql(const char *q, char *cmd) {
    char c0 = q[0];
    char c1 = q[1];
    char c2 = q[2];

    // If query starts with whitespace, check next chars
    if (c0 == ' ' || c0 == '\t' || c0 == '\n' || c0 == '\r') {
        c0 = q[1];
        c1 = q[2];
        c2 = q[3];
        if (c0 == ' ' || c0 == '\t' || c0 == '\n' || c0 == '\r') {
            c0 = q[2];
            c1 = q[3];
            c2 = q[4];
            if (c0 == ' ' || c0 == '\t' || c0 == '\n' || c0 == '\r') {
                c0 = q[3];
                c1 = q[4];
                c2 = q[5];
            }
        }
    }

    if (c0 >= 'a' && c0 <= 'z') c0 -= 32;
    if (c1 >= 'a' && c1 <= 'z') c1 -= 32;
    if (c2 >= 'a' && c2 <= 'z') c2 -= 32;

    if (c0 == 'S' && c1 == 'E' && c2 == 'L') __builtin_memcpy(cmd, "SELECT", 7);
    else if (c0 == 'I' && c1 == 'N' && c2 == 'S') __builtin_memcpy(cmd, "INSERT", 7);
    else if (c0 == 'U' && c1 == 'P' && c2 == 'D') __builtin_memcpy(cmd, "UPDATE", 7);
    else if (c0 == 'D' && c1 == 'E' && c2 == 'L') __builtin_memcpy(cmd, "DELETE", 7);
    else if (c0 == 'S' && c1 == 'H' && c2 == 'O') __builtin_memcpy(cmd, "SHOW", 5);
    else if (c0 == 'S' && c1 == 'E' && c2 == 'T') __builtin_memcpy(cmd, "SET", 4);
    else if (c0 == 'C' && c1 == 'O' && c2 == 'M') __builtin_memcpy(cmd, "COMMIT", 7);
    else if (c0 == 'R' && c1 == 'O' && c2 == 'L') __builtin_memcpy(cmd, "ROLLBACK", 9);
    else if (c0 == 'B' && c1 == 'E' && c2 == 'G') __builtin_memcpy(cmd, "BEGIN", 6);
    else if (c0 == 'S' && c1 == 'T' && c2 == 'A') __builtin_memcpy(cmd, "START", 6);
    else if (c0 == 'U' && c1 == 'S' && c2 == 'E') __builtin_memcpy(cmd, "USE", 4);
    else if (c0 == 'C' && c1 == 'R' && c2 == 'E') __builtin_memcpy(cmd, "CREATE", 7);
    else if (c0 == 'A' && c1 == 'L' && c2 == 'T') __builtin_memcpy(cmd, "ALTER", 6);
    else if (c0 == 'D' && c1 == 'R' && c2 == 'O') __builtin_memcpy(cmd, "DROP", 5);
    else if (c0 == 'T' && c1 == 'R' && c2 == 'U') __builtin_memcpy(cmd, "TRUNCATE", 9);
    else if (c0 == 'E' && c1 == 'X' && c2 == 'P') __builtin_memcpy(cmd, "EXPLAIN", 8);
    else if (c0 == 'D' && c1 == 'E' && c2 == 'S') __builtin_memcpy(cmd, "DESCRIBE", 9);
    else if (c0 == 'C' && c1 == 'A' && c2 == 'L') __builtin_memcpy(cmd, "CALL", 5);
    else if (c0 == 'K' && c1 == 'I' && c2 == 'L') __builtin_memcpy(cmd, "KILL", 5);
    else if (c0 == 'R' && c1 == 'E' && c2 == 'P') __builtin_memcpy(cmd, "REPLACE", 8);
    else __builtin_memcpy(cmd, "OTHER", 6);
}

static __always_inline void try_parse_handshake_response(u32 pid, u32 tid, const char *buf_user, u32 len) {
    len &= 0x1FF;
    if (len < 36) return;

    char header[8] = {0};
    if (bpf_probe_read_user(header, sizeof(header), buf_user) < 0) return;

    u32 client_flags = 0;
    u32 user_start_offset = 0;

    // Pattern A: Full-packet framing [3 len][1 seq_id == 1][4 flags]...
    if (len >= 40 && header[3] == 1) {
        if (bpf_probe_read_user(&client_flags, sizeof(client_flags), buf_user + 4) < 0) return;
        user_start_offset = 36;
    }
    // Pattern B: Segmented payload read in mysqld [4 flags][4 max_packet][1 charset][23 filler]...
    else {
        client_flags = *(u32 *)header;
        // Verify 23-byte filler at offset 9..31 (verify zero filler bytes)
        char filler_check[4] = {0};
        if (bpf_probe_read_user(filler_check, sizeof(filler_check), buf_user + 9) < 0) return;
        if (filler_check[0] != 0 || filler_check[1] != 0 || filler_check[2] != 0 || filler_check[3] != 0) return;
        user_start_offset = 32;
    }

    // CLIENT_CONNECT_WITH_DB = 0x00000008
    if (!(client_flags & 0x0008)) return;

    user_start_offset &= 0x1FF;
    if (user_start_offset + 32 >= len) return;

    // Read username string
    char user_str[32] = {0};
    bpf_probe_read_user_str(user_str, sizeof(user_str), buf_user + user_start_offset);

    u32 user_len = 0;
    #pragma clang loop unroll(full)
    for (int i = 0; i < 31; i++) {
        if (user_str[i & 0x1F] == '\0') break;
        user_len++;
    }
    if (user_len == 0 || user_len > 30) return;

    // Auth response offset: user_start_offset + user_len + 1
    u32 auth_offset = (user_start_offset + user_len + 1) & 0x1FF;
    if (auth_offset >= len) return;

    u8 auth_len = 0;
    if (bpf_probe_read_user(&auth_len, sizeof(auth_len), buf_user + auth_offset) < 0) return;

    // DB name offset: auth_offset + 1 + auth_len
    u32 db_offset = (auth_offset + 1 + (u32)auth_len) & 0x1FF;
    if (db_offset >= len) return;

    struct db_name_t new_db = {0};
    bpf_probe_read_user_str(new_db.name, sizeof(new_db.name), buf_user + db_offset);

    // Validate identifier characters
    #pragma clang loop unroll(full)
    for (int k = 0; k < 31; k++) {
        char c = new_db.name[k & 0x1F];
        if (c == '\0') break;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '$' || c == '-')) {
            new_db.name[0] = '\0';
            break;
        }
    }

    if (new_db.name[0] != '\0') {
        bpf_map_update_elem(&active_db, &tid, &new_db, BPF_ANY);
        bpf_map_update_elem(&proc_default_db, &pid, &new_db, BPF_ANY);
    }
}

static __always_inline int process_sql_request(u64 pid_tgid, const char *comm, const char *buf_user, u32 len) {
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    if (!is_target_process(comm, pid)) return 0;

    len &= 0x1FF;
    if (len < 2) return 0;

    char header[8] = {0};
    if (bpf_probe_read_user(header, sizeof(header), buf_user) < 0) return 0;

    u8 cmd_byte = 0;
    const char *payload_user = NULL;

    // Pattern A: Full-packet framing (Client write/sendto or socket full recvfrom)
    // [3 len][1 seq_id == 0][1 cmd_byte][query text...]
    if (len >= 5 && header[3] == 0 && (header[4] == 0x03 || header[4] == 0x02 || header[4] == 0x16 || header[4] == 0x17 || header[4] == 0x0E || header[4] == 0x01 || header[4] == 0x1F)) {
        cmd_byte = (u8)header[4];
        payload_user = buf_user + 5;
    }
    // Pattern B: MySQL Server segmented read (Server net_serv.cc)
    // [1 cmd_byte][query text...]
    else if (header[0] == 0x03 || header[0] == 0x16) {
        // COM_QUERY / PREPARE: payload must start with printable ASCII
        if ((u8)header[1] >= 32 && (u8)header[1] <= 126) {
            cmd_byte = (u8)header[0];
            payload_user = buf_user + 1;
        } else {
            return 0;
        }
    }
    else if (header[0] == 0x02) {
        // COM_INIT_DB: payload must start with a valid ASCII identifier letter/underscore
        char c1 = header[1];
        if ((c1 >= 'a' && c1 <= 'z') || (c1 >= 'A' && c1 <= 'Z') || c1 == '_') {
            cmd_byte = (u8)header[0];
            payload_user = buf_user + 1;
        } else {
            return 0;
        }
    }
    else if (header[0] == 0x17 || header[0] == 0x0E || header[0] == 0x01 || header[0] == 0x1F) {
        cmd_byte = (u8)header[0];
        payload_user = buf_user + 1;
    } else {
        return 0;
    }

    u32 zero = 0;
    struct sql_req_t *req = bpf_map_lookup_elem(&req_scratch, &zero);
    if (!req) return 0;

    __builtin_memset(req, 0, sizeof(*req));
    req->start_ns = bpf_ktime_get_ns();
    req->pid = pid;
    req->tid = tid;
    req->rx_bytes = len;
    bpf_get_current_comm(req->comm, sizeof(req->comm));

    // 2-Tier Client IP Lookup
    struct client_ip_t *cip = bpf_map_lookup_elem(&proc_client_ip, &pid);
    if (!cip || cip->ip == 0) {
        u32 zero_key = 0;
        cip = bpf_map_lookup_elem(&last_external_ip, &zero_key);
    }
    if (cip && cip->ip != 0) {
        req->saddr = cip->ip;
    }

    // 2-Tier Active Database Lookup
    struct db_name_t *active = bpf_map_lookup_elem(&active_db, &tid);
    if (active && active->name[0] != '\0') {
        __builtin_memcpy(req->db_name, active->name, sizeof(req->db_name));
    } else {
        struct db_name_t *proc_db = bpf_map_lookup_elem(&proc_default_db, &pid);
        if (proc_db && proc_db->name[0] != '\0') {
            __builtin_memcpy(req->db_name, proc_db->name, sizeof(req->db_name));
        } else {
            __builtin_memcpy(req->db_name, "(default)", 10);
        }
    }

    if (cmd_byte == 0x03 || cmd_byte == 0x16) {
        // COM_QUERY (0x03) or COM_STMT_PREPARE (0x16)
        if (cmd_byte == 0x03) {
            __builtin_memcpy(req->cmd_type, "COM_QUERY", 10);
        } else {
            __builtin_memcpy(req->cmd_type, "PREPARE", 8);
        }

        // Direct kernel-assisted user string copy
        bpf_probe_read_user_str(req->query, sizeof(req->query), payload_user);

        // Clamping query length strictly at exact packet boundary
        u32 query_len = (payload_user == buf_user + 5) ? (len - 5) : (len - 1);
        query_len &= 0x1FF;
        if (query_len < sizeof(req->query)) {
            req->query[query_len] = '\0';
        }

        // Sanity check: must be printable ASCII
        char first_c = req->query[0];
        if (first_c < 32 || first_c > 126) {
            return 0;
        }

        classify_sql(req->query, req->sql_cmd);

        // Check if query is USE db_name
        if (req->sql_cmd[0] == 'U' && req->sql_cmd[1] == 'S' && req->sql_cmd[2] == 'E') {
            struct db_name_t new_db = {0};
            int offset = 3;
            if (req->query[3] == ' ' || req->query[3] == '\t') offset = 4;
            #pragma clang loop unroll(full)
            for (int k = 0; k < 31; k++) {
                char ch = req->query[(offset + k) & 0x1FF];
                if (ch == '\0' || ch == ';' || ch == ' ' || ch == '`' || ch == '\r' || ch == '\n') break;
                if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '$' || ch == '-')) {
                    new_db.name[0] = '\0';
                    break;
                }
                new_db.name[k & 0x1F] = ch;
            }
            if (new_db.name[0] != '\0') {
                __builtin_memcpy(req->db_name, new_db.name, sizeof(req->db_name));
                bpf_map_update_elem(&active_db, &tid, &new_db, BPF_ANY);
                bpf_map_update_elem(&proc_default_db, &pid, &new_db, BPF_ANY);
            }
        }
    } else if (cmd_byte == 0x02) {
        // COM_INIT_DB (USE db)
        __builtin_memcpy(req->cmd_type, "INIT_DB", 8);
        __builtin_memcpy(req->sql_cmd, "USE", 4);

        struct db_name_t new_db = {0};
        bpf_probe_read_user_str(new_db.name, sizeof(new_db.name), payload_user);

        // Validate identifier characters
        #pragma clang loop unroll(full)
        for (int k = 0; k < 31; k++) {
            char c = new_db.name[k & 0x1F];
            if (c == '\0') break;
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '$' || c == '-')) {
                new_db.name[0] = '\0';
                break;
            }
        }

        if (new_db.name[0] != '\0') {
            __builtin_memcpy(req->db_name, new_db.name, sizeof(req->db_name));
            __builtin_memcpy(req->query, new_db.name, sizeof(new_db.name));
            bpf_map_update_elem(&active_db, &tid, &new_db, BPF_ANY);
            bpf_map_update_elem(&proc_default_db, &pid, &new_db, BPF_ANY);
        } else {
            return 0;
        }
    } else if (cmd_byte == 0x17) {
        // COM_STMT_EXECUTE
        __builtin_memcpy(req->cmd_type, "EXECUTE", 8);
        __builtin_memcpy(req->sql_cmd, "EXECUTE", 8);
    } else if (cmd_byte == 0x0E) {
        // COM_PING
        __builtin_memcpy(req->cmd_type, "PING", 5);
        __builtin_memcpy(req->sql_cmd, "PING", 5);
    } else if (cmd_byte == 0x01) {
        // COM_QUIT
        __builtin_memcpy(req->cmd_type, "QUIT", 5);
        __builtin_memcpy(req->sql_cmd, "QUIT", 5);
    } else if (cmd_byte == 0x1F) {
        // COM_RESET_CONNECTION
        __builtin_memcpy(req->cmd_type, "RESET_CONN", 11);
        __builtin_memcpy(req->sql_cmd, "RESET", 6);
    } else {
        return 0;
    }

    bpf_map_update_elem(&in_flight_queries, &pid_tgid, req, BPF_ANY);

    // Immediate Ring Buffer Submission on Ingress (http-tracer pattern)
    struct sql_event_t *e = bpf_ringbuf_reserve(&sql_events, sizeof(*e), 0);
    if (e) {
        e->pid = req->pid;
        e->tid = req->tid;
        e->saddr = req->saddr;
        e->daddr = req->daddr;
        e->sport = req->sport;
        e->dport = req->dport;
        e->duration_us = 0;
        e->status_code = 0;
        e->affected_rows = 0;
        e->tx_bytes = 0;
        e->rx_bytes = req->rx_bytes;
        __builtin_memcpy(e->comm, req->comm, sizeof(e->comm));
        __builtin_memcpy(e->cmd_type, req->cmd_type, sizeof(e->cmd_type));
        __builtin_memcpy(e->sql_cmd, req->sql_cmd, sizeof(e->sql_cmd));
        __builtin_memcpy(e->query, req->query, sizeof(e->query));
        __builtin_memcpy(e->db_name, req->db_name, sizeof(e->db_name));
        bpf_ringbuf_submit(e, 0);
    }

    return 1;
}

static __always_inline int process_sql_response(u64 pid_tgid, const char *comm, const char *buf_user, u32 len) {
    u32 pid = pid_tgid >> 32;
    if (!is_target_process(comm, pid)) return 0;

    struct sql_req_t *req = bpf_map_lookup_elem(&in_flight_queries, &pid_tgid);
    if (!req) return 0;

    len &= 0x1FF;
    if (len < 5) {
        return 0;
    }

    char resp_header[8] = {0};
    if (bpf_probe_read_user(resp_header, 7, buf_user) < 0) {
        return 0;
    }

    u8 resp_byte = (u8)resp_header[4];
    u16 status_code = 0;
    u32 affected_rows = 0;

    if (resp_byte == 0xFF) {
        // ERR Packet: [3 len][1 seq][1 0xFF][2 error_code_le][1 sqlstate_marker][5 sqlstate][error_msg...]
        u8 err_lo = (u8)resp_header[5];
        u8 err_hi = (u8)resp_header[6];
        status_code = (u16)err_lo | ((u16)err_hi << 8);
    } else if (resp_byte == 0x00) {
        // OK Packet
        status_code = 0;
        affected_rows = (u8)resp_header[5];
    } else if (resp_byte == 0xFE) {
        // EOF Packet
        status_code = 0;
    } else {
        // Result Set Packet Header (Column Count)
        status_code = 0;
    }

    u64 now = bpf_ktime_get_ns();
    u64 duration_us = (now - req->start_ns) / 1000;

    // 1. Emit completed response to sql_events ring buffer
    struct sql_event_t *e = bpf_ringbuf_reserve(&sql_events, sizeof(*e), 0);
    if (e) {
        e->pid = req->pid;
        e->tid = req->tid;
        e->saddr = req->saddr;
        e->daddr = req->daddr;
        e->sport = req->sport;
        e->dport = req->dport;
        e->duration_us = duration_us;
        e->status_code = status_code;
        e->affected_rows = affected_rows;
        e->tx_bytes = len;
        e->rx_bytes = req->rx_bytes;
        __builtin_memcpy(e->comm, req->comm, sizeof(e->comm));
        __builtin_memcpy(e->cmd_type, req->cmd_type, sizeof(e->cmd_type));
        __builtin_memcpy(e->sql_cmd, req->sql_cmd, sizeof(e->sql_cmd));
        __builtin_memcpy(e->query, req->query, sizeof(e->query));
        __builtin_memcpy(e->db_name, req->db_name, sizeof(e->db_name));
        bpf_ringbuf_submit(e, 0);
    }

    // 2. Deadlock, Lock Wait Timeout, or Rollback Detection
    if (status_code == 1213 || status_code == 1205 || status_code == 1062 || 
        (req->sql_cmd[0] == 'R' && req->sql_cmd[1] == 'O' && req->sql_cmd[2] == 'L')) {
        struct lock_event_t *le = bpf_ringbuf_reserve(&lock_events, sizeof(*le), 0);
        if (le) {
            le->pid = req->pid;
            le->saddr = req->saddr;
            le->error_code = status_code;
            le->duration_us = duration_us;
            __builtin_memcpy(le->query, req->query, sizeof(le->query));

            if (status_code == 1213) {
                __builtin_memcpy(le->event_type, "DEADLOCK", 9);
                __builtin_memcpy(le->message, "ER_LOCK_DEADLOCK (1213)", 24);
            } else if (status_code == 1205) {
                __builtin_memcpy(le->event_type, "LOCK_TIMEOUT", 13);
                __builtin_memcpy(le->message, "ER_LOCK_WAIT_TIMEOUT (1205)", 28);
            } else if (status_code == 1062) {
                __builtin_memcpy(le->event_type, "DUP_KEY", 8);
                __builtin_memcpy(le->message, "ER_DUP_ENTRY (1062)", 20);
            } else {
                __builtin_memcpy(le->event_type, "ROLLBACK", 9);
                __builtin_memcpy(le->message, "Transaction Rollback", 21);
            }

            bpf_ringbuf_submit(le, 0);
        }
    }

    bpf_map_delete_elem(&in_flight_queries, &pid_tgid);
    return 1;
}

// 1. Syscall Ingress Hooks (Requests)
SEC("tracepoint/syscalls/sys_enter_recvfrom")
int trace_sys_enter_recvfrom(struct trace_event_raw_sys_enter* ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    char comm[16];
    bpf_get_current_comm(comm, sizeof(comm));
    if (!is_target_process(comm, pid)) return 0;

    const char *buf = (const char *)ctx->args[1];
    bpf_map_update_elem(&recvfrom_args, &pid_tgid, &buf, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int trace_sys_exit_recvfrom(struct trace_event_raw_sys_exit* ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    long ret = ctx->ret;
    if (ret <= 0) return 0;

    const char **buf_ptr = bpf_map_lookup_elem(&recvfrom_args, &pid_tgid);
    if (!buf_ptr) return 0;
    const char *buf = *buf_ptr;
    bpf_map_delete_elem(&recvfrom_args, &pid_tgid);

    char comm[16];
    bpf_get_current_comm(comm, sizeof(comm));
    if (!process_sql_request(pid_tgid, comm, buf, (u32)ret)) {
        try_parse_handshake_response((u32)(pid_tgid >> 32), (u32)pid_tgid, buf, (u32)ret);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int trace_sys_enter_read(struct trace_event_raw_sys_enter* ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    char comm[16];
    bpf_get_current_comm(comm, sizeof(comm));
    if (!is_target_process(comm, pid)) return 0;

    const char *buf = (const char *)ctx->args[1];
    bpf_map_update_elem(&read_args, &pid_tgid, &buf, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int trace_sys_exit_read(struct trace_event_raw_sys_exit* ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    long ret = ctx->ret;
    if (ret <= 0) return 0;

    const char **buf_ptr = bpf_map_lookup_elem(&read_args, &pid_tgid);
    if (!buf_ptr) return 0;
    const char *buf = *buf_ptr;
    bpf_map_delete_elem(&read_args, &pid_tgid);

    char comm[16];
    bpf_get_current_comm(comm, sizeof(comm));
    if (!process_sql_request(pid_tgid, comm, buf, (u32)ret)) {
        try_parse_handshake_response((u32)(pid_tgid >> 32), (u32)pid_tgid, buf, (u32)ret);
    }
    return 0;
}

// 2. Syscall Egress Hooks (Responses & Logs)
SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_sys_sendto(struct trace_event_raw_sys_enter* ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    char comm[16];
    bpf_get_current_comm(comm, sizeof(comm));
    if (!is_target_process(comm, pid)) return 0;

    const char *buf = (const char *)ctx->args[1];
    u32 len = (u32)ctx->args[2];

    // 1. Try SQL request (e.g. client/proxy sending query via sendto)
    if (process_sql_request(pid_tgid, comm, buf, len)) {
        return 0;
    }

    // 2. Try SQL response (server responding via sendto)
    process_sql_response(pid_tgid, comm, buf, len);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int trace_sys_write(struct trace_event_raw_sys_enter* ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    char comm[16];
    bpf_get_current_comm(comm, sizeof(comm));
    if (!is_target_process(comm, pid)) return 0;

    int fd = (int)ctx->args[0];
    const char *buf = (const char *)ctx->args[1];
    u32 len = (u32)ctx->args[2];

    // 1. Try SQL request (e.g. client sending query via write)
    if (process_sql_request(pid_tgid, comm, buf, len)) {
        return 0;
    }

    // 2. Try SQL response (server responding via write)
    if (process_sql_response(pid_tgid, comm, buf, len)) {
        return 0;
    }

    len &= 0xFF;
    if (len < 10) return 0;

    struct log_event_t *le = bpf_ringbuf_reserve(&log_events, sizeof(*le), 0);
    if (!le) return 0;

    le->pid = pid;
    u32 read_bytes = len < 255 ? len : 255;
    bpf_probe_read_user(le->message, read_bytes, buf);
    le->message[read_bytes] = '\0';

    // MySQL log line signature detection:
    // 1) ISO/SQL timestamp: '2', '0', '2' (e.g. 2026-..., 2025-...)
    // 2) Severity tag: '[' (e.g. [Note], [Warning], [ERROR], [System])
    // 3) Process prefix: 'm', 'y', 's' (mysqld: ...) or 'm', 'a', 'r' (mariadbd: ...)
    // 4) Or standard stdout/stderr (fd == 1 || fd == 2) with printable ASCII
    int is_log = 0;
    if (le->message[0] == '2' && le->message[1] == '0' && (le->message[2] >= '2' && le->message[2] <= '3')) {
        is_log = 1;
    } else if (le->message[0] == '[') {
        is_log = 1;
    } else if (le->message[0] == 'm' && le->message[1] == 'y' && le->message[2] == 's') {
        is_log = 1;
    } else if (le->message[0] == 'm' && le->message[1] == 'a' && le->message[2] == 'r') {
        is_log = 1;
    } else if (fd == 1 || fd == 2) {
        if (le->message[0] >= 32 && le->message[0] <= 126) is_log = 1;
    }

    if (!is_log) {
        bpf_ringbuf_discard(le, 0);
        return 0;
    }

    if (fd == 2 || le->message[0] == 'E' || (le->message[1] == 'E' && le->message[2] == 'R')) {
        __builtin_memcpy(le->level, "ERROR", 6);
    } else if (le->message[1] == 'W' || le->message[1] == 'w' || (le->message[0] == 'W' && le->message[1] == 'A')) {
        __builtin_memcpy(le->level, "WARN", 5);
    } else {
        __builtin_memcpy(le->level, "INFO", 5);
    }

    bpf_ringbuf_submit(le, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_writev")
int trace_sys_writev(struct trace_event_raw_sys_enter* ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    char comm[16];
    bpf_get_current_comm(comm, sizeof(comm));
    if (!is_target_process(comm, pid)) return 0;

    int fd = (int)ctx->args[0];
    const struct iovec___local *iov_ptr = (const struct iovec___local *)ctx->args[1];
    unsigned long vlen = (unsigned long)ctx->args[2];

    if (!iov_ptr || vlen == 0) return 0;

    struct iovec___local iov;
    if (bpf_probe_read_user(&iov, sizeof(iov), iov_ptr) < 0) return 0;
    if (!iov.iov_base || iov.iov_len < 10) return 0;

    struct log_event_t *le = bpf_ringbuf_reserve(&log_events, sizeof(*le), 0);
    if (!le) return 0;

    le->pid = pid;
    u32 read_bytes = (u32)(iov.iov_len < 255 ? iov.iov_len : 255);
    read_bytes &= 0xFF;
    bpf_probe_read_user(le->message, read_bytes, iov.iov_base);
    le->message[read_bytes] = '\0';

    int is_log = 0;
    if (le->message[0] == '2' && le->message[1] == '0' && (le->message[2] >= '2' && le->message[2] <= '3')) {
        is_log = 1;
    } else if (le->message[0] == '[') {
        is_log = 1;
    } else if (le->message[0] == 'm' && le->message[1] == 'y' && le->message[2] == 's') {
        is_log = 1;
    } else if (le->message[0] == 'm' && le->message[1] == 'a' && le->message[2] == 'r') {
        is_log = 1;
    } else if (fd == 1 || fd == 2) {
        if (le->message[0] >= 32 && le->message[0] <= 126) is_log = 1;
    }

    if (!is_log) {
        bpf_ringbuf_discard(le, 0);
        return 0;
    }

    if (fd == 2 || le->message[0] == 'E' || (le->message[1] == 'E' && le->message[2] == 'R')) {
        __builtin_memcpy(le->level, "ERROR", 6);
    } else if (le->message[1] == 'W' || le->message[1] == 'w' || (le->message[0] == 'W' && le->message[1] == 'A')) {
        __builtin_memcpy(le->level, "WARN", 5);
    } else {
        __builtin_memcpy(le->level, "INFO", 5);
    }

    bpf_ringbuf_submit(le, 0);
    return 0;
}

// 3. TCP Sockets & Client IP Extraction
SEC("kprobe/tcp_recvmsg")
int kprobe_tcp_recvmsg(struct pt_regs *ctx) {
    struct sock___local *sk = (struct sock___local *)PT_REGS_PARM1(ctx);
    if (!sk) return 0;

    u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    u16 dport = __builtin_bswap16(BPF_CORE_READ(sk, __sk_common.skc_dport));
    u16 target_port = filter_port != 0 ? filter_port : 3306;

    if (sport != target_port && dport != target_port) {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);

    u32 client_ip = (dport == target_port) ? saddr : daddr;
    if (client_ip == 0 || (client_ip & 0x000000FF) == 127) {
        client_ip = (dport == target_port) ? daddr : saddr;
    }

    if (client_ip != 0 && (client_ip & 0x000000FF) != 127) {
        struct client_ip_t cip = { .ip = client_ip };
        bpf_map_update_elem(&proc_client_ip, &pid, &cip, BPF_ANY);
        u32 zero_key = 0;
        bpf_map_update_elem(&last_external_ip, &zero_key, &cip, BPF_ANY);
    }

    return 0;
}

SEC("kprobe/tcp_sendmsg")
int kprobe_tcp_sendmsg(struct pt_regs *ctx) {
    struct sock___local *sk = (struct sock___local *)PT_REGS_PARM1(ctx);
    if (!sk) return 0;

    u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    u16 dport = __builtin_bswap16(BPF_CORE_READ(sk, __sk_common.skc_dport));
    u16 target_port = filter_port != 0 ? filter_port : 3306;

    if (sport != target_port && dport != target_port) {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sql_req_t *req = bpf_map_lookup_elem(&in_flight_queries, &pid_tgid);
    if (req) {
        req->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        req->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        req->sport = sport;
        req->dport = dport;
    }

    return 0;
}

// 4. Block I/O Operations (InnoDB & Redo/Binlogs)
struct trace_event_raw_block_rq_completion___local {
    unsigned int nr_sector;
    char rwbs[8];
} __attribute__((preserve_access_index));

SEC("tracepoint/block/block_rq_issue")
int trace_block_rq_issue(void *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    char comm[16] = {0};
    bpf_get_current_comm(comm, sizeof(comm));
    if (!is_target_process(comm, pid)) return 0;

    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&io_start, &pid_tgid, &ts, BPF_ANY);
    return 0;
}

SEC("tracepoint/block/block_rq_complete")
int trace_block_rq_complete(struct trace_event_raw_block_rq_completion___local *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u64 *tsp = bpf_map_lookup_elem(&io_start, &pid_tgid);
    if (!tsp) return 0;

    u64 ts = *tsp;
    bpf_map_delete_elem(&io_start, &pid_tgid);

    char comm[16];
    bpf_get_current_comm(comm, sizeof(comm));
    if (!is_target_process(comm, pid)) return 0;

    u64 now = bpf_ktime_get_ns();
    u64 delta = (now - ts) / 1000;

    u32 nr_sector = 0;
    char rwbs[8] = {0};
    bpf_core_read(&nr_sector, sizeof(nr_sector), &ctx->nr_sector);
    bpf_core_read(&rwbs, sizeof(rwbs), &ctx->rwbs);

    u32 io_bytes = nr_sector > 0 ? (nr_sector * 512) : 4096;
    int is_write = (rwbs[0] == 'W' || rwbs[0] == 'w');

    struct io_event_t *e = bpf_ringbuf_reserve(&io_events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = pid_tgid >> 32;
    __builtin_memcpy(e->comm, comm, sizeof(e->comm));
    if (is_write) {
        __builtin_memcpy(e->rwflag, "WRITE", 6);
    } else {
        __builtin_memcpy(e->rwflag, "READ", 5);
    }
    e->bytes = io_bytes;
    e->latency_us = delta;

    bpf_ringbuf_submit(e, 0);

    // Accumulate into io_stats hash map
    struct mysql_io_key_t iokey = {0};
    bpf_get_current_comm(iokey.comm, sizeof(iokey.comm));
    struct io_stat_t *ios = bpf_map_lookup_elem(&io_stats, &iokey);
    if (ios) {
        if (is_write) {
            __sync_fetch_and_add(&ios->write_bytes, io_bytes);
        } else {
            __sync_fetch_and_add(&ios->read_bytes, io_bytes);
        }
    } else {
        struct io_stat_t new_ios = {0};
        if (is_write) {
            new_ios.write_bytes = io_bytes;
        } else {
            new_ios.read_bytes = io_bytes;
        }
        bpf_map_update_elem(&io_stats, &iokey, &new_ios, BPF_ANY);
    }

    return 0;
}

// 5. Worker Thread CPU Profiling
struct sched_stat_runtime_args {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    char comm[16];
    int pid;
    u64 runtime;
    u64 vruntime;
};

SEC("tracepoint/sched/sched_stat_runtime")
int trace_sched_stat_runtime(struct sched_stat_runtime_args *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    char comm[16];
    bpf_get_current_comm(comm, sizeof(comm));
    if (!is_target_process(comm, pid)) return 0;

    struct mysql_thread_key_t key = {0};
    struct task_struct___local *task = (struct task_struct___local *)bpf_get_current_task();
    struct mm_struct___local *mm = BPF_CORE_READ(task, mm);
    unsigned long arg_start = 0;
    if (mm) {
        arg_start = BPF_CORE_READ(mm, arg_start);
    }
    if (arg_start) {
        bpf_probe_read_user_str(key.title, sizeof(key.title), (void *)arg_start);
    } else {
        bpf_get_current_comm(key.title, sizeof(key.title));
    }

    u64 runtime = ctx->runtime;
    if (runtime == 0) runtime = 1000000;

    struct cpu_stat_t *cs = bpf_map_lookup_elem(&cpu_stats, &key);
    if (cs) {
        __sync_fetch_and_add(&cs->cpu_time_ns, runtime);
    } else {
        struct cpu_stat_t new_cs = {.cpu_time_ns = runtime};
        bpf_map_update_elem(&cpu_stats, &key, &new_cs, BPF_ANY);
    }

    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
