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

struct task_struct___local {
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

// Exported event schemas matching manifest.yaml
struct http_event_t {
    u32 pid;
    u32 ppid;
    u64 req_id;
    u64 parent_req_id;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    char method[8];
    char path[256];
    char host[64];
    char user_agent[32];
    char content_type[32];
    char trace_id[40];
    u16 status_code;
    u64 duration_us;
    u32 rx_bytes;
    u32 tx_bytes;
    char comm[16];
    char proto[8];
    char server_version[32];
    char req_payload[256];
    char resp_payload[256];
} __attribute__((packed));

struct slow_event_t {
    u32 pid;
    u32 ppid;
    u64 req_id;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    char method[8];
    char path[256];
    char host[64];
    u16 status_code;
    u64 duration_us;
    u32 tx_bytes;
    u32 rx_bytes;
    char comm[16];
    char proto[8];
    char server_version[32];
    char req_payload[256];
    char resp_payload[256];
} __attribute__((packed));

struct error_event_t {
    u32 pid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    char method[8];
    char path[256];
    char host[64];
    u16 status_code;
    u64 duration_us;
    char error_msg[64];
    char comm[16];
} __attribute__((packed));

struct log_event_t {
    u32 pid;
    char comm[16];
    char level[8];
    char message[256];
} __attribute__((packed));

struct cpu_stat_key_t {
    char title[64];
};

struct cpu_stat_t {
    u64 cpu_time_ns;
};

struct host_stat_key_t {
    char host[64];
};

struct host_stat_t {
    u64 req_count;
};

struct in_flight_req_t {
    u64 start_ns;
    u64 req_id;
    u64 parent_req_id;
    u32 pid;
    u32 ppid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    char method[8];
    char path[256];
    char host[64];
    char user_agent[32];
    char content_type[32];
    char trace_id[40];
    char comm[16];
    char proto[8];
    char req_payload[256];
    u32 tx_bytes;
};

struct scratch_buf_t {
    char buf[1024];
    struct in_flight_req_t req;
};

// ---------------------------------------------------------------------------------
// Maps
// ---------------------------------------------------------------------------------

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} http_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} slow_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} error_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} log_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct cpu_stat_key_t);
    __type(value, struct cpu_stat_t);
} cpu_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct host_stat_key_t);
    __type(value, struct host_stat_t);
} host_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64); // pid_tgid
    __type(value, struct in_flight_req_t);
} in_flight_reqs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32); // pid
    __type(value, u64); // active req_id
} active_spans SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct scratch_buf_t);
} req_scratch SEC(".maps");

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

// ---------------------------------------------------------------------------------
// Configurable Runtime Variables
// ---------------------------------------------------------------------------------

volatile const u16 filter_port = 0;
volatile const u32 filter_pid = 0;
volatile const u64 slow_req_us = 50000; // 50ms default

// ---------------------------------------------------------------------------------
// Helper Functions & Protocol Parsers (Zero-Loop Architecture per Finding #67 & #72)
// ---------------------------------------------------------------------------------

static __always_inline int is_web_comm(const char *comm) {
    if (comm[0] == 'n' && comm[1] == 'g' && comm[2] == 'i' && comm[3] == 'n') return 1; // nginx
    if (comm[0] == 'n' && comm[1] == 'o' && comm[2] == 'd' && comm[3] == 'e') return 1; // node
    if (comm[0] == 'g' && comm[1] == 'u' && comm[2] == 'n' && comm[3] == 'i') return 1; // gunicorn
    if (comm[0] == 'u' && comm[1] == 'v' && comm[2] == 'i' && comm[3] == 'c') return 1; // uvicorn
    if (comm[0] == 'p' && comm[1] == 'h' && comm[2] == 'p') return 1; // php-fpm
    if (comm[0] == 'c' && comm[1] == 'a' && comm[2] == 'd' && comm[3] == 'd') return 1; // caddy
    if (comm[0] == 'e' && comm[1] == 'n' && comm[2] == 'v' && comm[3] == 'o') return 1; // envoy
    if (comm[0] == 't' && comm[1] == 'r' && comm[2] == 'a' && comm[3] == 'e') return 1; // traefik
    if (comm[0] == 'a' && comm[1] == 'p' && comm[2] == 'a' && comm[3] == 'c') return 1; // apache2
    if (comm[0] == 'h' && comm[1] == 't' && comm[2] == 't' && comm[3] == 'p') return 1; // httpd
    if (comm[0] == 'p' && comm[1] == 'y' && comm[2] == 't' && comm[3] == 'h') return 1; // python
    if (comm[0] == 'g' && comm[1] == 'o') return 1; // go / golang
    if (comm[0] == 'j' && comm[1] == 'a' && comm[2] == 'v' && comm[3] == 'a') return 1; // java
    if (comm[0] == 'r' && comm[1] == 'u' && comm[2] == 'b' && comm[3] == 'y') return 1; // ruby
    return 0;
}

static __always_inline int is_eprobe_comm(void) {
    char comm[16] = {0};
    bpf_get_current_comm(&comm, sizeof(comm));
    return comm[0] == 'e' && comm[1] == 'p' && comm[2] == 'r' &&
           comm[3] == 'o' && comm[4] == 'b' && comm[5] == 'e';
}

static __always_inline int is_target_process(const char *comm, u32 pid) {
    if (comm[0] == 'e' && comm[1] == 'p' && comm[2] == 'r' &&
        comm[3] == 'o' && comm[4] == 'b' && comm[5] == 'e') {
        return 0;
    }
    if (filter_pid != 0 && pid == filter_pid) return 1;
    if (is_web_comm(comm)) return 1;

    struct task_struct___local *task = (struct task_struct___local *)bpf_get_current_task();
    if (task) {
        struct task_struct___local *leader = BPF_CORE_READ(task, group_leader);
        if (leader) {
            char leader_comm[16] = {0};
            bpf_probe_read_kernel_str(leader_comm, sizeof(leader_comm), leader->comm);
            if (is_web_comm(leader_comm)) return 1;
        }
    }
    return 0;
}

// Fast O(1) Zero-Loop HTTP method detector
static __always_inline int parse_http_method(const char *buf, char *method_out) {
    if (buf[0] == 'G' && buf[1] == 'E' && buf[2] == 'T' && buf[3] == ' ') {
        __builtin_memcpy(method_out, "GET", 4);
        return 4;
    }
    if (buf[0] == 'P' && buf[1] == 'O' && buf[2] == 'S' && buf[3] == 'T' && buf[4] == ' ') {
        __builtin_memcpy(method_out, "POST", 5);
        return 5;
    }
    if (buf[0] == 'P' && buf[1] == 'U' && buf[2] == 'T' && buf[3] == ' ') {
        __builtin_memcpy(method_out, "PUT", 4);
        return 4;
    }
    if (buf[0] == 'D' && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'E' && buf[4] == 'T' && buf[5] == ' ') {
        __builtin_memcpy(method_out, "DELETE", 7);
        return 7;
    }
    if (buf[0] == 'P' && buf[1] == 'A' && buf[2] == 'T' && buf[3] == 'C' && buf[4] == 'H' && buf[5] == ' ') {
        __builtin_memcpy(method_out, "PATCH", 6);
        return 6;
    }
    if (buf[0] == 'H' && buf[1] == 'E' && buf[2] == 'A' && buf[3] == 'D' && buf[4] == ' ') {
        __builtin_memcpy(method_out, "HEAD", 5);
        return 5;
    }
    if (buf[0] == 'O' && buf[1] == 'P' && buf[2] == 'T' && buf[3] == 'I' && buf[4] == 'O' && buf[5] == 'N' && buf[6] == 'S' && buf[7] == ' ') {
        __builtin_memcpy(method_out, "OPTIONS", 8);
        return 8;
    }
    if (buf[0] == 'C' && buf[1] == 'O' && buf[2] == 'N' && buf[3] == 'N' && buf[4] == 'E' && buf[5] == 'C' && buf[6] == 'T' && buf[7] == ' ') {
        __builtin_memcpy(method_out, "CONNECT", 8);
        return 8;
    }
    return 0;
}

// Fast O(1) Zero-Loop HTTP status code parser
static __always_inline u16 parse_http_status(const char *buf) {
    if (buf[0] == 'H' && buf[1] == 'T' && buf[2] == 'T' && buf[3] == 'P' && buf[4] == '/' && buf[5] == '1' && buf[6] == '.') {
        char d0 = buf[9];
        char d1 = buf[10];
        char d2 = buf[11];
        if (d0 >= '0' && d0 <= '9' && d1 >= '0' && d1 <= '9' && d2 >= '0' && d2 <= '9') {
            return (u16)((d0 - '0') * 100 + (d1 - '0') * 10 + (d2 - '0'));
        }
    }
    return 0;
}

// Status message generator for errors
static __always_inline void get_status_msg(u16 code, char *msg_out) {
    if (code == 400) { __builtin_memcpy(msg_out, "Bad Request", 12); return; }
    if (code == 401) { __builtin_memcpy(msg_out, "Unauthorized", 13); return; }
    if (code == 403) { __builtin_memcpy(msg_out, "Forbidden", 10); return; }
    if (code == 404) { __builtin_memcpy(msg_out, "Not Found", 10); return; }
    if (code == 405) { __builtin_memcpy(msg_out, "Method Not Allowed", 19); return; }
    if (code == 422) { __builtin_memcpy(msg_out, "Unprocessable Entity", 21); return; }
    if (code == 429) { __builtin_memcpy(msg_out, "Too Many Requests", 18); return; }
    if (code == 500) { __builtin_memcpy(msg_out, "Internal Server Error", 22); return; }
    if (code == 502) { __builtin_memcpy(msg_out, "Bad Gateway", 12); return; }
    if (code == 503) { __builtin_memcpy(msg_out, "Service Unavailable", 20); return; }
    if (code == 504) { __builtin_memcpy(msg_out, "Gateway Timeout", 16); return; }
    __builtin_memcpy(msg_out, "HTTP Error", 11);
}

// ---------------------------------------------------------------------------------
// Request Processor (Zero-Loop Linear Execution per Finding #72 & #88)
// ---------------------------------------------------------------------------------

static __always_inline int process_http_request(u32 pid, u32 ppid, const char *comm, u32 saddr, u32 daddr, u16 sport, u16 dport, const char *buf_user, u32 len, const char *method, int path_offset) {
    u32 zero = 0;
    struct scratch_buf_t *scratch = bpf_map_lookup_elem(&req_scratch, &zero);
    if (!scratch) return 0;

    bpf_probe_read_user(scratch->buf, sizeof(scratch->buf), buf_user);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct in_flight_req_t *req = &scratch->req;
    __builtin_memset(req, 0, sizeof(*req));

    u64 now = bpf_ktime_get_ns();
    req->req_id = ((u64)pid << 32) | (u32)(now & 0xFFFFFFFF);

    u64 *parent_span = bpf_map_lookup_elem(&active_spans, &ppid);
    if (parent_span) {
        req->parent_req_id = *parent_span;
    } else {
        req->parent_req_id = (u64)ppid;
    }

    req->pid = pid;
    req->ppid = ppid;
    req->saddr = saddr;
    req->daddr = daddr;
    req->sport = sport;
    req->dport = dport;
    req->start_ns = now;
    req->tx_bytes = len;
    __builtin_memcpy(req->comm, comm, sizeof(req->comm));
    __builtin_memcpy(req->method, method, sizeof(req->method));
    __builtin_memcpy(req->proto, "HTTP/1.1", 8);
    __builtin_memcpy(req->host, "localhost", 10);

    // 1. Read URL Path (bounded space-clamp runs after Host: loop to avoid nested verifier state multiplication)
    path_offset &= 0x0F;
    bpf_probe_read_user_str(req->path, sizeof(req->path), buf_user + path_offset);

    // 2. Bounded Host: header extraction (unroll disabled)
    #pragma clang loop unroll(disable)
    for (int i = 0; i < 48; i++) {
        char c = scratch->buf[i & 0x7F];
        if (c == '\0') break;
        if ((c == 'H' || c == 'h') &&
            (scratch->buf[(i + 1) & 0x7F] == 'o' || scratch->buf[(i + 1) & 0x7F] == 'O') &&
            (scratch->buf[(i + 2) & 0x7F] == 's' || scratch->buf[(i + 2) & 0x7F] == 'S') &&
            (scratch->buf[(i + 3) & 0x7F] == 't' || scratch->buf[(i + 3) & 0x7F] == 'T') &&
            scratch->buf[(i + 4) & 0x7F] == ':') {
            int v = i + 5;
            if (scratch->buf[v & 0x7F] == ' ') v++;
            #pragma clang loop unroll(disable)
            for (int k = 0; k < 31; k++) {
                char ch = scratch->buf[(v + k) & 0x7F];
                if (ch == '\r' || ch == '\n' || ch == '\0' || ch == ' ' || ch == ':') {
                    req->host[k & 0x1F] = '\0';
                    break;
                }
                req->host[k & 0x1F] = ch;
            }
            break;
        }
    }

    // 3. Raw request payload capture
    u32 rlen = (len < sizeof(req->req_payload)) ? len : sizeof(req->req_payload) - 1;
    rlen &= 0xFF;
    bpf_probe_read_user(req->req_payload, sizeof(req->req_payload), buf_user);
    req->req_payload[rlen] = '\0';

    // 4. Update host_stats hash map
    struct host_stat_key_t hkey = {0};
    __builtin_memcpy(hkey.host, req->host, sizeof(hkey.host));
    struct host_stat_t *hval = bpf_map_lookup_elem(&host_stats, &hkey);
    if (hval) {
        __sync_fetch_and_add(&hval->req_count, 1);
    } else {
        struct host_stat_t init_hval = { .req_count = 1 };
        bpf_map_update_elem(&host_stats, &hkey, &init_hval, BPF_ANY);
    }

    // 5. Clamp URL Path up to 255 chars (linear wrt downstream straight-line map updates)
    #pragma clang loop unroll(disable)
    for (int k = 0; k < 255; k++) {
        int idx = k & 0xFF;
        char c = req->path[idx];
        if (c == ' ' || c == '\r' || c == '\n' || c == '\0') {
            req->path[idx] = '\0';
            break;
        }
    }
    req->path[255] = '\0';

    bpf_map_update_elem(&in_flight_reqs, &pid_tgid, req, BPF_ANY);
    bpf_map_update_elem(&active_spans, &pid, &req->req_id, BPF_ANY);
    return 1;
}

// ---------------------------------------------------------------------------------
// Response Processor (Clean Isolated Ringbuf Emission)
// ---------------------------------------------------------------------------------

static __always_inline int process_http_response(u32 pid, u32 ppid, const char *comm, u32 saddr, u32 daddr, u16 sport, u16 dport, const char *buf_user, u32 len, u16 status_code, const char *body_user, u32 body_len) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct in_flight_req_t *req = bpf_map_lookup_elem(&in_flight_reqs, &pid_tgid);
    u64 now = bpf_ktime_get_ns();
    u64 duration_us = 0;

    struct http_event_t *e = bpf_ringbuf_reserve(&http_events, sizeof(*e), 0);
    if (!e) {
        bpf_map_delete_elem(&in_flight_reqs, &pid_tgid);
        bpf_map_delete_elem(&active_spans, &pid);
        return 0;
    }

    // Read scratch buffer for response inspection
    u32 zero = 0;
    struct scratch_buf_t *scratch = bpf_map_lookup_elem(&req_scratch, &zero);
    if (scratch && buf_user) {
        bpf_probe_read_user(scratch->buf, sizeof(scratch->buf), buf_user);
    }

    // Bounded Server: header scanner (unroll disabled)
    char server_ver[32] = {0};
    __builtin_memcpy(server_ver, "HTTP-Server", 12);
    if (scratch) {
        #pragma clang loop unroll(disable)
        for (int i = 0; i < 48; i++) {
            char c = scratch->buf[i & 0x7F];
            if (c == '\0') break;
            if ((c == 'S' || c == 's') &&
                scratch->buf[(i + 6) & 0x7F] == ':') {
                int v = i + 7;
                if (scratch->buf[v & 0x7F] == ' ') v++;
                #pragma clang loop unroll(disable)
                for (int k = 0; k < 31; k++) {
                    char ch = scratch->buf[(v + k) & 0x7F];
                    if (ch == '\r' || ch == '\n' || ch == '\0') {
                        server_ver[k & 0x1F] = '\0';
                        break;
                    }
                    server_ver[k & 0x1F] = ch;
                }
                break;
            }
        }
    }

    // Response body capture
    const char *resp_src = (body_user && body_len > 0) ? body_user : buf_user;
    u32 rlen = (body_user && body_len > 0) ? body_len : len;
    u32 blen = (rlen < sizeof(e->resp_payload)) ? rlen : sizeof(e->resp_payload) - 1;
    blen &= 0xFF;
    if (resp_src) {
        bpf_probe_read_user(e->resp_payload, sizeof(e->resp_payload), resp_src);
        e->resp_payload[blen] = '\0';
    }

    if (req) {
        duration_us = (now - req->start_ns) / 1000;
        u32 eff_saddr = req->saddr ? req->saddr : saddr;
        u32 eff_daddr = req->daddr ? req->daddr : daddr;
        u16 eff_sport = req->sport ? req->sport : sport;
        u16 eff_dport = req->dport ? req->dport : dport;

        e->pid = req->pid;
        e->ppid = req->ppid;
        e->req_id = req->req_id;
        e->parent_req_id = req->parent_req_id;
        e->saddr = eff_saddr;
        e->daddr = eff_daddr;
        e->sport = eff_sport;
        e->dport = eff_dport;
        e->duration_us = duration_us;
        e->tx_bytes = req->tx_bytes;
        e->rx_bytes = len + body_len;
        e->status_code = status_code;
        __builtin_memcpy(e->method, req->method, sizeof(e->method));
        __builtin_memcpy(e->path, req->path, sizeof(e->path));
        __builtin_memcpy(e->host, req->host, sizeof(e->host));
        __builtin_memcpy(e->user_agent, req->user_agent, sizeof(e->user_agent));
        __builtin_memcpy(e->content_type, req->content_type, sizeof(e->content_type));
        __builtin_memcpy(e->trace_id, req->trace_id, sizeof(e->trace_id));
        __builtin_memcpy(e->comm, req->comm, sizeof(e->comm));
        __builtin_memcpy(e->proto, "HTTP/1.1", 8);
        __builtin_memcpy(e->server_version, server_ver, sizeof(e->server_version));
        __builtin_memcpy(e->req_payload, req->req_payload, sizeof(e->req_payload));

        bpf_ringbuf_submit(e, 0);

        // Alert streams
        if (duration_us >= slow_req_us) {
            struct slow_event_t *se = bpf_ringbuf_reserve(&slow_events, sizeof(*se), 0);
            if (se) {
                se->pid = req->pid;
                se->ppid = req->ppid;
                se->req_id = req->req_id;
                se->saddr = eff_saddr;
                se->daddr = eff_daddr;
                se->sport = eff_sport;
                se->dport = eff_dport;
                se->status_code = status_code;
                se->duration_us = duration_us;
                se->tx_bytes = req->tx_bytes;
                se->rx_bytes = len + body_len;
                __builtin_memcpy(se->method, req->method, sizeof(se->method));
                __builtin_memcpy(se->path, req->path, sizeof(se->path));
                __builtin_memcpy(se->host, req->host, sizeof(se->host));
                __builtin_memcpy(se->comm, req->comm, sizeof(se->comm));
                __builtin_memcpy(se->proto, "HTTP/1.1", 8);
                __builtin_memcpy(se->server_version, server_ver, sizeof(se->server_version));
                __builtin_memcpy(se->req_payload, req->req_payload, sizeof(se->req_payload));
                if (resp_src) {
                    bpf_probe_read_user(se->resp_payload, sizeof(se->resp_payload), resp_src);
                    se->resp_payload[blen] = '\0';
                }
                bpf_ringbuf_submit(se, 0);
            }
        }

        if (status_code >= 400) {
            struct error_event_t *ee = bpf_ringbuf_reserve(&error_events, sizeof(*ee), 0);
            if (ee) {
                ee->pid = req->pid;
                ee->saddr = eff_saddr;
                ee->daddr = eff_daddr;
                ee->sport = eff_sport;
                ee->dport = eff_dport;
                ee->status_code = status_code;
                ee->duration_us = duration_us;
                __builtin_memcpy(ee->method, req->method, sizeof(ee->method));
                __builtin_memcpy(ee->path, req->path, sizeof(ee->path));
                __builtin_memcpy(ee->host, req->host, sizeof(ee->host));
                __builtin_memcpy(ee->comm, req->comm, sizeof(ee->comm));
                get_status_msg(status_code, ee->error_msg);
                bpf_ringbuf_submit(ee, 0);
            }
        }

        bpf_map_delete_elem(&in_flight_reqs, &pid_tgid);
        bpf_map_delete_elem(&active_spans, &pid);
        return 1;
    }

    // Direct response without matched in-flight request
    e->pid = pid;
    e->ppid = ppid;
    e->req_id = ((u64)pid << 32) | (u32)(now & 0xFFFFFFFF);
    e->parent_req_id = (u64)ppid;
    e->saddr = saddr;
    e->daddr = daddr;
    e->sport = sport;
    e->dport = dport;
    e->duration_us = 0;
    e->tx_bytes = 0;
    e->rx_bytes = len + body_len;
    e->status_code = status_code;
    __builtin_memcpy(e->method, "RESP", 5);
    __builtin_memcpy(e->path, "/", 2);
    __builtin_memcpy(e->host, "localhost", 10);
    __builtin_memcpy(e->comm, comm, 16);
    __builtin_memcpy(e->proto, "HTTP/1.1", 8);
    __builtin_memcpy(e->server_version, server_ver, sizeof(e->server_version));
    bpf_ringbuf_submit(e, 0);

    return 1;
}

// ---------------------------------------------------------------------------------
// Attach Points
// ---------------------------------------------------------------------------------

// ---------------------------------------------------------------------------------
// Attach Points
// ---------------------------------------------------------------------------------

SEC("kprobe/tcp_sendmsg")
int kprobe_tcp_sendmsg(struct pt_regs *ctx) {
    struct sock___local *sk = (struct sock___local *)PT_REGS_PARM1(ctx);
    if (!sk) return 0;

    u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    u16 dport = __builtin_bswap16(BPF_CORE_READ(sk, __sk_common.skc_dport));

    if (filter_port != 0 && sport != filter_port && dport != filter_port) {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (filter_pid != 0 && pid != filter_pid) {
        return 0;
    }

    u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);

    struct in_flight_req_t *req = bpf_map_lookup_elem(&in_flight_reqs, &pid_tgid);
    if (req) {
        req->saddr = saddr;
        req->daddr = daddr;
        req->sport = sport;
        req->dport = dport;
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int trace_sys_write(struct trace_event_raw_sys_enter* ctx) {
    if (is_eprobe_comm()) return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (filter_pid != 0 && pid != filter_pid) return 0;

    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    u32 fd = (u32)ctx->args[0];
    const char *buf = (const char *)ctx->args[1];
    u32 len = (u32)ctx->args[2];
    len &= 0x1FF;

    if (fd == 2 && is_target_process(comm, pid) && len >= 5) {
        len &= 0xFF;
        char first_ch = 0;
        bpf_probe_read_user(&first_ch, 1, buf);
        if (first_ch != '-' && first_ch != '\n' && first_ch != '\r' && first_ch != ' ') {
            struct log_event_t *log = bpf_ringbuf_reserve(&log_events, sizeof(*log), 0);
            if (log) {
                log->pid = pid;
                __builtin_memcpy(log->comm, comm, sizeof(log->comm));
                __builtin_memcpy(log->level, "WARN", 5);
                bpf_probe_read_user_str(log->message, sizeof(log->message), buf);
                bpf_ringbuf_submit(log, 0);
            }
        }
    }

    if (fd <= 2 || len < 8) return 0;

    char hdr16[16] = {0};
    bpf_probe_read_user(hdr16, sizeof(hdr16), buf);

    char method[8] = {0};
    int path_offset = parse_http_method(hdr16, method);
    u16 status_code = 0;
    if (path_offset <= 0) {
        status_code = parse_http_status(hdr16);
        if (status_code == 0) return 0;
    }

    struct task_struct___local *task = (struct task_struct___local *)bpf_get_current_task();
    struct task_struct___local *parent = BPF_CORE_READ(task, real_parent);
    u32 ppid = BPF_CORE_READ(parent, pid);

    if (status_code > 0) {
        return process_http_response(pid, ppid, comm, 0, 0, 0, 0, buf, len, status_code, NULL, 0);
    }
    if (path_offset > 0) {
        return process_http_request(pid, ppid, comm, 0, 0, 0, 0, buf, len, method, path_offset);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_writev")
int trace_sys_writev(struct trace_event_raw_sys_enter* ctx) {
    if (is_eprobe_comm()) return 0;

    u32 fd = (u32)ctx->args[0];
    if (fd <= 2) return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (filter_pid != 0 && pid != filter_pid) return 0;

    const struct iovec___local *iov = (const struct iovec___local *)ctx->args[1];
    unsigned long vlen = ctx->args[2];
    vlen &= 0x07;
    if (!iov || vlen == 0) return 0;

    void *base0 = NULL;
    unsigned long len0 = 0;
    bpf_probe_read_user(&base0, sizeof(base0), &iov[0].iov_base);
    bpf_probe_read_user(&len0, sizeof(len0), &iov[0].iov_len);
    len0 &= 0x1FF;
    if (!base0 || len0 < 8) return 0;

    char hdr16[16] = {0};
    bpf_probe_read_user(hdr16, sizeof(hdr16), base0);

    u16 status_code = parse_http_status(hdr16);
    if (status_code == 0) return 0;

    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    struct task_struct___local *task = (struct task_struct___local *)bpf_get_current_task();
    struct task_struct___local *parent = BPF_CORE_READ(task, real_parent);
    u32 ppid = BPF_CORE_READ(parent, pid);

    void *base1 = NULL;
    unsigned long len1 = 0;
    if (vlen >= 2) {
        bpf_probe_read_user(&base1, sizeof(base1), &iov[1].iov_base);
        bpf_probe_read_user(&len1, sizeof(len1), &iov[1].iov_len);
        len1 &= 0x1FF;
    }
    return process_http_response(pid, ppid, comm, 0, 0, 0, 0, (const char *)base0, (u32)len0, status_code, (const char *)base1, (u32)len1);
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_sys_sendto(struct trace_event_raw_sys_enter* ctx) {
    if (is_eprobe_comm()) return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (filter_pid != 0 && pid != filter_pid) return 0;

    const char *buf = (const char *)ctx->args[1];
    u32 len = (u32)ctx->args[2];
    len &= 0x1FF;
    if (len < 8) return 0;

    char hdr16[16] = {0};
    bpf_probe_read_user(hdr16, sizeof(hdr16), buf);

    char method[8] = {0};
    int path_offset = parse_http_method(hdr16, method);
    u16 status_code = 0;
    if (path_offset <= 0) {
        status_code = parse_http_status(hdr16);
        if (status_code == 0) return 0;
    }

    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    struct task_struct___local *task = (struct task_struct___local *)bpf_get_current_task();
    struct task_struct___local *parent = BPF_CORE_READ(task, real_parent);
    u32 ppid = BPF_CORE_READ(parent, pid);

    if (status_code > 0) {
        return process_http_response(pid, ppid, comm, 0, 0, 0, 0, buf, len, status_code, NULL, 0);
    }
    if (path_offset > 0) {
        return process_http_request(pid, ppid, comm, 0, 0, 0, 0, buf, len, method, path_offset);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int trace_sys_enter_read(struct trace_event_raw_sys_enter* ctx) {
    if (is_eprobe_comm()) return 0;

    u32 fd = (u32)ctx->args[0];
    if (fd <= 2) return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    if (filter_pid != 0 && pid != filter_pid) return 0;

    const char *buf = (const char *)ctx->args[1];
    bpf_map_update_elem(&read_args, &pid_tgid, &buf, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int trace_sys_exit_read(struct trace_event_raw_sys_exit* ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (filter_pid != 0 && pid != filter_pid) {
        bpf_map_delete_elem(&read_args, &pid_tgid);
        return 0;
    }

    const char **buf_ptr = bpf_map_lookup_elem(&read_args, &pid_tgid);
    if (!buf_ptr) return 0;
    const char *buf = *buf_ptr;
    bpf_map_delete_elem(&read_args, &pid_tgid);

    long ret = ctx->ret;
    if (ret <= 0) return 0;

    ret &= 0x1FF;
    if (ret < 8) return 0;

    char hdr16[16] = {0};
    bpf_probe_read_user(hdr16, sizeof(hdr16), buf);

    char method[8] = {0};
    int path_offset = parse_http_method(hdr16, method);
    u16 status_code = 0;
    if (path_offset <= 0) {
        status_code = parse_http_status(hdr16);
        if (status_code == 0) return 0;
    }

    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    struct task_struct___local *task = (struct task_struct___local *)bpf_get_current_task();
    struct task_struct___local *parent = BPF_CORE_READ(task, real_parent);
    u32 ppid = BPF_CORE_READ(parent, pid);

    if (path_offset > 0) {
        return process_http_request(pid, ppid, comm, 0, 0, 0, 0, buf, (u32)ret, method, path_offset);
    }
    if (status_code > 0) {
        return process_http_response(pid, ppid, comm, 0, 0, 0, 0, buf, (u32)ret, status_code, NULL, 0);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int trace_sys_enter_recvfrom(struct trace_event_raw_sys_enter* ctx) {
    if (is_eprobe_comm()) return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    if (filter_pid != 0 && pid != filter_pid) return 0;

    const char *buf = (const char *)ctx->args[1];
    bpf_map_update_elem(&recvfrom_args, &pid_tgid, &buf, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int trace_sys_exit_recvfrom(struct trace_event_raw_sys_exit* ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (filter_pid != 0 && pid != filter_pid) {
        bpf_map_delete_elem(&recvfrom_args, &pid_tgid);
        return 0;
    }

    const char **buf_ptr = bpf_map_lookup_elem(&recvfrom_args, &pid_tgid);
    if (!buf_ptr) return 0;
    const char *buf = *buf_ptr;
    bpf_map_delete_elem(&recvfrom_args, &pid_tgid);

    long ret = ctx->ret;
    if (ret <= 0) return 0;

    ret &= 0x1FF;
    if (ret < 8) return 0;

    char hdr16[16] = {0};
    bpf_probe_read_user(hdr16, sizeof(hdr16), buf);

    char method[8] = {0};
    int path_offset = parse_http_method(hdr16, method);
    u16 status_code = 0;
    if (path_offset <= 0) {
        status_code = parse_http_status(hdr16);
        if (status_code == 0) return 0;
    }

    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    struct task_struct___local *task = (struct task_struct___local *)bpf_get_current_task();
    struct task_struct___local *parent = BPF_CORE_READ(task, real_parent);
    u32 ppid = BPF_CORE_READ(parent, pid);

    if (path_offset > 0) {
        return process_http_request(pid, ppid, comm, 0, 0, 0, 0, buf, (u32)ret, method, path_offset);
    }
    if (status_code > 0) {
        return process_http_response(pid, ppid, comm, 0, 0, 0, 0, buf, (u32)ret, status_code, NULL, 0);
    }
    return 0;
}

struct trace_event_raw_sched_stat_runtime___local {
    u64 runtime;
} __attribute__((preserve_access_index));

// Track web worker CPU utilization
SEC("tracepoint/sched/sched_stat_runtime")
int trace_sched_stat_runtime(struct trace_event_raw_sched_stat_runtime___local *ctx) {
    char comm[16] = {0};
    bpf_get_current_comm(&comm, sizeof(comm));

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (!is_target_process(comm, pid)) {
        return 0;
    }

    struct cpu_stat_key_t key = {0};
    bpf_get_current_comm(key.title, sizeof(key.title));

    u64 runtime = 0;
    bpf_core_read(&runtime, sizeof(runtime), &ctx->runtime);
    struct cpu_stat_t *stat = bpf_map_lookup_elem(&cpu_stats, &key);
    if (stat) {
        __sync_fetch_and_add(&stat->cpu_time_ns, runtime);
    } else {
        struct cpu_stat_t new_stat = { .cpu_time_ns = runtime };
        bpf_map_update_elem(&cpu_stats, &key, &new_stat, BPF_ANY);
    }

    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
