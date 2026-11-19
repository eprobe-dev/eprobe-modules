// SPDX-License-Identifier: GPL-2.0-only OR MIT
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/eprobe_cgroup.h>

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

// CO-RE task struct for cgroup traversal
struct task_struct___local {
    struct task_struct___local *group_leader;
    struct task_struct___local *real_parent;
    u32 tgid;
    u32 pid;
    char comm[16];
} __attribute__((preserve_access_index));

// Exported event schemas matching manifest.yaml
struct tls_event_t {
    u32 pid;
    u32 ppid;
    u32 tid;
    char comm[16];
    char container_id[13];
    char role[8];
    char method[8];
    char path[256];
    char host[64];
    u16 status_code;
    u64 duration_us;
    u32 req_len;
    u32 resp_len;
    char req_payload[256];
    char resp_payload[256];
} __attribute__((packed));

struct host_key_t {
    char host[64];
};

struct host_stat_t {
    u64 req_count;
};

struct status_key_t {
    u32 status_code;
};

struct status_stat_t {
    u64 count;
};

struct in_flight_tls_t {
    u64 start_ns;
    u32 pid;
    u32 ppid;
    u32 tid;
    char comm[16];
    char container_id[13];
    char role[8];
    char method[8];
    char path[256];
    char host[64];
    char req_payload[256];
    u32 req_len;
};

struct host_val_t {
    char host[64];
};

struct active_read_t {
    const char *buf;
    u64 ts;
    const unsigned long *readbytes_ptr;
    u8 is_caller_ex;
    u8 in_read;
    u64 ssl_ptr;
};

struct scratch_t {
    char buf[512];
    struct in_flight_tls_t inflight;
};

// ---------------------------------------------------------------------------------
// Maps
// ---------------------------------------------------------------------------------

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} tls_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct host_key_t);
    __type(value, struct host_stat_t);
} host_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, struct status_key_t);
    __type(value, struct status_stat_t);
} status_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64); // pid_tgid
    __type(value, struct in_flight_tls_t);
} inflight_reqs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64); // pid_tgid
    __type(value, struct active_read_t);
} active_reads SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64); // pid_tgid
    __type(value, u8);
} active_writes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64); // ssl_ptr
    __type(value, struct host_val_t);
} ssl_hosts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32); // pid
    __type(value, struct host_val_t);
} pid_hosts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct scratch_t);
} scratch_map SEC(".maps");

// ---------------------------------------------------------------------------------
// Variables (rewritable by eprobe-cli)
// ---------------------------------------------------------------------------------
volatile const u16 filter_port = 0;
volatile const u32 filter_pid = 0;
volatile const u8 filter_errors_only = 0;
volatile const u64 slow_threshold_us = 0;

// ---------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------

static __always_inline int is_eprobe_comm(const char *comm) {
    if (comm[0] == 'e' && comm[1] == 'p' && comm[2] == 'r' && comm[3] == 'o' && comm[4] == 'b' && comm[5] == 'e') {
        return 1;
    }
    return 0;
}

static __always_inline void copy_str(char *dst, const char *src, int max_len) {
    #pragma clang loop unroll(full)
    for (int i = 0; i < max_len; i++) {
        dst[i] = src[i];
        if (src[i] == '\0')
            break;
    }
}

static __always_inline void get_container_id(char *cid, u32 len) {
    #pragma clang loop unroll(full)
    for (int i = 0; i < 13; i++) {
        cid[i] = '\0';
    }
    if (!parse_container_id(cid)) {
        cid[0] = '-';
        cid[1] = '\0';
    }
}

// Single-pass linear HTTP parser
static __always_inline int parse_http_method(const char *buf, char *method_out, int *path_offset) {
    if (buf[0] == 'G' && buf[1] == 'E' && buf[2] == 'T' && buf[3] == ' ') {
        method_out[0] = 'G'; method_out[1] = 'E'; method_out[2] = 'T'; method_out[3] = '\0';
        *path_offset = 4;
        return 1;
    }
    if (buf[0] == 'P' && buf[1] == 'O' && buf[2] == 'S' && buf[3] == 'T' && buf[4] == ' ') {
        method_out[0] = 'P'; method_out[1] = 'O'; method_out[2] = 'S'; method_out[3] = 'T'; method_out[4] = '\0';
        *path_offset = 5;
        return 1;
    }
    if (buf[0] == 'P' && buf[1] == 'U' && buf[2] == 'T' && buf[3] == ' ') {
        method_out[0] = 'P'; method_out[1] = 'U'; method_out[2] = 'T'; method_out[3] = '\0';
        *path_offset = 4;
        return 1;
    }
    if (buf[0] == 'D' && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'E' && buf[4] == 'T' && buf[5] == 'E' && buf[6] == ' ') {
        method_out[0] = 'D'; method_out[1] = 'E'; method_out[2] = 'L'; method_out[3] = 'E'; method_out[4] = 'T'; method_out[5] = 'E'; method_out[6] = '\0';
        *path_offset = 7;
        return 1;
    }
    if (buf[0] == 'P' && buf[1] == 'A' && buf[2] == 'T' && buf[3] == 'C' && buf[4] == 'H' && buf[5] == ' ') {
        method_out[0] = 'P'; method_out[1] = 'A'; method_out[2] = 'T'; method_out[3] = 'C'; method_out[4] = 'H'; method_out[5] = '\0';
        *path_offset = 6;
        return 1;
    }
    if (buf[0] == 'H' && buf[1] == 'E' && buf[2] == 'A' && buf[3] == 'D' && buf[4] == ' ') {
        method_out[0] = 'H'; method_out[1] = 'E'; method_out[2] = 'A'; method_out[3] = 'D'; method_out[4] = '\0';
        *path_offset = 5;
        return 1;
    }
    if (buf[0] == 'O' && buf[1] == 'P' && buf[2] == 'T' && buf[3] == 'I' && buf[4] == 'O' && buf[5] == 'N' && buf[6] == 'S' && buf[7] == ' ') {
        method_out[0] = 'O'; method_out[1] = 'P'; method_out[2] = 'T'; method_out[3] = 'I'; method_out[4] = 'O'; method_out[5] = 'N'; method_out[6] = 'S'; method_out[7] = '\0';
        *path_offset = 8;
        return 1;
    }
    return 0;
}

static __always_inline u16 parse_http_status(const char *buf, int len) {
    if (len < 12) return 0;
    if (buf[0] == 'H' && buf[1] == 'T' && buf[2] == 'T' && buf[3] == 'P' && buf[4] == '/' && buf[5] == '1' && buf[6] == '.') {
        if (buf[8] == ' ' && buf[9] >= '0' && buf[9] <= '9' && buf[10] >= '0' && buf[10] <= '9' && buf[11] >= '0' && buf[11] <= '9') {
            return (u16)((buf[9] - '0') * 100 + (buf[10] - '0') * 10 + (buf[11] - '0'));
        }
    }
    return 0;
}

// ---------------------------------------------------------------------------------
// Zero-Loop Architecture (Prevents Verifier State Explosion)
// Modeled after http-tracer (Findings #88, #90, #93, #99 in MEMORY_CORE.md)
// ---------------------------------------------------------------------------------

static __always_inline void extract_http_path(const char *buf, int path_offset, char *path_out) {
    int start = path_offset & 0x1F;
    #pragma clang loop unroll(disable)
    for (int i = 0; i < 48; i++) {
        char c = buf[(start + i) & 0x7F];
        if (c == ' ' || c == '\r' || c == '\n' || c == '\0') {
            path_out[i & 0x3F] = '\0';
            break;
        }
        path_out[i & 0x3F] = c;
    }
    path_out[47] = '\0';
}

static __always_inline void extract_http_host(const char *buf, char *host_out) {
    int h_start = -1;

    #pragma clang loop unroll(disable)
    for (int i = 0; i < 48; i++) {
        int idx = i & 0x7F;
        if (buf[idx] == '\0') break;
        if ((buf[idx] == 'H' || buf[idx] == 'h') &&
            buf[(idx + 1) & 0x7F] == 'o' &&
            buf[(idx + 2) & 0x7F] == 's' &&
            buf[(idx + 3) & 0x7F] == 't' &&
            buf[(idx + 4) & 0x7F] == ':') {
            int v = idx + 5;
            if (buf[v & 0x7F] == ' ') v++;
            h_start = v;
            break;
        }
    }

    if (h_start < 0) {
        __builtin_memcpy(host_out, "unknown", 8);
        return;
    }

    #pragma clang loop unroll(disable)
    for (int k = 0; k < 31; k++) {
        char ch = buf[(h_start + k) & 0x7F];
        if (ch == '\r' || ch == '\n' || ch == '\0' || ch == ' ' || ch == ':') {
            host_out[k & 0x1F] = '\0';
            break;
        }
        host_out[k & 0x1F] = ch;
    }
    host_out[31] = '\0';
}

static __always_inline void extract_payload(const char *buf, u32 len, char *payload_out) {
    u32 rlen = len < 256 ? len : 255;
    __builtin_memcpy(payload_out, buf, 256);
    // Prevent Clang -O2 from folding away the 0xff mask as redundant after the ternary above,
    // which otherwise lets the Linux 6.8+ BPF verifier lose the <256 bound across register spills.
    asm volatile("%0 &= 0xff" : "+r"(rlen));
    payload_out[rlen] = '\0';
}

// ---------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------
// HTTP/2 (RFC 7540) Framing & Static Table (RFC 7541) Zero-Loop Parsers
// ---------------------------------------------------------------------------------

static __always_inline int is_http2_preface(const char *buf) {
    if (buf[0] == 'P' && buf[1] == 'R' && buf[2] == 'I' && buf[3] == ' ' &&
        buf[4] == '*' && buf[5] == ' ' && buf[6] == 'H' && buf[7] == 'T') {
        return 1;
    }
    return 0;
}

static __always_inline int parse_h2_headers_method(const char *buf, u32 len, char *method_out) {
    if (len < 10) return 0;
    if ((u8)buf[3] != 0x01) return 0; // Must be HEADERS frame

    u8 offset = 9;
    if ((u8)buf[4] & 0x20) { // PRIORITY flag adds 5 bytes
        offset = 14;
    }
    if (offset < len) {
        u8 b = (u8)buf[offset];
        if (b == 0x82) {
            method_out[0] = 'G'; method_out[1] = 'E'; method_out[2] = 'T'; method_out[3] = '\0';
            return 1;
        }
        if (b == 0x83) {
            method_out[0] = 'P'; method_out[1] = 'O'; method_out[2] = 'S'; method_out[3] = 'T'; method_out[4] = '\0';
            return 1;
        }
        if (offset + 1 < len) {
            b = (u8)buf[offset + 1];
            if (b == 0x82) {
                method_out[0] = 'G'; method_out[1] = 'E'; method_out[2] = 'T'; method_out[3] = '\0';
                return 1;
            }
            if (b == 0x83) {
                method_out[0] = 'P'; method_out[1] = 'O'; method_out[2] = 'S'; method_out[3] = 'T'; method_out[4] = '\0';
                return 1;
            }
        }
    }
    method_out[0] = 'H'; method_out[1] = '2'; method_out[2] = '\0';
    return 1;
}

static __always_inline u16 parse_h2_status(const char *buf, u32 len) {
    if (len < 10) return 0;
    if ((u8)buf[3] == 0x01) { // HEADERS frame
        u8 s = (u8)buf[9];
        if (s == 0x88) return 200;
        if (s == 0x89) return 204;
        if (s == 0x8B) return 304;
        if (s == 0x8C) return 400;
        if (s == 0x8D) return 404;
        if (s == 0x8E) return 500;
        if (len > 10) {
            s = (u8)buf[10];
            if (s == 0x88) return 200;
            if (s == 0x89) return 204;
            if (s == 0x8B) return 304;
            if (s == 0x8C) return 400;
            if (s == 0x8D) return 404;
            if (s == 0x8E) return 500;
        }
        return 200; // default for valid HTTP/2 response headers
    }
    if ((u8)buf[3] == 0x00 && len >= 9) { // DATA frame
        return 200;
    }
    return 0;
}

// ---------------------------------------------------------------------------------
// OpenSSL Uprobes: SSL_write & SSL_write_ex (Entry & Return)
// ---------------------------------------------------------------------------------

static __always_inline int handle_ssl_write_entry(struct pt_regs *ctx, const char *user_buf, u32 num, u8 is_ex) {
    char comm[16] = {0};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (is_eprobe_comm(comm))
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    if (filter_pid != 0 && pid != filter_pid)
        return 0;

    if (!user_buf || num == 0)
        return 0;

    u8 *in_w = bpf_map_lookup_elem(&active_writes, &pid_tgid);
    if (is_ex && in_w && *in_w == 1) {
        // Inner SSL_write_ex called from outer SSL_write. Skip to prevent double counting.
        return 0;
    }

    if (!is_ex) {
        u8 one = 1;
        bpf_map_update_elem(&active_writes, &pid_tgid, &one, BPF_ANY);
    }

    // Enforce verifier scalar bounds mathematically
    num &= 0x1FF;
    if (num < 4)
        return 0;

    u32 zero = 0;
    struct scratch_t *scratch = bpf_map_lookup_elem(&scratch_map, &zero);
    if (!scratch)
        return 0;

    // Read payload from userspace buffer
    u32 read_bytes = num < sizeof(scratch->buf) ? num : (sizeof(scratch->buf) - 1);
    read_bytes &= 0x1FF;
    if (bpf_probe_read_user(scratch->buf, read_bytes, user_buf) < 0)
        return 0;
    scratch->buf[read_bytes & 0x1FF] = '\0';

    // Case A: Outgoing Client Request (HTTP/1.1 or HTTP/2)
    struct in_flight_tls_t *req = &scratch->inflight;
    int is_req = 0;
    int path_offset = 0;

    if (parse_http_method(scratch->buf, req->method, &path_offset)) {
        is_req = 1;
        extract_http_path(scratch->buf, path_offset, req->path);
        extract_http_host(scratch->buf, req->host);
    } else if (is_http2_preface(scratch->buf) || (read_bytes >= 9 && (u8)scratch->buf[3] == 0x01)) {
        is_req = 1;
        if (!parse_h2_headers_method(scratch->buf, read_bytes, req->method)) {
            copy_str(req->method, "H2", 3);
        }
        copy_str(req->path, "/", 2);
        copy_str(req->host, "remote-h2", 10);
    } else if (read_bytes >= 9 && (u8)scratch->buf[3] == 0x00) {
        // HTTP/2 DATA frame: update payload of existing in-flight request
        struct in_flight_tls_t *existing = bpf_map_lookup_elem(&inflight_reqs, &pid_tgid);
        if (existing && num > 9) {
            extract_payload(&scratch->buf[9], num - 9, existing->req_payload);
        }
        return 0;
    }

    if (is_req) {
        req->start_ns = bpf_ktime_get_ns();
        req->pid = pid;
        req->ppid = 0;
        req->tid = tid;
        req->req_len = num;
        copy_str(req->comm, comm, sizeof(req->comm));
        copy_str(req->role, "CLIENT", sizeof(req->role));
        get_container_id(req->container_id, sizeof(req->container_id));

        // If host was not parsed from HTTP/1.1 or defaulted to remote-h2 / unknown, resolve via SNI
        if (req->host[0] == '\0' ||
            (req->host[0] == 'r' && req->host[1] == 'e' && req->host[2] == 'm') ||
            (req->host[0] == 'u' && req->host[1] == 'n' && req->host[2] == 'k')) {
            u64 ssl_ptr = (u64)PT_REGS_PARM1(ctx);
            struct host_val_t *hval = bpf_map_lookup_elem(&ssl_hosts, &ssl_ptr);
            if (!hval) {
                hval = bpf_map_lookup_elem(&pid_hosts, &pid);
            }
            if (hval && hval->host[0] != '\0') {
                copy_str(req->host, hval->host, sizeof(req->host));
            }
        }

        struct host_key_t hkey = {0};
        __builtin_memcpy(hkey.host, req->host, sizeof(hkey.host));
        struct host_stat_t *hstat = bpf_map_lookup_elem(&host_stats, &hkey);
        if (hstat) {
            __sync_fetch_and_add(&hstat->req_count, 1);
        } else {
            struct host_stat_t init_stat = {.req_count = 1};
            bpf_map_update_elem(&host_stats, &hkey, &init_stat, BPF_ANY);
        }

        extract_payload(scratch->buf, num, req->req_payload);
        bpf_map_update_elem(&inflight_reqs, &pid_tgid, req, BPF_ANY);
        return 0;
    }

    // Case B: HTTP/1.1 Response from Local Server (Server Outbound Flow)
    if (scratch->buf[0] == 'H' && scratch->buf[1] == 'T' && scratch->buf[2] == 'T' && scratch->buf[3] == 'P') {
        u16 status = parse_http_status(scratch->buf, num);
        if (status > 0) {
            struct in_flight_tls_t *sreq = bpf_map_lookup_elem(&inflight_reqs, &pid_tgid);
            u64 duration_us = 0;
            u64 now = bpf_ktime_get_ns();
            if (sreq && sreq->start_ns > 0 && now > sreq->start_ns) {
                duration_us = (now - sreq->start_ns) / 1000;
            }

            if (filter_errors_only && status < 400) {
                bpf_map_delete_elem(&inflight_reqs, &pid_tgid);
                return 0;
            }

            struct tls_event_t *e = bpf_ringbuf_reserve(&tls_events, sizeof(struct tls_event_t), 0);
            if (e) {
                e->pid = pid;
                e->ppid = 0;
                e->tid = tid;
                e->status_code = status;
                e->duration_us = duration_us;
                e->resp_len = num;
                copy_str(e->comm, comm, sizeof(e->comm));
                copy_str(e->role, "SERVER", sizeof(e->role));
                get_container_id(e->container_id, sizeof(e->container_id));

                if (sreq) {
                    e->req_len = sreq->req_len;
                    copy_str(e->method, sreq->method, sizeof(e->method));
                    __builtin_memcpy(e->path, sreq->path, sizeof(e->path));
                    __builtin_memcpy(e->host, sreq->host, sizeof(e->host));
                    __builtin_memcpy(e->req_payload, sreq->req_payload, sizeof(e->req_payload));
                } else {
                    e->req_len = 0;
                    copy_str(e->method, "HTTP", 5);
                    copy_str(e->path, "/", 2);
                    copy_str(e->host, "local", 6);
                    e->req_payload[0] = '\0';
                }

                extract_payload(scratch->buf, num, e->resp_payload);
                bpf_ringbuf_submit(e, 0);
            }

            struct status_key_t skey = {.status_code = status};
            struct status_stat_t *sstat = bpf_map_lookup_elem(&status_stats, &skey);
            if (sstat) {
                __sync_fetch_and_add(&sstat->count, 1);
            } else {
                struct status_stat_t init_sstat = {.count = 1};
                bpf_map_update_elem(&status_stats, &skey, &init_sstat, BPF_ANY);
            }

            bpf_map_delete_elem(&inflight_reqs, &pid_tgid);
        }
        return 0;
    }

    return 0;
}

SEC("uprobe/SSL_write")
int uprobe_SSL_write(struct pt_regs *ctx) {
    const char *buf = (const char *)PT_REGS_PARM2(ctx);
    int num = (int)PT_REGS_PARM3(ctx);
    return handle_ssl_write_entry(ctx, buf, (u32)num, 0);
}

SEC("uprobe/SSL_write_ex")
int uprobe_SSL_write_ex(struct pt_regs *ctx) {
    const char *buf = (const char *)PT_REGS_PARM2(ctx);
    unsigned long num = (unsigned long)PT_REGS_PARM3(ctx);
    return handle_ssl_write_entry(ctx, buf, (u32)num, 1);
}

SEC("uretprobe/SSL_write")
int uretprobe_SSL_write(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&active_writes, &pid_tgid);
    return 0;
}

SEC("uretprobe/SSL_write_ex")
int uretprobe_SSL_write_ex(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&active_writes, &pid_tgid);
    return 0;
}

// ---------------------------------------------------------------------------------
// OpenSSL SNI Uprobes: SSL_ctrl, SSL_set1_host & SSL_free
// ---------------------------------------------------------------------------------

SEC("uprobe/SSL_ctrl")
int uprobe_SSL_ctrl(struct pt_regs *ctx) {
    int cmd = (int)PT_REGS_PARM2(ctx);
    if (cmd != 55) // SSL_CTRL_SET_TLSEXT_HOSTNAME
        return 0;

    u64 ssl_ptr = (u64)PT_REGS_PARM1(ctx);
    const char *name_ptr = (const char *)PT_REGS_PARM4(ctx);
    if (!name_ptr)
        return 0;

    struct host_val_t hval = {0};
    if (bpf_probe_read_user_str(hval.host, sizeof(hval.host), name_ptr) <= 0)
        return 0;

    bpf_map_update_elem(&ssl_hosts, &ssl_ptr, &hval, BPF_ANY);

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    bpf_map_update_elem(&pid_hosts, &pid, &hval, BPF_ANY);

    return 0;
}

SEC("uprobe/SSL_set1_host")
int uprobe_SSL_set1_host(struct pt_regs *ctx) {
    u64 ssl_ptr = (u64)PT_REGS_PARM1(ctx);
    const char *name_ptr = (const char *)PT_REGS_PARM2(ctx);
    if (!name_ptr)
        return 0;

    struct host_val_t hval = {0};
    if (bpf_probe_read_user_str(hval.host, sizeof(hval.host), name_ptr) <= 0)
        return 0;

    bpf_map_update_elem(&ssl_hosts, &ssl_ptr, &hval, BPF_ANY);

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    bpf_map_update_elem(&pid_hosts, &pid, &hval, BPF_ANY);

    return 0;
}

SEC("uprobe/SSL_free")
int uprobe_SSL_free(struct pt_regs *ctx) {
    u64 ssl_ptr = (u64)PT_REGS_PARM1(ctx);
    bpf_map_delete_elem(&ssl_hosts, &ssl_ptr);

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    bpf_map_delete_elem(&pid_hosts, &pid);

    return 0;
}

// ---------------------------------------------------------------------------------
// OpenSSL Uprobes: SSL_read & SSL_read_ex (Entry & Return)
// ---------------------------------------------------------------------------------

static __always_inline int handle_ssl_read_entry(struct pt_regs *ctx, const char *buf, u8 is_ex) {
    char comm[16] = {0};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (is_eprobe_comm(comm))
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    if (filter_pid != 0 && pid != filter_pid)
        return 0;

    struct active_read_t *existing = bpf_map_lookup_elem(&active_reads, &pid_tgid);
    if (existing && existing->in_read) {
        // Already inside outer SSL_read. Do not overwrite tracking record.
        return 0;
    }

    struct active_read_t ar = {
        .buf = buf,
        .ts = bpf_ktime_get_ns(),
        .readbytes_ptr = is_ex ? (const unsigned long *)PT_REGS_PARM4(ctx) : NULL,
        .is_caller_ex = is_ex,
        .in_read = !is_ex,
        .ssl_ptr = (u64)PT_REGS_PARM1(ctx),
    };
    bpf_map_update_elem(&active_reads, &pid_tgid, &ar, BPF_ANY);
    return 0;
}

static __always_inline int handle_ssl_read_return(struct pt_regs *ctx, int ret, u8 is_ex) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct active_read_t *ar = bpf_map_lookup_elem(&active_reads, &pid_tgid);
    if (!ar)
        return 0;

    if (is_ex && ar->in_read) {
        // Inner SSL_read_ex return during active outer SSL_read.
        // Do not delete active_reads; let outer uretprobe_SSL_read complete the event!
        return 0;
    }

    const char *user_buf = ar->buf;
    u32 ret_bytes = 0;

    if (is_ex) {
        if (ret != 1 || !ar->readbytes_ptr) {
            bpf_map_delete_elem(&active_reads, &pid_tgid);
            return 0;
        }
        unsigned long actual_len = 0;
        if (bpf_probe_read_user(&actual_len, sizeof(actual_len), ar->readbytes_ptr) < 0) {
            bpf_map_delete_elem(&active_reads, &pid_tgid);
            return 0;
        }
        ret_bytes = (u32)actual_len;
    } else {
        if (ret <= 0) {
            bpf_map_delete_elem(&active_reads, &pid_tgid);
            return 0;
        }
        ret_bytes = (u32)ret;
    }

    bpf_map_delete_elem(&active_reads, &pid_tgid);

    if (!user_buf || ret_bytes == 0)
        return 0;

    char comm[16] = {0};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (is_eprobe_comm(comm))
        return 0;

    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    u32 zero = 0;
    struct scratch_t *scratch = bpf_map_lookup_elem(&scratch_map, &zero);
    if (!scratch)
        return 0;

    u32 read_bytes = ret_bytes;
    read_bytes &= 0x1FF;
    if (read_bytes < 4)
        return 0;

    #pragma clang loop unroll(full)
    for (int i = 0; i < 64; i++) {
        scratch->buf[i] = '\0';
    }

    if (bpf_probe_read_user(scratch->buf, read_bytes < sizeof(scratch->buf) ? read_bytes : (sizeof(scratch->buf) - 1), user_buf) < 0)
        return 0;
    scratch->buf[read_bytes & 0x1FF] = '\0';

    // Case 1: Incoming HTTP Response from Remote API Endpoint (Client Outbound Flow)
    u16 status = 0;
    if (scratch->buf[0] == 'H' && scratch->buf[1] == 'T' && scratch->buf[2] == 'T' && scratch->buf[3] == 'P') {
        status = parse_http_status(scratch->buf, read_bytes);
    } else if (read_bytes >= 9 && ((u8)scratch->buf[3] == 0x01 || (u8)scratch->buf[3] == 0x00)) {
        status = parse_h2_status(scratch->buf, read_bytes);
    }

    if (status > 0) {
        struct in_flight_tls_t *req = bpf_map_lookup_elem(&inflight_reqs, &pid_tgid);
        u64 duration_us = 0;
        u64 now = bpf_ktime_get_ns();
        if (req && req->start_ns > 0 && now > req->start_ns) {
            duration_us = (now - req->start_ns) / 1000;
        }

        if (filter_errors_only && status < 400) {
            bpf_map_delete_elem(&inflight_reqs, &pid_tgid);
            return 0;
        }

        struct tls_event_t *e = bpf_ringbuf_reserve(&tls_events, sizeof(struct tls_event_t), 0);
        if (e) {
            e->pid = pid;
            e->ppid = 0;
            e->tid = tid;
            e->status_code = status;
            e->duration_us = duration_us;
            e->resp_len = read_bytes;
            copy_str(e->comm, comm, sizeof(e->comm));
            copy_str(e->role, "CLIENT", sizeof(e->role));
            get_container_id(e->container_id, sizeof(e->container_id));

            if (req) {
                e->req_len = req->req_len;
                copy_str(e->method, req->method, sizeof(e->method));
                __builtin_memcpy(e->path, req->path, sizeof(e->path));
                __builtin_memcpy(e->host, req->host, sizeof(e->host));
                __builtin_memcpy(e->req_payload, req->req_payload, sizeof(e->req_payload));
            } else {
                e->req_len = 0;
                copy_str(e->method, "HTTP", 5);
                copy_str(e->path, "/", 2);
                copy_str(e->host, "remote", 7);
                e->req_payload[0] = '\0';
            }

            // Extract Response Body (Zero-Loop Direct Capture)
            if ((u8)scratch->buf[3] == 0x00 && read_bytes > 9) {
                extract_payload(&scratch->buf[9], read_bytes - 9, e->resp_payload);
            } else {
                extract_payload(scratch->buf, read_bytes, e->resp_payload);
            }

            bpf_ringbuf_submit(e, 0);
        }

        // Update status code stats
        struct status_key_t skey = {.status_code = status};
        struct status_stat_t *sstat = bpf_map_lookup_elem(&status_stats, &skey);
        if (sstat) {
            __sync_fetch_and_add(&sstat->count, 1);
        } else {
            struct status_stat_t init_sstat = {.count = 1};
            bpf_map_update_elem(&status_stats, &skey, &init_sstat, BPF_ANY);
        }

        bpf_map_delete_elem(&inflight_reqs, &pid_tgid);
        return 0;
    }

    // Case 2: Incoming HTTP Request to Local HTTPS Server (Server Inbound Flow)
    int path_offset = 0;
    char method[8] = {0};
    if (parse_http_method(scratch->buf, method, &path_offset)) {
        struct in_flight_tls_t *req = &scratch->inflight;
        req->start_ns = bpf_ktime_get_ns();
        req->pid = pid;
        req->ppid = 0;
        req->tid = tid;
        req->req_len = read_bytes;
        copy_str(req->comm, comm, sizeof(req->comm));
        copy_str(req->role, "SERVER", sizeof(req->role));
        copy_str(req->method, method, sizeof(req->method));
        get_container_id(req->container_id, sizeof(req->container_id));

        // Extract Path, Host, and Request Payload using Zero-Loop Architecture
        extract_http_path(scratch->buf, path_offset, req->path);
        extract_http_host(scratch->buf, req->host);
        if (req->host[0] == '\0' || (req->host[0] == 'u' && req->host[1] == 'n' && req->host[2] == 'k')) {
            struct host_val_t *hval = bpf_map_lookup_elem(&ssl_hosts, &ar->ssl_ptr);
            if (!hval) {
                hval = bpf_map_lookup_elem(&pid_hosts, &pid);
            }
            if (hval && hval->host[0] != '\0') {
                copy_str(req->host, hval->host, sizeof(req->host));
            }
        }
        extract_payload(scratch->buf, read_bytes, req->req_payload);

        bpf_map_update_elem(&inflight_reqs, &pid_tgid, req, BPF_ANY);
    }

    return 0;
}

SEC("uprobe/SSL_read")
int uprobe_SSL_read(struct pt_regs *ctx) {
    const char *buf = (const char *)PT_REGS_PARM2(ctx);
    return handle_ssl_read_entry(ctx, buf, 0);
}

SEC("uprobe/SSL_read_ex")
int uprobe_SSL_read_ex(struct pt_regs *ctx) {
    const char *buf = (const char *)PT_REGS_PARM2(ctx);
    return handle_ssl_read_entry(ctx, buf, 1);
}

SEC("uretprobe/SSL_read")
int uretprobe_SSL_read(struct pt_regs *ctx) {
    int ret = (int)PT_REGS_RC(ctx);
    return handle_ssl_read_return(ctx, ret, 0);
}

SEC("uretprobe/SSL_read_ex")
int uretprobe_SSL_read_ex(struct pt_regs *ctx) {
    int ret = (int)PT_REGS_RC(ctx);
    return handle_ssl_read_return(ctx, ret, 1);
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
