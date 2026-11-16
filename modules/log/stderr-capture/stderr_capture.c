// SPDX-License-Identifier: GPL-2.0-only OR MIT
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/eprobe_tracepoint.h>
#include <bpf/eprobe_cgroup.h>

typedef unsigned long long u64;
typedef unsigned int u32;

struct stderr_event_t {
    u32 pid;
    u32 uid;
    char comm[16];
    char container_id[16];
    char level[8];
    u32 len;
    u32 trunc;
    char payload[256];
} __attribute__((packed));

// Optional PID filter variable populated by CLI flag --pid
volatile const u32 target_pid = 0;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB ring buffer
} stderr_events SEC(".maps");

struct iovec___local {
    void *iov_base;
    unsigned long iov_len;
} __attribute__((preserve_access_index));

// Zero-Loop O(1) Noise Filter: discards non-error short frames and terminal escape sequences
static __always_inline int is_noise_fragment(const char *msg, u32 len) {
    // 1. Any write under 16 bytes is discarded UNLESS it explicitly starts with an error keyword.
    // Discards:
    // - 1-byte curl progress meter updates ('%', '1', '0', 'X', 'f', 'e', 'r', 'd')
    // - 6-byte FastCGI / PHP-FPM worker status frames and socket control pings
    // - 8-9 byte bash bracketed paste mode escape sequences (\x1b[?2004h, \x1b[?2004l)
    // - 4-6 byte terminal clearing sequences (\r\x1b[2K, \x1b[0m)
    // - Bare numeric exit codes ('0', '1', '4')
    if (len < 16) {
        if (len < 3) {
            return 1;
        }
        char c0 = msg[0];
        char c1 = msg[1];
        char c2 = msg[2];
        int is_err = 0;
        if ((c0 == 'E' || c0 == 'e') && (c1 == 'R' || c1 == 'r') && (c2 == 'R' || c2 == 'r')) is_err = 1;
        if ((c0 == 'F' || c0 == 'f') && (c1 == 'A' || c1 == 'a') && (c2 == 'I' || c2 == 'i')) is_err = 1;
        if ((c0 == 'W' || c0 == 'w') && (c1 == 'A' || c1 == 'a') && (c2 == 'R' || c2 == 'r')) is_err = 1;
        if ((c0 == 'F' || c0 == 'f') && (c1 == 'A' || c1 == 'a') && (c2 == 'T' || c2 == 't')) is_err = 1;
        if (!is_err) {
            return 1;
        }
    }

    // 2. Discard terminal ANSI escape sequences (0x1B / 27)
    if (msg[0] == 0x1B || msg[0] == 27 || msg[1] == 0x1B || msg[1] == 27) {
        return 1;
    }

    // 3. For writes >= 16 bytes, ensure the message starts with printable ASCII (not raw binary/nulls)
    if ((unsigned char)msg[0] < 32 && (unsigned char)msg[1] < 32) {
        return 1;
    }

    return 0;
}

// Inspect output text for error keywords to emit standard anomaly level tokens
static __always_inline void classify_log_level(char *level, const char *msg) {
    int is_fatal = 0;
    int is_err = 0;
    int is_warn = 0;

    // Scan the first 6 prefix positions for standard severity tokens
    #pragma clang loop unroll(full)
    for (int i = 0; i < 6; i++) {
        char c0 = msg[i];
        char c1 = msg[i + 1];
        char c2 = msg[i + 2];
        char c3 = msg[i + 3];

        if ((c0 == 'F' || c0 == 'f') && (c1 == 'A' || c1 == 'a') && (c2 == 'T' || c2 == 't') && (c3 == 'A' || c3 == 'a')) {
            is_fatal = 1;
            break;
        }
        if ((c0 == 'C' || c0 == 'c') && (c1 == 'R' || c1 == 'r') && (c2 == 'I' || c2 == 'i') && (c3 == 'T' || c3 == 't')) {
            is_fatal = 1;
            break;
        }
        if ((c0 == 'E' || c0 == 'e') && (c1 == 'R' || c1 == 'r') && (c2 == 'R' || c2 == 'r')) {
            if (!is_err) is_err = 1;
            break;
        }
        if ((c0 == 'F' || c0 == 'f') && (c1 == 'A' || c1 == 'a') && (c2 == 'I' || c2 == 'i') && (c3 == 'L' || c3 == 'l')) {
            if (!is_err) is_err = 1;
            break;
        }
        if ((c0 == 'W' || c0 == 'w') && (c1 == 'A' || c1 == 'a') && (c2 == 'R' || c2 == 'r') && (c3 == 'N' || c3 == 'n')) {
            if (!is_warn) is_warn = 1;
            break;
        }
    }

    if (is_fatal) {
        level[0] = 'F'; level[1] = 'A'; level[2] = 'T'; level[3] = 'A'; level[4] = 'L'; level[5] = '\0';
    } else if (is_err) {
        level[0] = 'E'; level[1] = 'R'; level[2] = 'R'; level[3] = 'O'; level[4] = 'R'; level[5] = '\0';
    } else if (is_warn) {
        level[0] = 'W'; level[1] = 'A'; level[2] = 'R'; level[3] = 'N'; level[4] = '\0';
    } else {
        level[0] = 'S'; level[1] = 'T'; level[2] = 'D'; level[3] = 'E'; level[4] = 'R'; level[5] = 'R'; level[6] = '\0';
    }
}

static __always_inline int is_eprobe_comm(void) {
    char comm[16] = {0};
    bpf_get_current_comm(&comm, sizeof(comm));
    return comm[0] == 'e' && comm[1] == 'p' && comm[2] == 'r' &&
           comm[3] == 'o' && comm[4] == 'b' && comm[5] == 'e';
}

static __always_inline int process_stderr(const void *buf, u32 count) {
    if (is_eprobe_comm()) {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (target_pid != 0 && pid != target_pid) {
        return 0;
    }

    count &= 0x1FF; // Explicit scalar mask for verifier
    if (count == 0 || !buf) {
        return 0;
    }

    u32 read_bytes = count < 255 ? count : 255;
    read_bytes &= 0xFF;

    struct stderr_event_t *e = bpf_ringbuf_reserve(&stderr_events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    if (bpf_probe_read_user(e->payload, read_bytes, buf) < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    e->payload[read_bytes] = '\0';

    if (is_noise_fragment(e->payload, read_bytes)) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    e->pid = pid;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->len = read_bytes;
    e->trunc = count > 255 ? 1 : 0;

    char cid[16] = {0};
    if (parse_container_id(cid)) {
        __builtin_memcpy(e->container_id, cid, sizeof(e->container_id));
    } else {
        e->container_id[0] = 'h'; e->container_id[1] = 'o'; e->container_id[2] = 's'; e->container_id[3] = 't'; e->container_id[4] = '\0';
    }

    classify_log_level(e->level, e->payload);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int trace_sys_write(struct trace_event_raw_sys_enter *ctx) {
    unsigned int fd = (unsigned int)ctx->args[0];
    if (fd != 2) {
        return 0; // Strictly stderr
    }

    const void *buf = (const void *)ctx->args[1];
    u32 count = (u32)ctx->args[2];
    return process_stderr(buf, count);
}

SEC("tracepoint/syscalls/sys_enter_writev")
int trace_sys_writev(struct trace_event_raw_sys_enter *ctx) {
    unsigned int fd = (unsigned int)ctx->args[0];
    if (fd != 2) {
        return 0; // Strictly stderr
    }

    const void *iov_ptr = (const void *)ctx->args[1];
    if (!iov_ptr) {
        return 0;
    }

    struct iovec___local iov;
    if (bpf_probe_read_user(&iov, sizeof(iov), iov_ptr) < 0) {
        return 0;
    }

    u32 count = (u32)iov.iov_len;
    const void *buf = iov.iov_base;
    return process_stderr(buf, count);
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";

