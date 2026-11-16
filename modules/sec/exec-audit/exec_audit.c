// SPDX-License-Identifier: GPL-2.0-only OR MIT
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/eprobe_tracepoint.h>
#include <bpf/eprobe_cgroup.h>

typedef unsigned long long u64;
typedef unsigned int u32;

struct event_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 loginuid;
    char comm[16];
    char container_id[16];
    char filename[256];
    char args[256];
    char level[8];
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB ring buffer page-aligned
} events SEC(".maps");

// CO-RE Definitions for Task & Loginuid Struct Access
struct kuid_t___local {
    unsigned int val;
} __attribute__((preserve_access_index));

struct task_struct___local {
    struct task_struct___local *real_parent;
    int tgid;
    struct kuid_t___local loginuid;
} __attribute__((preserve_access_index));

// Single-pass verifier-safe argument reader (Zero multi-loop explosion)
static __always_inline void read_args(char *args, const char *const *argv) {
    args[0] = '\0';
    if (!argv) return;

    const char *arg1 = NULL;
    const char *arg2 = NULL;
    bpf_probe_read_user(&arg1, sizeof(arg1), &argv[1]);
    bpf_probe_read_user(&arg2, sizeof(arg2), &argv[2]);

    if (!arg1) return;

    // Direct read of primary argument (e.g. script name, subcommand, or flag)
    int len1 = bpf_probe_read_user_str(args, 128, arg1);
    if (len1 <= 1) {
        args[0] = '\0';
        return;
    }

    // If second argument exists (e.g. -c "command" or flag value), append it cleanly
    if (arg2) {
        char buf2[120] = {0};
        int len2 = bpf_probe_read_user_str(buf2, sizeof(buf2), arg2);
        if (len2 > 1) {
            u32 off = (u32)(len1 - 1);
            off &= 0x7F; // Strictly clamp to [0, 127]
            args[off] = ' ';

            // Single linear loop without nested loops or induction state chaining
            #pragma clang loop unroll(disable)
            for (int i = 0; i < 120; i++) {
                char c = buf2[i];
                if (c == '\0') break;
                args[(off + 1 + i) & 0xFF] = c;
            }
            args[(off + len2) & 0xFF] = '\0';
            return;
        }
    }

    args[(len1 - 1) & 0x7F] = '\0';
}

static __always_inline int is_eprobe_comm(void) {
    char comm[16] = {0};
    bpf_get_current_comm(&comm, sizeof(comm));
    return comm[0] == 'e' && comm[1] == 'p' && comm[2] == 'r' &&
           comm[3] == 'o' && comm[4] == 'b' && comm[5] == 'e';
}

static __always_inline int process_exec(struct trace_event_raw_sys_enter *ctx, const char *filename_ptr, const char *const *argv_ptr) {
    if (is_eprobe_comm()) {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->pid = pid;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    if (filename_ptr) {
        bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename_ptr);
    } else {
        e->filename[0] = '\0';
    }

    read_args(e->args, argv_ptr);

    struct task_struct___local *task = (struct task_struct___local *)bpf_get_current_task();
    struct task_struct___local *parent = BPF_CORE_READ(task, real_parent);
    e->ppid = BPF_CORE_READ(parent, tgid);
    e->loginuid = BPF_CORE_READ(task, loginuid.val);

    char cid[16] = {0};
    if (parse_container_id(cid)) {
        __builtin_memcpy(e->container_id, cid, sizeof(e->container_id));
    } else {
        e->container_id[0] = 'h'; e->container_id[1] = 'o'; e->container_id[2] = 's'; e->container_id[3] = 't'; e->container_id[4] = '\0';
    }

    if (e->uid == 0) {
        e->level[0] = 'W'; e->level[1] = 'A'; e->level[2] = 'R'; e->level[3] = 'N'; e->level[4] = '\0';
    } else {
        e->level[0] = 'I'; e->level[1] = 'N'; e->level[2] = 'F'; e->level[3] = 'O'; e->level[4] = '\0';
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_sys_execve(struct trace_event_raw_sys_enter *ctx) {
    const char *filename_ptr = (const char *)ctx->args[0];
    const char *const *argv_ptr = (const char *const *)ctx->args[1];
    return process_exec(ctx, filename_ptr, argv_ptr);
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int trace_sys_execveat(struct trace_event_raw_sys_enter *ctx) {
    const char *filename_ptr = (const char *)ctx->args[1];
    const char *const *argv_ptr = (const char *const *)ctx->args[2];
    return process_exec(ctx, filename_ptr, argv_ptr);
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
