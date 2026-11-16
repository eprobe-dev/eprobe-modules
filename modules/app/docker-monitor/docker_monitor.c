// SPDX-License-Identifier: GPL-2.0-only OR MIT
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;
typedef __be32 __u32;
typedef __be16 __u16;

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

struct proc_event_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[16];
    char filename[128];
    char container_id[16];
};

struct oom_event_t {
    u32 pid;
    u32 uid;
    u32 exit_code;
    char comm[16];
    char container_id[16];
    char reason[32];
};

struct app_crash_event_t {
    u32 pid;
    u32 uid;
    u32 exit_code;
    char comm[16];
    char container_id[16];
    char reason[32];
};

struct log_event_t {
    u32 pid;
    char comm[16];
    char container_id[16];
    char level[8];
    char message[256];
};

struct net_event_t {
    u32 pid;
    char comm[16];
    char container_id[16];
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u64 latency_us;
};

struct io_event_t {
    u32 pid;
    char comm[16];
    char container_id[16];
    char rwflag[8];
    u32 bytes;
    u64 latency_us;
};

struct lifecycle_event_t {
    u32 pid;
    char container_id[16];
    char action[16];
};

struct container_stat_t {
    u64 event_count;
};

// Shared key struct for all per-container hash maps
struct container_key_t {
    char container_id[16];
};

// In-kernel aggregation value structs
struct cpu_stat_t {
    u64 cpu_time_ns;
};

struct mem_stat_t {
    u64 rss_bytes;
};

struct net_stat_t {
    u64 tx_bytes;
    u64 rx_bytes;
};

struct io_stat_t {
    u64 read_bytes;
    u64 write_bytes;
};

// Global CLI Filter Variables
volatile const u32 filter_pid = 0;
volatile const u16 filter_port = 0;

// Ring Buffers
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} proc_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} oom_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} app_crash_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} log_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} net_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} io_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} lifecycle_events SEC(".maps");

// In-Kernel Aggregation Hash Maps (stateful metrics polled by user-space ticker)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct container_key_t);
    __type(value, struct cpu_stat_t);
} cpu_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct container_key_t);
    __type(value, struct mem_stat_t);
} mem_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct container_key_t);
    __type(value, struct net_stat_t);
} net_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct container_key_t);
    __type(value, struct io_stat_t);
} io_stats SEC(".maps");

// Connection Start Time Hashmap for RTT Calculation
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, void *);
    __type(value, u64);
} conn_start SEC(".maps");

// Block I/O Start Time Hashmap
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, u64);
} io_start SEC(".maps");

// Container Event Aggregation Hashmap
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[16]);
    __type(value, struct container_stat_t);
} container_stats SEC(".maps");

// Container Stdio Inode Tracking (filters internal anonymous pipes/redirects)
struct container_stdio_t {
    u64 stdout_ino;
    u64 stderr_ino;
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[16]);
    __type(value, struct container_stdio_t);
} container_stdio_map SEC(".maps");

// Per-CPU scratch buffer for cgroup path parsing.
// Using map memory instead of stack avoids verifier dynamic-length tracking issues
// with bpf_probe_read_kernel_str (ARG_PTR_TO_UNINIT_MEM).
struct cgroup_path_val {
    char path[256];
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct cgroup_path_val);
} cgroup_path_buf SEC(".maps");

#include <bpf/eprobe_tracepoint.h>

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

// CO-RE Definitions for Task, File & Cgroup Struct Access
struct inode___local {
    unsigned long i_ino;
} __attribute__((preserve_access_index));

struct file___local {
    struct inode___local *f_inode;
} __attribute__((preserve_access_index));

struct fdtable___local {
    struct file___local **fd;
} __attribute__((preserve_access_index));

struct files_struct___local {
    struct fdtable___local *fdt;
} __attribute__((preserve_access_index));

struct kernfs_node___local {
    const char *name;
} __attribute__((preserve_access_index));

struct cgroup___local {
    struct kernfs_node___local *kn;
} __attribute__((preserve_access_index));

struct cgroup_subsys_state___local {
    struct cgroup___local *cgroup;
} __attribute__((preserve_access_index));

struct css_set___local {
    struct cgroup___local *dfl_cgrp;
    struct cgroup_subsys_state___local *subsys[13];
} __attribute__((preserve_access_index));

// CO-RE Definitions for PID Namespace Verification
struct ns_common___local {
    unsigned int inum;
} __attribute__((preserve_access_index));

struct pid_namespace___local {
    struct ns_common___local ns;
} __attribute__((preserve_access_index));

struct nsproxy___local {
    struct pid_namespace___local *pid_ns_for_children;
} __attribute__((preserve_access_index));

struct task_struct___local {
    struct task_struct___local *real_parent;
    int tgid;
    int exit_code;
    struct css_set___local *cgroups;
    struct nsproxy___local *nsproxy;
    struct files_struct___local *files;
} __attribute__((preserve_access_index));

// Verify task is running inside a container (non-init PID namespace)
static __always_inline int is_container_context(void) {
    struct task_struct___local *task = (struct task_struct___local *)bpf_get_current_task();
    // Two-step read: ns is an embedded struct, not a pointer
    struct pid_namespace___local *pid_ns = BPF_CORE_READ(task, nsproxy, pid_ns_for_children);
    if (!pid_ns) return 0;
    unsigned int inum = BPF_CORE_READ(pid_ns, ns.inum);
    // 0xEFFFFFFC (4026531836) = init PID namespace inode
    return inum != 0xEFFFFFFC;
}

static __always_inline u64 get_fd_inode(struct task_struct___local *task, unsigned int fd) {
    if (!task) return 0;
    struct files_struct___local *files = BPF_CORE_READ(task, files);
    if (!files) return 0;
    struct fdtable___local *fdt = BPF_CORE_READ(files, fdt);
    if (!fdt) return 0;
    struct file___local **fd_array = BPF_CORE_READ(fdt, fd);
    if (!fd_array) return 0;

    struct file___local *f = NULL;
    if (fd == 1) {
        bpf_probe_read_kernel(&f, sizeof(f), &fd_array[1]);
    } else if (fd == 2) {
        bpf_probe_read_kernel(&f, sizeof(f), &fd_array[2]);
    }
    if (!f) return 0;

    u64 ino = BPF_CORE_READ(f, f_inode, i_ino);
    return ino;
}

static __always_inline int is_container_root_task(struct task_struct___local *task) {
    struct pid_namespace___local *pid_ns = BPF_CORE_READ(task, nsproxy, pid_ns_for_children);
    if (!pid_ns) return 0;
    unsigned int inum = BPF_CORE_READ(pid_ns, ns.inum);
    if (inum == 0xEFFFFFFC) return 0; // Host process

    struct task_struct___local *parent = BPF_CORE_READ(task, real_parent);
    if (!parent) return 1;

    struct pid_namespace___local *parent_pid_ns = BPF_CORE_READ(parent, nsproxy, pid_ns_for_children);
    if (!parent_pid_ns) return 1;
    unsigned int parent_inum = BPF_CORE_READ(parent_pid_ns, ns.inum);

    // If parent is in the host namespace, this task is the root entrypoint of the container!
    return parent_inum == 0xEFFFFFFC;
}

static __always_inline int check_container_stdio(struct task_struct___local *task, const char *container_id, unsigned int fd) {
    u64 current_ino = get_fd_inode(task, fd);
    if (current_ino == 0) {
        return 1; // Fallback: allow if inode cannot be resolved
    }

    struct container_stdio_t *stdio = bpf_map_lookup_elem(&container_stdio_map, (void *)container_id);
    if (!stdio) {
        struct container_stdio_t new_stdio = {0};
        if (fd == 1) new_stdio.stdout_ino = current_ino;
        else if (fd == 2) new_stdio.stderr_ino = current_ino;
        bpf_map_update_elem(&container_stdio_map, (void *)container_id, &new_stdio, BPF_ANY);
        return 1;
    }

    // If this is the container's root task, anchor/confirm the root inode
    if (is_container_root_task(task)) {
        if (fd == 1 && stdio->stdout_ino != current_ino) {
            stdio->stdout_ino = current_ino;
        } else if (fd == 2 && stdio->stderr_ino != current_ino) {
            stdio->stderr_ino = current_ino;
        }
        return 1;
    }

    // For other tasks in the container:
    if (fd == 1) {
        if (stdio->stdout_ino == 0) {
            stdio->stdout_ino = current_ino;
            return 1;
        }
        if (current_ino != stdio->stdout_ino) {
            return 0; // Drop internal pipe / redirected stdout
        }
    } else if (fd == 2) {
        if (stdio->stderr_ino == 0) {
            stdio->stderr_ino = current_ino;
            return 1;
        }
        if (current_ino != stdio->stderr_ino) {
            return 0; // Drop internal pipe / redirected stderr
        }
    }

    return 1;
}

static __always_inline int is_noise_fragment(const char *msg, u32 len) {
    if (len == 0) return 1;
    if (len == 1) {
        char c = msg[0];
        if (c == '\n' || c == '\r' || c == ' ' || c == '\t' || (c >= '0' && c <= '9')) {
            return 1;
        }
    }
    if (len == 2) {
        char c0 = msg[0];
        char c1 = msg[1];
        if ((c0 >= '0' && c0 <= '9') && (c1 == '\n' || c1 == '\r' || (c1 >= '0' && c1 <= '9') || c1 == ' ')) {
            return 1;
        }
        if ((c0 == '\n' || c0 == '\r' || c0 == ' ') && (c1 == '\n' || c1 == '\r' || c1 == ' ')) {
            return 1;
        }
    }
    return 0;
}

static __always_inline void classify_log_level(char *level, unsigned int fd, const char *msg, u32 len) {
    int is_err = 0;
    int is_warn = 0;
    (void)len;

    #pragma clang loop unroll(full)
    for (int i = 0; i < 44; i++) {
        char c0 = msg[i];
        char c1 = msg[i + 1];
        char c2 = msg[i + 2];
        if (c0 == '\0' || c1 == '\0' || c2 == '\0') break;
        char c3 = msg[i + 3];

        if ((c0 == 'E' || c0 == 'e') && (c1 == 'R' || c1 == 'r') && (c2 == 'R' || c2 == 'r')) {
            is_err = 1;
            break;
        }
        if (c3 != '\0') {
            if ((c0 == 'F' || c0 == 'f') && (c1 == 'A' || c1 == 'a') && (c2 == 'I' || c2 == 'i') && (c3 == 'L' || c3 == 'l')) {
                is_err = 1;
                break;
            }
            if ((c0 == 'F' || c0 == 'f') && (c1 == 'A' || c1 == 'a') && (c2 == 'T' || c2 == 't') && (c3 == 'A' || c3 == 'a')) {
                is_err = 1;
                break;
            }
            if ((c0 == 'C' || c0 == 'c') && (c1 == 'R' || c1 == 'r') && (c2 == 'I' || c2 == 'i') && (c3 == 'T' || c3 == 't')) {
                is_err = 1;
                break;
            }
            if ((c0 == 'W' || c0 == 'w') && (c1 == 'A' || c1 == 'a') && (c2 == 'R' || c2 == 'r') && (c3 == 'N' || c3 == 'n')) {
                is_warn = 1;
                break;
            }
        }
    }

    if (is_err) {
        level[0] = 'E'; level[1] = 'R'; level[2] = 'R'; level[3] = 'O'; level[4] = 'R'; level[5] = '\0';
    } else if (is_warn) {
        level[0] = 'W'; level[1] = 'A'; level[2] = 'R'; level[3] = 'N'; level[4] = '\0';
    } else if (fd == 1) {
        level[0] = 'I'; level[1] = 'N'; level[2] = 'F'; level[3] = 'O'; level[4] = '\0';
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

static __always_inline int is_hex_char(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static __always_inline int parse_container_id(char *dst) {
    if (is_eprobe_comm()) {
        return 0;
    }
    struct task_struct___local *task = (struct task_struct___local *)bpf_get_current_task();
    const char *kn_name = BPF_CORE_READ(task, cgroups, subsys[0], cgroup, kn, name);
    if (!kn_name) {
        kn_name = BPF_CORE_READ(task, cgroups, dfl_cgrp, kn, name);
    }
    if (!kn_name) {
        return 0;
    }

    char buf[128] = {0};
    bpf_probe_read_kernel_str(buf, sizeof(buf), kn_name);

    int start_idx = -1;

    // Check for Docker cgroup prefix: "docker-<id>.scope" or "docker/<id>"
    if (buf[0] == 'd' && buf[1] == 'o' && buf[2] == 'c' && buf[3] == 'k' && buf[4] == 'e' && buf[5] == 'r' && buf[6] == '-') {
        start_idx = 7;
    } else if (buf[0] == 'd' && buf[1] == 'o' && buf[2] == 'c' && buf[3] == 'k' && buf[4] == 'e' && buf[5] == 'r' && buf[6] == '/') {
        start_idx = 7;
    }
    // Check for CRI-Containerd prefix: "cri-containerd-<id>.scope"
    else if (buf[0] == 'c' && buf[1] == 'r' && buf[2] == 'i' && buf[3] == '-' && buf[4] == 'c' && buf[5] == 'o' && buf[6] == 'n' &&
             buf[7] == 't' && buf[8] == 'a' && buf[9] == 'i' && buf[10] == 'n' && buf[11] == 'e' && buf[12] == 'r' && buf[13] == 'd' && buf[14] == '-') {
        start_idx = 15;
    }
    // Check for Podman/Libpod prefix: "libpod-<id>.scope"
    else if (buf[0] == 'l' && buf[1] == 'i' && buf[2] == 'b' && buf[3] == 'p' && buf[4] == 'o' && buf[5] == 'd' && buf[6] == '-') {
        start_idx = 7;
    }
    // Check for raw 12+ character hex container ID (cgroupfs / containerd direct cgroup)
    else if (is_hex_char(buf[0]) && is_hex_char(buf[1]) && is_hex_char(buf[2]) && is_hex_char(buf[3]) &&
             is_hex_char(buf[4]) && is_hex_char(buf[5]) && is_hex_char(buf[6]) && is_hex_char(buf[7]) &&
             is_hex_char(buf[8]) && is_hex_char(buf[9]) && is_hex_char(buf[10]) && is_hex_char(buf[11])) {
        start_idx = 0;
    }

    // Filter out host systemd slices (user.slice, init.scope, containerd.service, systemd-hostnam, etc.)
    if (start_idx < 0) {
        return 0;
    }

    // Extract exact 12-character short container hex ID
    #pragma clang loop unroll(disable)
    for (int i = 0; i < 12; i++) {
        char c = buf[(start_idx + i) & 0x7F];
        if (c == '\0' || c == '.') break;
        dst[i] = c;
    }
    dst[12] = '\0';
    return 1;
}

static __always_inline void record_container_event(const char *cid) {
    struct container_stat_t *st = bpf_map_lookup_elem(&container_stats, (void *)cid);
    if (st) {
        __sync_fetch_and_add(&st->event_count, 1);
    } else {
        struct container_stat_t new_st = {.event_count = 1};
        bpf_map_update_elem(&container_stats, (void *)cid, &new_st, BPF_ANY);
    }
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_sys_execve(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (filter_pid != 0 && pid != filter_pid) {
        return 0;
    }

    char container_id[16] = {0};
    if (!parse_container_id(container_id)) {
        return 0;
    }

    record_container_event(container_id);

    struct proc_event_t *e = bpf_ringbuf_reserve(&proc_events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->pid = pid;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    const char *filename_ptr = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename_ptr);

    struct task_struct___local *task = (struct task_struct___local *)bpf_get_current_task();
    struct task_struct___local *parent = BPF_CORE_READ(task, real_parent);
    e->ppid = BPF_CORE_READ(parent, tgid);

    __builtin_memcpy(e->container_id, container_id, sizeof(e->container_id));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int trace_sched_process_exit(void *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    char container_id[16] = {0};
    if (!parse_container_id(container_id)) {
        return 0;
    }

    struct task_struct___local *task = (struct task_struct___local *)bpf_get_current_task();
    int raw_exit_code = BPF_CORE_READ(task, exit_code);

    if (raw_exit_code == 0) {
        return 0;
    }

    u32 exit_code = 0;
    if ((raw_exit_code & 0x7F) != 0) {
        // Terminated by signal (POSIX 128 + signal, e.g. SIGKILL 137, SIGSEGV 139)
        exit_code = 128 + (raw_exit_code & 0x7F);
    } else {
        // Exited via exit() / exit_group()
        exit_code = (raw_exit_code >> 8) & 0xFF;
    }

    if (exit_code == 0) {
        return 0;
    }

    struct app_crash_event_t *e = bpf_ringbuf_reserve(&app_crash_events, sizeof(*e), 0);
    if (e) {
        e->pid = pid;
        e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        e->exit_code = exit_code;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        __builtin_memcpy(e->container_id, container_id, sizeof(e->container_id));

        const char src[] = "PROC_EXIT_ERR";
        for (int i = 0; i < 14; i++) {
            e->reason[i] = src[i];
        }
        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}

SEC("kprobe/oom_kill_process")
int kprobe_oom_kill_process(void *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    char container_id[16] = {0};
    if (!parse_container_id(container_id)) {
        return 0;
    }

    struct oom_event_t *e = bpf_ringbuf_reserve(&oom_events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->pid = pid;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->exit_code = 137;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memcpy(e->container_id, container_id, sizeof(e->container_id));

    const char src[] = "OOM_KILLED_KPROBE";
    for (int i = 0; i < 18; i++) {
        e->reason[i] = src[i];
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int trace_sys_write(struct trace_event_raw_sys_enter *ctx) {
    unsigned int fd = (unsigned int)ctx->args[0];
    if (fd != 1 && fd != 2) {
        return 0; // Capture both stdout (1) and stderr (2)
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (filter_pid != 0 && pid != filter_pid) {
        return 0;
    }

    char container_id[16] = {0};
    if (!parse_container_id(container_id)) {
        return 0;
    }

    struct task_struct___local *task = (struct task_struct___local *)bpf_get_current_task();
    if (!check_container_stdio(task, container_id, fd)) {
        return 0;
    }

    u32 count = (u32)ctx->args[2];
    count &= 0xFF; // Bitwise mask enforces bounded non-negative scalar (max 255) for verifier

    if (count == 0) {
        return 0;
    }

    const char *buf = (const char *)ctx->args[1];
    u32 read_bytes = count < 255 ? count : 255;

    // Direct Ringbuf Allocation - Bypasses Stack Limit
    struct log_event_t *e = bpf_ringbuf_reserve(&log_events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    bpf_probe_read_user(e->message, read_bytes, buf);
    e->message[read_bytes] = '\0';

    // Drop empty, bare-newline, or single-digit status fragments
    if (is_noise_fragment(e->message, read_bytes)) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    e->pid = pid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memcpy(e->container_id, container_id, sizeof(e->container_id));
    classify_log_level(e->level, fd, e->message, read_bytes);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_writev")
int trace_sys_writev(struct trace_event_raw_sys_enter *ctx) {
    unsigned int fd = (unsigned int)ctx->args[0];
    if (fd != 1 && fd != 2) {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (filter_pid != 0 && pid != filter_pid) {
        return 0;
    }

    char container_id[16] = {0};
    if (!parse_container_id(container_id)) {
        return 0;
    }

    struct task_struct___local *task = (struct task_struct___local *)bpf_get_current_task();
    if (!check_container_stdio(task, container_id, fd)) {
        return 0;
    }

    struct iovec___local {
        void *iov_base;
        unsigned long iov_len;
    } iov;

    const void *iov_ptr = (const void *)ctx->args[1];
    if (!iov_ptr || bpf_probe_read_user(&iov, sizeof(iov), iov_ptr) < 0) {
        return 0;
    }

    u32 count = (u32)iov.iov_len;
    count &= 0xFF;
    if (count == 0 || !iov.iov_base) {
        return 0;
    }

    u32 read_bytes = count < 255 ? count : 255;

    struct log_event_t *e = bpf_ringbuf_reserve(&log_events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    bpf_probe_read_user(e->message, read_bytes, iov.iov_base);
    e->message[read_bytes] = '\0';

    // Drop empty, bare-newline, or single-digit status fragments
    if (is_noise_fragment(e->message, read_bytes)) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    e->pid = pid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memcpy(e->container_id, container_id, sizeof(e->container_id));
    classify_log_level(e->level, fd, e->message, read_bytes);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/tcp_v4_connect")
int kprobe_tcp_v4_connect(struct pt_regs *ctx) {
    struct sock___local *sk = (struct sock___local *)PT_REGS_PARM1(ctx);
    if (!sk) return 0;

    char container_id[16] = {0};
    if (!parse_container_id(container_id)) {
        return 0;
    }

    u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);

    // Drop loopback traffic (127.0.0.0/8)
    if ((daddr & 0x000000FF) == 127 || (saddr & 0x000000FF) == 127) {
        return 0;
    }

    void *sk_ptr = (void *)sk;
    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&conn_start, &sk_ptr, &ts, BPF_ANY);
    return 0;
}

SEC("kprobe/tcp_sendmsg")
int kprobe_tcp_sendmsg(struct pt_regs *ctx) {
    struct sock___local *sk = (struct sock___local *)PT_REGS_PARM1(ctx);
    if (!sk) return 0;

    char container_id[16] = {0};
    if (!parse_container_id(container_id)) {
        return 0;
    }

    u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);

    // Drop loopback traffic (127.0.0.0/8)
    if ((daddr & 0x000000FF) == 127 || (saddr & 0x000000FF) == 127) {
        return 0;
    }

    void *sk_ptr = (void *)sk;
    u64 *tsp = bpf_map_lookup_elem(&conn_start, &sk_ptr);
    if (!tsp) return 0;

    u64 ts = *tsp;
    bpf_map_delete_elem(&conn_start, &sk_ptr);

    u64 now = bpf_ktime_get_ns();
    u64 delta = (now - ts) / 1000;

    struct net_event_t *e = bpf_ringbuf_reserve(&net_events, sizeof(*e), 0);
    if (!e) return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memcpy(e->container_id, container_id, sizeof(e->container_id));

    e->saddr = saddr;
    e->daddr = daddr;
    e->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    e->dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    e->latency_us = delta;

    bpf_ringbuf_submit(e, 0);

    // Accumulate TX bytes into net_stats hash map
    struct container_key_t nkey = {0};
    __builtin_memcpy(nkey.container_id, container_id, 16);
    u64 msg_len = (u64)PT_REGS_PARM3(ctx);
    struct net_stat_t *ns = bpf_map_lookup_elem(&net_stats, &nkey);
    if (ns) {
        __sync_fetch_and_add(&ns->tx_bytes, msg_len);
    } else {
        struct net_stat_t new_ns = {.tx_bytes = msg_len};
        bpf_map_update_elem(&net_stats, &nkey, &new_ns, BPF_ANY);
    }

    return 0;
}

SEC("kprobe/tcp_recvmsg")
int kprobe_tcp_recvmsg(struct pt_regs *ctx) {
    char container_id[16] = {0};
    if (!parse_container_id(container_id)) {
        return 0;
    }

    struct container_key_t rkey = {0};
    __builtin_memcpy(rkey.container_id, container_id, 16);
    u64 msg_len = (u64)PT_REGS_PARM3(ctx);

    struct net_stat_t *ns = bpf_map_lookup_elem(&net_stats, &rkey);
    if (ns) {
        __sync_fetch_and_add(&ns->rx_bytes, msg_len);
    } else {
        struct net_stat_t new_ns = {.rx_bytes = msg_len};
        bpf_map_update_elem(&net_stats, &rkey, &new_ns, BPF_ANY);
    }
    return 0;
}

struct trace_event_raw_block_rq_completion___local {
    unsigned int nr_sector;
    char rwbs[8];
} __attribute__((preserve_access_index));

SEC("tracepoint/block/block_rq_issue")
int trace_block_rq_issue(void *ctx) {
    if (is_eprobe_comm() || !is_container_context()) {
        return 0;
    }
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&io_start, &pid_tgid, &ts, BPF_ANY);
    return 0;
}

SEC("tracepoint/block/block_rq_complete")
int trace_block_rq_complete(struct trace_event_raw_block_rq_completion___local *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 *tsp = bpf_map_lookup_elem(&io_start, &pid_tgid);
    if (!tsp) return 0;

    u64 ts = *tsp;
    bpf_map_delete_elem(&io_start, &pid_tgid);

    char container_id[16] = {0};
    if (!parse_container_id(container_id)) {
        return 0;
    }

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
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memcpy(e->container_id, container_id, sizeof(e->container_id));

    if (is_write) {
        e->rwflag[0] = 'W'; e->rwflag[1] = 'R'; e->rwflag[2] = 'I'; e->rwflag[3] = 'T'; e->rwflag[4] = 'E'; e->rwflag[5] = '\0';
    } else {
        e->rwflag[0] = 'R'; e->rwflag[1] = 'E'; e->rwflag[2] = 'A'; e->rwflag[3] = 'D'; e->rwflag[4] = '\0';
    }
    e->bytes = io_bytes;
    e->latency_us = delta;

    bpf_ringbuf_submit(e, 0);

    // Accumulate I/O bytes into io_stats hash map
    struct container_key_t iokey = {0};
    __builtin_memcpy(iokey.container_id, container_id, 16);
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

// Removed trace_event_raw_cgroup struct because it's incompatible with custom kernels.
// We now use raw_tracepoints which provide direct kernel pointers.
// Scans a cgroup path (in per-CPU map memory) for container runtime prefixes.
// Architecture mirrors the proven parse_container_id() at L286:
//   Phase 1: Search loop finds prefix, sets start offset, breaks immediately
//   Phase 2: Single small copy loop OUTSIDE the search loop using & 0x7F masking
// This keeps copy logic out of the search loop body, avoiding verifier state explosion.
static __always_inline int parse_container_id_from_path(const char *path, char *out_id) {
    int start = -1;

    // Phase 1: Search for container runtime prefix
    #pragma clang loop unroll(disable)
    for (int i = 0; i < 128; i++) {
        if (path[i] == '\0') break;

        // Check "docker-" (len 7)
        if (path[i] == 'd' && path[i+1] == 'o' && path[i+2] == 'c' &&
            path[i+3] == 'k' && path[i+4] == 'e' && path[i+5] == 'r' && path[i+6] == '-') {
            start = i + 7; break;
        }
        // Check "cri-containerd-" (len 15)
        if (path[i] == 'c' && path[i+1] == 'r' && path[i+2] == 'i' && path[i+3] == '-' &&
            path[i+4] == 'c' && path[i+5] == 'o' && path[i+6] == 'n' && path[i+7] == 't' &&
            path[i+8] == 'a' && path[i+9] == 'i' && path[i+10] == 'n' && path[i+11] == 'e' &&
            path[i+12] == 'r' && path[i+13] == 'd' && path[i+14] == '-') {
            start = i + 15; break;
        }
        // Check "containerd-" (len 11)
        if (path[i] == 'c' && path[i+1] == 'o' && path[i+2] == 'n' && path[i+3] == 't' &&
            path[i+4] == 'a' && path[i+5] == 'i' && path[i+6] == 'n' && path[i+7] == 'e' &&
            path[i+8] == 'r' && path[i+9] == 'd' && path[i+10] == '-') {
            start = i + 11; break;
        }
        // Check "crio-" (len 5)
        if (path[i] == 'c' && path[i+1] == 'r' && path[i+2] == 'i' && path[i+3] == 'o' && path[i+4] == '-') {
            start = i + 5; break;
        }
        // Check "libpod-" (len 7)
        if (path[i] == 'l' && path[i+1] == 'i' && path[i+2] == 'b' &&
            path[i+3] == 'p' && path[i+4] == 'o' && path[i+5] == 'd' && path[i+6] == '-') {
            start = i + 7; break;
        }
        // Check "/docker/" (len 8)
        if (path[i] == '/' && path[i+1] == 'd' && path[i+2] == 'o' && path[i+3] == 'c' &&
            path[i+4] == 'k' && path[i+5] == 'e' && path[i+6] == 'r' && path[i+7] == '/') {
            start = i + 8; break;
        }
        // Check "/containers/" (len 12)
        if (path[i] == '/' && path[i+1] == 'c' && path[i+2] == 'o' && path[i+3] == 'n' &&
            path[i+4] == 't' && path[i+5] == 'a' && path[i+6] == 'i' && path[i+7] == 'n' &&
            path[i+8] == 'e' && path[i+9] == 'r' && path[i+10] == 's' && path[i+11] == '/') {
            start = i + 12; break;
        }
    }

    if (start < 0) return 0;

    // Phase 2: Extract 12-char container ID (proven pattern from parse_container_id L319-L327)
    #pragma clang loop unroll(disable)
    for (int j = 0; j < 12; j++) {
        char c = path[(start + j) & 0x7F];
        if (c == '\0' || c == '.') break;
        out_id[j] = c;
    }
    out_id[12] = '\0';
    return 1;
}

SEC("raw_tracepoint/cgroup_mkdir")
int raw_trace_cgroup_mkdir(struct bpf_raw_tracepoint_args *ctx) {
    // raw tracepoint provides direct arguments from kernel signature:
    // (struct cgroup *cgrp, const char *path)
    const char *raw_path = (const char *)ctx->args[1];
    if (!raw_path) return 0;

    // Use per-CPU map as scratch buffer: map memory is always fully initialized
    // from the verifier's perspective, eliminating dynamic-length tracking issues.
    u32 zero = 0;
    struct cgroup_path_val *buf = bpf_map_lookup_elem(&cgroup_path_buf, &zero);
    if (!buf) return 0;

    if (bpf_probe_read_kernel_str(buf->path, sizeof(buf->path), raw_path) <= 0)
        return 0;

    char container_id[16] = {0};
    if (!parse_container_id_from_path(buf->path, container_id))
        return 0;

    struct lifecycle_event_t *e = bpf_ringbuf_reserve(&lifecycle_events, sizeof(*e), 0);
    if (!e) return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;
    __builtin_memcpy(e->container_id, container_id, sizeof(e->container_id));
    __builtin_memcpy(e->action, "CREATED", 8);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("raw_tracepoint/cgroup_rmdir")
int raw_trace_cgroup_rmdir(struct bpf_raw_tracepoint_args *ctx) {
    const char *raw_path = (const char *)ctx->args[1];
    if (!raw_path) return 0;

    u32 zero = 0;
    struct cgroup_path_val *buf = bpf_map_lookup_elem(&cgroup_path_buf, &zero);
    if (!buf) return 0;

    if (bpf_probe_read_kernel_str(buf->path, sizeof(buf->path), raw_path) <= 0)
        return 0;

    char container_id[16] = {0};
    if (!parse_container_id_from_path(buf->path, container_id))
        return 0;

    struct lifecycle_event_t *e = bpf_ringbuf_reserve(&lifecycle_events, sizeof(*e), 0);
    if (!e) return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;
    __builtin_memcpy(e->container_id, container_id, sizeof(e->container_id));
    __builtin_memcpy(e->action, "DESTROYED", 10);

    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&container_stdio_map, container_id);
    return 0;
}

SEC("tracepoint/kmem/mm_page_alloc")
int trace_mm_page_alloc(void *ctx) {
    char container_id[16] = {0};
    if (!parse_container_id(container_id)) {
        return 0;
    }
    record_container_event(container_id);

    // Accumulate RSS into mem_stats hash map (+4096 bytes per page)
    struct container_key_t mkey = {0};
    __builtin_memcpy(mkey.container_id, container_id, 16);
    struct mem_stat_t *ms = bpf_map_lookup_elem(&mem_stats, &mkey);
    if (ms) {
        __sync_fetch_and_add(&ms->rss_bytes, 4096);
    } else {
        struct mem_stat_t new_ms = {.rss_bytes = 4096};
        bpf_map_update_elem(&mem_stats, &mkey, &new_ms, BPF_ANY);
    }
    return 0;
}

SEC("tracepoint/kmem/mm_page_free")
int trace_mm_page_free(void *ctx) {
    char container_id[16] = {0};
    if (!parse_container_id(container_id)) {
        return 0;
    }

    // Subtract RSS from mem_stats hash map (-4096 bytes per page)
    struct container_key_t mkey = {0};
    __builtin_memcpy(mkey.container_id, container_id, 16);
    struct mem_stat_t *ms = bpf_map_lookup_elem(&mem_stats, &mkey);
    if (ms && ms->rss_bytes >= 4096) {
        __sync_fetch_and_add(&ms->rss_bytes, (u64)-4096);
    }
    return 0;
}

struct trace_event_raw_sched_stat_runtime___local {
    u64 runtime;
} __attribute__((preserve_access_index));

SEC("tracepoint/sched/sched_stat_runtime")
int trace_sched_stat_runtime(struct trace_event_raw_sched_stat_runtime___local *ctx) {
    // PID namespace guard: reject host-level processes
    if (!is_container_context()) {
        return 0;
    }

    char container_id[16] = {0};
    if (!parse_container_id(container_id)) {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (filter_pid != 0 && pid != filter_pid) {
        return 0;
    }

    record_container_event(container_id);

    u64 runtime = 0;
    bpf_core_read(&runtime, sizeof(runtime), &ctx->runtime);
    if (runtime == 0) {
        runtime = 1000000;
    }

    // In-kernel CPU runtime aggregation: exact nanoseconds spent on CPU
    struct container_key_t ckey = {0};
    __builtin_memcpy(ckey.container_id, container_id, 16);
    struct cpu_stat_t *cs = bpf_map_lookup_elem(&cpu_stats, &ckey);
    if (cs) {
        __sync_fetch_and_add(&cs->cpu_time_ns, runtime);
    } else {
        struct cpu_stat_t new_cs = {.cpu_time_ns = runtime};
        bpf_map_update_elem(&cpu_stats, &ckey, &new_cs, BPF_ANY);
    }
    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
