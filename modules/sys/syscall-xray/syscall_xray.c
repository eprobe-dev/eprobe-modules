// SPDX-License-Identifier: GPL-2.0-only OR MIT
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/eprobe_tracepoint.h>
#include <bpf/eprobe_cgroup.h>

typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;

#define AF_UNIX_LOCAL  1
#define AF_INET_LOCAL  2
#define AF_INET6_LOCAL 10

#define SYS_NR_CONNECT 42
#define SYS_NR_OPENAT  257
#define SYS_NR_OPENAT2 437

#define ERR_EPERM        1
#define ERR_ENOENT       2
#define ERR_EINTR        4
#define ERR_EIO          5
#define ERR_EBADF        9
#define ERR_EAGAIN       11
#define ERR_ENOMEM       12
#define ERR_EACCES       13
#define ERR_EFAULT       14
#define ERR_EBUSY        16
#define ERR_EEXIST       17
#define ERR_ENOTDIR      20
#define ERR_EISDIR       21
#define ERR_EINVAL       22
#define ERR_EMFILE       24
#define ERR_ENOSPC       28
#define ERR_EPIPE        32
#define ERR_ENAMETOOLONG 36
#define ERR_ENOSYS       38
#define ERR_EADDRINUSE   98
#define ERR_EADDRNOTAVAIL 99
#define ERR_ECONNRESET   104
#define ERR_ETIMEDOUT    110
#define ERR_ECONNREFUSED 111
#define ERR_EHOSTUNREACH 113
#define ERR_EINPROGRESS  115

#define SPEC_KIND_OPENAT  1
#define SPEC_KIND_OPENAT2 2
#define SPEC_KIND_CONNECT 3

#define SET_LIT(dst, lit) __builtin_memcpy((dst), (lit), sizeof(lit))

// -----------------------------------------------------------------------------
// Exported Telemetry Structs (1:1 Schema Parity with manifest.yaml)
// -----------------------------------------------------------------------------

struct syscall_event_t {
    u32 pid;
    u32 tid;
    u32 ppid;
    u32 syscall_id;
    char comm[16];
    char container_id[16];
    char syscall[20];
    u32 daddr;
    u16 dport;
    u16 errno_code;
    char errno_name[16];
    u64 duration_us;
    char level[8];
    char target[128];
} __attribute__((packed));

_Static_assert(sizeof(struct syscall_event_t) == 236, "syscall_event_t must be 236 bytes");

struct syscall_stat_key_t {
    char syscall[20];
};

struct syscall_stat_t {
    u64 total_ns;
    u64 call_count;
    u64 error_count;
};

_Static_assert(sizeof(struct syscall_stat_key_t) == 20, "syscall_stat_key_t must be 20 bytes");
_Static_assert(sizeof(struct syscall_stat_t) == 24, "syscall_stat_t must be 24 bytes");

// -----------------------------------------------------------------------------
// Internal Correlation & Scratch Structures
// -----------------------------------------------------------------------------

struct inflight_sys_t {
    u64 start_ns;
    u32 syscall_id;
    u32 pad;
};

struct spec_arg_t {
    u64 start_ns;
    u32 daddr;
    u16 dport;
    u16 kind;
    char target[128];
};

struct scratch_t {
    struct spec_arg_t spec;
};

struct eprobe_sockaddr_hdr {
    u16 sa_family;
};

struct eprobe_sockaddr_in {
    u16 sin_family;
    u16 sin_port;
    u32 sin_addr;
};

struct eprobe_sockaddr_in6 {
    u16 sin6_family;
    u16 sin6_port;
    u32 sin6_flowinfo;
    u8 sin6_addr[16];
};

struct task_struct___local {
    struct task_struct___local *real_parent;
    int tgid;
} __attribute__((preserve_access_index));

// -----------------------------------------------------------------------------
// BPF Maps
// -----------------------------------------------------------------------------

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); // 4MB ring buffer
} syscall_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, struct syscall_stat_key_t);
    __type(value, struct syscall_stat_t);
} syscall_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, u32); // tid
    __type(value, struct inflight_sys_t);
} inflight_syscalls SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, u32); // tid
    __type(value, struct spec_arg_t);
} spec_args_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct scratch_t);
} scratch_map SEC(".maps");

// -----------------------------------------------------------------------------
// Runtime-Configurable Variables (CLI Flags via .rodata)
// -----------------------------------------------------------------------------

volatile const u32 filter_pid = 0;            // --pid
volatile const u8 errors_only = 0;            // --errors-only
volatile const u64 slow_threshold_us = 10000; // --slow-us (default 10ms)
volatile const u8 include_transient = 0;      // --include-transient

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

static __always_inline u16 eprobe_ntohs(u16 v) {
    return (u16)((v << 8) | (v >> 8));
}

static __always_inline int is_eprobe_comm(const char *comm) {
    return comm[0] == 'e' && comm[1] == 'p' && comm[2] == 'r' &&
           comm[3] == 'o' && comm[4] == 'b' && comm[5] == 'e';
}

static __always_inline int is_idle_sleep_syscall(u32 id) {
    switch (id) {
    case 7:   // poll
    case 23:  // select
    case 35:  // nanosleep
    case 202: // futex
    case 230: // clock_nanosleep
    case 232: // epoll_wait
    case 271: // pselect6
    case 272: // ppoll
    case 281: // epoll_pwait
    case 449: // futex_waitv
        return 1;
    default:
        return 0;
    }
}

static __always_inline void resolve_syscall_name(u32 id, char *dst) {
    switch (id) {
    case 0:   SET_LIT(dst, "read"); return;
    case 1:   SET_LIT(dst, "write"); return;
    case 2:   SET_LIT(dst, "open"); return;
    case 3:   SET_LIT(dst, "close"); return;
    case 4:   SET_LIT(dst, "stat"); return;
    case 5:   SET_LIT(dst, "fstat"); return;
    case 6:   SET_LIT(dst, "lstat"); return;
    case 7:   SET_LIT(dst, "poll"); return;
    case 8:   SET_LIT(dst, "lseek"); return;
    case 9:   SET_LIT(dst, "mmap"); return;
    case 10:  SET_LIT(dst, "mprotect"); return;
    case 11:  SET_LIT(dst, "munmap"); return;
    case 12:  SET_LIT(dst, "brk"); return;
    case 16:  SET_LIT(dst, "ioctl"); return;
    case 17:  SET_LIT(dst, "pread64"); return;
    case 18:  SET_LIT(dst, "pwrite64"); return;
    case 19:  SET_LIT(dst, "readv"); return;
    case 20:  SET_LIT(dst, "writev"); return;
    case 21:  SET_LIT(dst, "access"); return;
    case 22:  SET_LIT(dst, "pipe"); return;
    case 23:  SET_LIT(dst, "select"); return;
    case 32:  SET_LIT(dst, "dup"); return;
    case 33:  SET_LIT(dst, "dup2"); return;
    case 35:  SET_LIT(dst, "nanosleep"); return;
    case 39:  SET_LIT(dst, "getpid"); return;
    case 41:  SET_LIT(dst, "socket"); return;
    case 42:  SET_LIT(dst, "connect"); return;
    case 43:  SET_LIT(dst, "accept"); return;
    case 44:  SET_LIT(dst, "sendto"); return;
    case 45:  SET_LIT(dst, "recvfrom"); return;
    case 46:  SET_LIT(dst, "sendmsg"); return;
    case 47:  SET_LIT(dst, "recvmsg"); return;
    case 48:  SET_LIT(dst, "shutdown"); return;
    case 49:  SET_LIT(dst, "bind"); return;
    case 50:  SET_LIT(dst, "listen"); return;
    case 51:  SET_LIT(dst, "getsockname"); return;
    case 52:  SET_LIT(dst, "getpeername"); return;
    case 54:  SET_LIT(dst, "setsockopt"); return;
    case 55:  SET_LIT(dst, "getsockopt"); return;
    case 56:  SET_LIT(dst, "clone"); return;
    case 57:  SET_LIT(dst, "fork"); return;
    case 58:  SET_LIT(dst, "vfork"); return;
    case 59:  SET_LIT(dst, "execve"); return;
    case 60:  SET_LIT(dst, "exit"); return;
    case 61:  SET_LIT(dst, "wait4"); return;
    case 62:  SET_LIT(dst, "kill"); return;
    case 72:  SET_LIT(dst, "fcntl"); return;
    case 74:  SET_LIT(dst, "fsync"); return;
    case 75:  SET_LIT(dst, "fdatasync"); return;
    case 78:  SET_LIT(dst, "getdents"); return;
    case 79:  SET_LIT(dst, "getcwd"); return;
    case 80:  SET_LIT(dst, "chdir"); return;
    case 82:  SET_LIT(dst, "rename"); return;
    case 83:  SET_LIT(dst, "mkdir"); return;
    case 84:  SET_LIT(dst, "rmdir"); return;
    case 87:  SET_LIT(dst, "unlink"); return;
    case 88:  SET_LIT(dst, "symlink"); return;
    case 89:  SET_LIT(dst, "readlink"); return;
    case 90:  SET_LIT(dst, "chmod"); return;
    case 92:  SET_LIT(dst, "chown"); return;
    case 102: SET_LIT(dst, "getuid"); return;
    case 186: SET_LIT(dst, "gettid"); return;
    case 202: SET_LIT(dst, "futex"); return;
    case 217: SET_LIT(dst, "getdents64"); return;
    case 228: SET_LIT(dst, "clock_gettime"); return;
    case 230: SET_LIT(dst, "clock_nanosleep"); return;
    case 231: SET_LIT(dst, "exit_group"); return;
    case 232: SET_LIT(dst, "epoll_wait"); return;
    case 233: SET_LIT(dst, "epoll_ctl"); return;
    case 257: SET_LIT(dst, "openat"); return;
    case 262: SET_LIT(dst, "newfstatat"); return;
    case 263: SET_LIT(dst, "unlinkat"); return;
    case 264: SET_LIT(dst, "renameat"); return;
    case 268: SET_LIT(dst, "fchmodat"); return;
    case 269: SET_LIT(dst, "faccessat"); return;
    case 271: SET_LIT(dst, "pselect6"); return;
    case 272: SET_LIT(dst, "ppoll"); return;
    case 281: SET_LIT(dst, "epoll_pwait"); return;
    case 288: SET_LIT(dst, "accept4"); return;
    case 292: SET_LIT(dst, "dup3"); return;
    case 293: SET_LIT(dst, "pipe2"); return;
    case 302: SET_LIT(dst, "prlimit64"); return;
    case 318: SET_LIT(dst, "getrandom"); return;
    case 322: SET_LIT(dst, "execveat"); return;
    case 332: SET_LIT(dst, "statx"); return;
    case 435: SET_LIT(dst, "clone3"); return;
    case 437: SET_LIT(dst, "openat2"); return;
    case 439: SET_LIT(dst, "faccessat2"); return;
    case 449: SET_LIT(dst, "futex_waitv"); return;
    default:
        dst[0] = 's'; dst[1] = 'y'; dst[2] = 's'; dst[3] = '_';
        if (id >= 100 && id < 1000) {
            dst[4] = (char)('0' + (id / 100));
            dst[5] = (char)('0' + ((id / 10) % 10));
            dst[6] = (char)('0' + (id % 10));
            dst[7] = '\0';
        } else if (id >= 10 && id < 100) {
            dst[4] = (char)('0' + (id / 10));
            dst[5] = (char)('0' + (id % 10));
            dst[6] = '\0';
        } else if (id < 10) {
            dst[4] = (char)('0' + id);
            dst[5] = '\0';
        } else {
            dst[4] = 'o'; dst[5] = 't'; dst[6] = 'h'; dst[7] = 'e'; dst[8] = 'r'; dst[9] = '\0';
        }
        return;
    }
}

static __always_inline void resolve_errno(long ret, u16 *code_out, char *name_out) {
    if (ret >= 0) {
        *code_out = 0;
        SET_LIT(name_out, "OK");
        return;
    }
    long neg = -ret;
    u16 code = (neg > 0 && neg <= 4095) ? (u16)neg : 0;
    *code_out = code;

    switch (code) {
    case ERR_EPERM:        SET_LIT(name_out, "EPERM"); return;
    case ERR_ENOENT:       SET_LIT(name_out, "ENOENT"); return;
    case ERR_EINTR:        SET_LIT(name_out, "EINTR"); return;
    case ERR_EIO:          SET_LIT(name_out, "EIO"); return;
    case ERR_EBADF:        SET_LIT(name_out, "EBADF"); return;
    case ERR_EAGAIN:       SET_LIT(name_out, "EAGAIN"); return;
    case ERR_ENOMEM:       SET_LIT(name_out, "ENOMEM"); return;
    case ERR_EACCES:       SET_LIT(name_out, "EACCES"); return;
    case ERR_EFAULT:       SET_LIT(name_out, "EFAULT"); return;
    case ERR_EBUSY:        SET_LIT(name_out, "EBUSY"); return;
    case ERR_EEXIST:       SET_LIT(name_out, "EEXIST"); return;
    case ERR_ENOTDIR:      SET_LIT(name_out, "ENOTDIR"); return;
    case ERR_EISDIR:       SET_LIT(name_out, "EISDIR"); return;
    case ERR_EINVAL:       SET_LIT(name_out, "EINVAL"); return;
    case ERR_EMFILE:       SET_LIT(name_out, "EMFILE"); return;
    case ERR_ENOSPC:       SET_LIT(name_out, "ENOSPC"); return;
    case ERR_EPIPE:        SET_LIT(name_out, "EPIPE"); return;
    case ERR_ENAMETOOLONG: SET_LIT(name_out, "ENAMETOOLONG"); return;
    case ERR_ENOSYS:       SET_LIT(name_out, "ENOSYS"); return;
    case ERR_EADDRINUSE:   SET_LIT(name_out, "EADDRINUSE"); return;
    case ERR_EADDRNOTAVAIL:SET_LIT(name_out, "EADDRNOTAVAIL"); return;
    case ERR_ECONNRESET:   SET_LIT(name_out, "ECONNRESET"); return;
    case ERR_ETIMEDOUT:    SET_LIT(name_out, "ETIMEDOUT"); return;
    case ERR_ECONNREFUSED: SET_LIT(name_out, "ECONNREFUSED"); return;
    case ERR_EHOSTUNREACH: SET_LIT(name_out, "EHOSTUNREACH"); return;
    case ERR_EINPROGRESS:  SET_LIT(name_out, "EINPROGRESS"); return;
    default:               SET_LIT(name_out, "ERRNO"); return;
    }
}

static __always_inline int is_transient_errno(u16 code) {
    return code == ERR_EAGAIN || code == ERR_EINPROGRESS;
}

static __always_inline u32 read_current_ppid(void) {
    struct task_struct___local *task = (struct task_struct___local *)bpf_get_current_task();
    if (!task) return 0;
    struct task_struct___local *parent = BPF_CORE_READ(task, real_parent);
    if (!parent) return 0;
    return (u32)BPF_CORE_READ(parent, tgid);
}

static __always_inline void populate_severity(u16 err_code, u64 duration_us, char *level) {
    if (duration_us >= 1000000ULL) {
        SET_LIT(level, "CRITICAL");
        return;
    }
    if (err_code != 0) {
        if (err_code == ERR_ECONNREFUSED || err_code == ERR_ETIMEDOUT ||
            err_code == ERR_EACCES || err_code == ERR_EPERM ||
            err_code == ERR_EIO || err_code == ERR_ENOSPC ||
            err_code == ERR_ENOMEM || err_code == ERR_EMFILE) {
            SET_LIT(level, "ERROR");
        } else {
            SET_LIT(level, "WARN");
        }
        return;
    }
    if (duration_us >= 100000ULL) {
        SET_LIT(level, "ERROR");
    } else {
        SET_LIT(level, "WARN");
    }
}

static __always_inline void update_syscall_stats(const char *sys_name, u64 delta_ns, int is_error) {
    struct syscall_stat_key_t key = {0};
    __builtin_memcpy(key.syscall, sys_name, sizeof(key.syscall));

    struct syscall_stat_t *st = bpf_map_lookup_elem(&syscall_stats, &key);
    if (st) {
        __sync_fetch_and_add(&st->total_ns, delta_ns);
        __sync_fetch_and_add(&st->call_count, 1);
        if (is_error) {
            __sync_fetch_and_add(&st->error_count, 1);
        }
    } else {
        struct syscall_stat_t new_st = {
            .total_ns = delta_ns,
            .call_count = 1,
            .error_count = is_error ? 1 : 0,
        };
        bpf_map_update_elem(&syscall_stats, &key, &new_st, BPF_ANY);
    }
}

static __always_inline void emit_syscall_event(
    u32 pid, u32 tid, const char *comm, u32 syscall_id, const char *sys_name,
    u32 daddr, u16 dport, u16 err_code, const char *err_name,
    u64 duration_us, const char *target_buf_128
) {
    struct syscall_event_t *e = bpf_ringbuf_reserve(&syscall_events, sizeof(*e), 0);
    if (!e) return;

    __builtin_memset(e, 0, sizeof(*e));
    e->pid = pid;
    e->tid = tid;
    e->ppid = read_current_ppid();
    e->syscall_id = syscall_id;
    __builtin_memcpy(e->comm, comm, 16);
    if (!parse_container_id(e->container_id)) {
        SET_LIT(e->container_id, "host");
    }
    __builtin_memcpy(e->syscall, sys_name, 20);
    e->daddr = daddr;
    e->dport = dport;
    e->errno_code = err_code;
    __builtin_memcpy(e->errno_name, err_name, 16);
    e->duration_us = duration_us;
    populate_severity(err_code, duration_us, e->level);
    if (target_buf_128) {
        // target_buf_128 must point to a >= 128-byte buffer (e.g. spec_arg_t.target), never a short .rodata string literal.
        __builtin_memcpy(e->target, target_buf_128, sizeof(e->target));
        e->target[sizeof(e->target) - 1] = '\0';
    }

    bpf_ringbuf_submit(e, 0);
}

// -----------------------------------------------------------------------------
// Specialized Syscall Tracepoints: openat, openat2, connect
// -----------------------------------------------------------------------------

static __always_inline int handle_openat_enter(const char *filename, u16 kind) {
    char comm[16] = {0};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (is_eprobe_comm(comm)) return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    if (filter_pid != 0 && pid != filter_pid) return 0;

    u32 zero = 0;
    struct scratch_t *sc = bpf_map_lookup_elem(&scratch_map, &zero);
    if (!sc) return 0;

    __builtin_memset(&sc->spec, 0, sizeof(sc->spec));
    sc->spec.start_ns = bpf_ktime_get_ns();
    sc->spec.kind = kind;
    if (filename) {
        bpf_probe_read_user_str(sc->spec.target, sizeof(sc->spec.target), filename);
    }

    bpf_map_update_elem(&spec_args_map, &tid, &sc->spec, BPF_ANY);
    return 0;
}

static __always_inline int handle_spec_exit(long ret, u32 syscall_id) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    if (filter_pid != 0 && pid != filter_pid) return 0;

    struct spec_arg_t *arg = bpf_map_lookup_elem(&spec_args_map, &tid);
    if (!arg) return 0;

    u64 now = bpf_ktime_get_ns();
    u64 delta_ns = (now > arg->start_ns) ? (now - arg->start_ns) : 0;
    u64 duration_us = delta_ns / 1000ULL;
    u32 daddr = arg->daddr;
    u16 dport = arg->dport;

    u16 err_code = 0;
    char err_name[16] = {0};
    resolve_errno(ret, &err_code, err_name);

    u64 thresh = slow_threshold_us > 0 ? slow_threshold_us : 10000ULL;
    int transient = is_transient_errno(err_code);
    int should_emit = 0;

    if (errors_only) {
        if (err_code != 0 && (!transient || include_transient)) {
            should_emit = 1;
        }
    } else {
        if (err_code != 0 && (!transient || include_transient)) {
            should_emit = 1;
        } else if (duration_us >= thresh) {
            should_emit = 1;
        }
    }

    if (should_emit) {
        char comm[16] = {0};
        bpf_get_current_comm(&comm, sizeof(comm));
        if (!is_eprobe_comm(comm)) {
            char sys_name[20] = {0};
            resolve_syscall_name(syscall_id, sys_name);
            emit_syscall_event(pid, tid, comm, syscall_id, sys_name, daddr, dport, err_code, err_name, duration_us, arg->target);
        }
    }

    bpf_map_delete_elem(&spec_args_map, &tid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_sys_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    const char *filename = (const char *)ctx->args[1];
    return handle_openat_enter(filename, SPEC_KIND_OPENAT);
}

SEC("tracepoint/syscalls/sys_exit_openat")
int trace_sys_exit_openat(struct trace_event_raw_sys_exit *ctx) {
    return handle_spec_exit(ctx->ret, SYS_NR_OPENAT);
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int trace_sys_enter_openat2(struct trace_event_raw_sys_enter *ctx) {
    const char *filename = (const char *)ctx->args[1];
    return handle_openat_enter(filename, SPEC_KIND_OPENAT2);
}

SEC("tracepoint/syscalls/sys_exit_openat2")
int trace_sys_exit_openat2(struct trace_event_raw_sys_exit *ctx) {
    return handle_spec_exit(ctx->ret, SYS_NR_OPENAT2);
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_sys_enter_connect(struct trace_event_raw_sys_enter *ctx) {
    char comm[16] = {0};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (is_eprobe_comm(comm)) return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    if (filter_pid != 0 && pid != filter_pid) return 0;

    u32 zero = 0;
    struct scratch_t *sc = bpf_map_lookup_elem(&scratch_map, &zero);
    if (!sc) return 0;

    __builtin_memset(&sc->spec, 0, sizeof(sc->spec));
    sc->spec.start_ns = bpf_ktime_get_ns();
    sc->spec.kind = SPEC_KIND_CONNECT;
    SET_LIT(sc->spec.target, "socket");

    const void *uservaddr = (const void *)ctx->args[1];
    u32 addrlen = (u32)ctx->args[2];
    addrlen &= 0xFF;

    if (uservaddr && addrlen >= sizeof(struct eprobe_sockaddr_hdr)) {
        struct eprobe_sockaddr_hdr hdr = {0};
        if (bpf_probe_read_user(&hdr, sizeof(hdr), uservaddr) == 0) {
            if (hdr.sa_family == AF_INET_LOCAL && addrlen >= sizeof(struct eprobe_sockaddr_in)) {
                struct eprobe_sockaddr_in sin = {0};
                if (bpf_probe_read_user(&sin, sizeof(sin), uservaddr) == 0) {
                    sc->spec.daddr = sin.sin_addr;
                    sc->spec.dport = eprobe_ntohs(sin.sin_port);
                    SET_LIT(sc->spec.target, "AF_INET");
                }
            } else if (hdr.sa_family == AF_INET6_LOCAL && addrlen >= sizeof(struct eprobe_sockaddr_in6)) {
                struct eprobe_sockaddr_in6 sin6 = {0};
                if (bpf_probe_read_user(&sin6, sizeof(sin6), uservaddr) == 0) {
                    sc->spec.dport = eprobe_ntohs(sin6.sin6_port);
                    SET_LIT(sc->spec.target, "AF_INET6");
                }
            } else if (hdr.sa_family == AF_UNIX_LOCAL && addrlen > 2) {
                bpf_probe_read_user_str(sc->spec.target, sizeof(sc->spec.target), (const char *)uservaddr + 2);
                if (sc->spec.target[0] == '\0') {
                    SET_LIT(sc->spec.target, "unix:abstract");
                }
            }
        }
    }

    bpf_map_update_elem(&spec_args_map, &tid, &sc->spec, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int trace_sys_exit_connect(struct trace_event_raw_sys_exit *ctx) {
    return handle_spec_exit(ctx->ret, SYS_NR_CONNECT);
}

// -----------------------------------------------------------------------------
// Raw Tracepoints: Host/PID-Wide Syscall Summary & Generic Slow/Error Stream
// -----------------------------------------------------------------------------

SEC("raw_tracepoint/sys_enter")
int raw_trace_sys_enter(struct bpf_raw_tracepoint_args *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    if (filter_pid != 0 && pid != filter_pid) {
        return 0;
    }

    char comm[16] = {0};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (is_eprobe_comm(comm)) {
        return 0;
    }

    struct inflight_sys_t entry = {
        .start_ns = bpf_ktime_get_ns(),
        .syscall_id = (u32)ctx->args[1],
        .pad = 0,
    };
    bpf_map_update_elem(&inflight_syscalls, &tid, &entry, BPF_ANY);
    return 0;
}

SEC("raw_tracepoint/sys_exit")
int raw_trace_sys_exit(struct bpf_raw_tracepoint_args *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    if (filter_pid != 0 && pid != filter_pid) {
        return 0;
    }

    struct inflight_sys_t *entry = bpf_map_lookup_elem(&inflight_syscalls, &tid);
    if (!entry) {
        return 0;
    }

    u64 start_ns = entry->start_ns;
    u32 syscall_id = entry->syscall_id;
    bpf_map_delete_elem(&inflight_syscalls, &tid);

    char comm[16] = {0};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (is_eprobe_comm(comm)) {
        return 0;
    }

    u64 now = bpf_ktime_get_ns();
    u64 delta_ns = (now > start_ns) ? (now - start_ns) : 0;
    u64 duration_us = delta_ns / 1000ULL;

    long ret = (long)ctx->args[1];
    u16 err_code = 0;
    char err_name[16] = {0};
    resolve_errno(ret, &err_code, err_name);

    char sys_name[20] = {0};
    resolve_syscall_name(syscall_id, sys_name);

    // 1. Always update 1Hz strace -c style leaderboard (including openat/openat2/connect)
    update_syscall_stats(sys_name, delta_ns, err_code != 0);

    // 2. Specialized tracepoints emit detailed openat/openat2/connect records to syscall_events
    if (syscall_id == SYS_NR_OPENAT || syscall_id == SYS_NR_OPENAT2 || syscall_id == SYS_NR_CONNECT) {
        return 0;
    }

    u64 thresh = slow_threshold_us > 0 ? slow_threshold_us : 10000ULL;
    int transient = is_transient_errno(err_code);
    int idle_wait = is_idle_sleep_syscall(syscall_id);
    int should_emit = 0;

    if (errors_only) {
        if (err_code != 0 && (!transient || include_transient)) {
            should_emit = 1;
        }
    } else {
        if (err_code != 0 && (!transient || include_transient)) {
            should_emit = 1;
        } else if (!idle_wait && duration_us >= thresh) {
            should_emit = 1;
        }
    }

    if (should_emit) {
        emit_syscall_event(pid, tid, comm, syscall_id, sys_name, 0, 0, err_code, err_name, duration_us, NULL);
    }

    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
