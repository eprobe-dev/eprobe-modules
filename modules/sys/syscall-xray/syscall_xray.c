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
#define SET_LIT_BOUNDED(dst, max_sz, lit) do { \
    _Static_assert(sizeof(lit) <= (max_sz), "string literal exceeds target buffer"); \
    __builtin_memcpy((dst), (lit), sizeof(lit)); \
} while (0)
#define SET_SYS(dst, lit) SET_LIT_BOUNDED((dst), 20, lit)
#define SET_ERR(dst, lit) SET_LIT_BOUNDED((dst), 16, lit)

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

struct errno_stat_key_t {
    char errno_name[16];
};

struct errno_stat_t {
    u64 error_count;
};

_Static_assert(sizeof(struct errno_stat_key_t) == 16, "errno_stat_key_t must be 16 bytes");
_Static_assert(sizeof(struct errno_stat_t) == 8, "errno_stat_t must be 8 bytes");

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
    u32 syscall_id;
    u16 err_code;
    u16 pad;
    struct syscall_stat_key_t sys_key;
    struct errno_stat_key_t err_key;
    u32 pad2;
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
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct errno_stat_key_t);
    __type(value, struct errno_stat_t);
} errno_stats SEC(".maps");

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
    case 34:  // pause
    case 35:  // nanosleep
    case 43:  // accept
    case 61:  // wait4
    case 65:  // semop
    case 70:  // msgrcv
    case 128: // rt_sigtimedwait
    case 130: // rt_sigsuspend
    case 202: // futex
    case 208: // io_getevents
    case 219: // restart_syscall
    case 220: // semtimedop
    case 230: // clock_nanosleep
    case 232: // epoll_wait
    case 243: // mq_timedreceive
    case 247: // waitid
    case 270: // pselect6
    case 271: // ppoll
    case 281: // epoll_pwait
    case 288: // accept4
    case 333: // io_pgetevents
    case 426: // io_uring_enter
    case 441: // epoll_pwait2
    case 449: // futex_waitv
    case 455: // futex_wait
        return 1;
    default:
        return 0;
    }
}

static __always_inline void resolve_syscall_name(u32 id, char *dst) {
    switch (id) {
    case 0:   SET_SYS(dst, "read"); return;
    case 1:   SET_SYS(dst, "write"); return;
    case 2:   SET_SYS(dst, "open"); return;
    case 3:   SET_SYS(dst, "close"); return;
    case 4:   SET_SYS(dst, "stat"); return;
    case 5:   SET_SYS(dst, "fstat"); return;
    case 6:   SET_SYS(dst, "lstat"); return;
    case 7:   SET_SYS(dst, "poll"); return;
    case 8:   SET_SYS(dst, "lseek"); return;
    case 9:   SET_SYS(dst, "mmap"); return;
    case 10:  SET_SYS(dst, "mprotect"); return;
    case 11:  SET_SYS(dst, "munmap"); return;
    case 12:  SET_SYS(dst, "brk"); return;
    case 13:  SET_SYS(dst, "rt_sigaction"); return;
    case 14:  SET_SYS(dst, "rt_sigprocmask"); return;
    case 15:  SET_SYS(dst, "rt_sigreturn"); return;
    case 16:  SET_SYS(dst, "ioctl"); return;
    case 17:  SET_SYS(dst, "pread64"); return;
    case 18:  SET_SYS(dst, "pwrite64"); return;
    case 19:  SET_SYS(dst, "readv"); return;
    case 20:  SET_SYS(dst, "writev"); return;
    case 21:  SET_SYS(dst, "access"); return;
    case 22:  SET_SYS(dst, "pipe"); return;
    case 23:  SET_SYS(dst, "select"); return;
    case 24:  SET_SYS(dst, "sched_yield"); return;
    case 25:  SET_SYS(dst, "mremap"); return;
    case 26:  SET_SYS(dst, "msync"); return;
    case 27:  SET_SYS(dst, "mincore"); return;
    case 28:  SET_SYS(dst, "madvise"); return;
    case 32:  SET_SYS(dst, "dup"); return;
    case 33:  SET_SYS(dst, "dup2"); return;
    case 34:  SET_SYS(dst, "pause"); return;
    case 35:  SET_SYS(dst, "nanosleep"); return;
    case 36:  SET_SYS(dst, "getitimer"); return;
    case 37:  SET_SYS(dst, "alarm"); return;
    case 38:  SET_SYS(dst, "setitimer"); return;
    case 39:  SET_SYS(dst, "getpid"); return;
    case 40:  SET_SYS(dst, "sendfile"); return;
    case 41:  SET_SYS(dst, "socket"); return;
    case 42:  SET_SYS(dst, "connect"); return;
    case 43:  SET_SYS(dst, "accept"); return;
    case 44:  SET_SYS(dst, "sendto"); return;
    case 45:  SET_SYS(dst, "recvfrom"); return;
    case 46:  SET_SYS(dst, "sendmsg"); return;
    case 47:  SET_SYS(dst, "recvmsg"); return;
    case 48:  SET_SYS(dst, "shutdown"); return;
    case 49:  SET_SYS(dst, "bind"); return;
    case 50:  SET_SYS(dst, "listen"); return;
    case 51:  SET_SYS(dst, "getsockname"); return;
    case 52:  SET_SYS(dst, "getpeername"); return;
    case 53:  SET_SYS(dst, "socketpair"); return;
    case 54:  SET_SYS(dst, "setsockopt"); return;
    case 55:  SET_SYS(dst, "getsockopt"); return;
    case 56:  SET_SYS(dst, "clone"); return;
    case 57:  SET_SYS(dst, "fork"); return;
    case 58:  SET_SYS(dst, "vfork"); return;
    case 59:  SET_SYS(dst, "execve"); return;
    case 60:  SET_SYS(dst, "exit"); return;
    case 61:  SET_SYS(dst, "wait4"); return;
    case 62:  SET_SYS(dst, "kill"); return;
    case 63:  SET_SYS(dst, "uname"); return;
    case 65:  SET_SYS(dst, "semop"); return;
    case 70:  SET_SYS(dst, "msgrcv"); return;
    case 72:  SET_SYS(dst, "fcntl"); return;
    case 73:  SET_SYS(dst, "flock"); return;
    case 74:  SET_SYS(dst, "fsync"); return;
    case 75:  SET_SYS(dst, "fdatasync"); return;
    case 76:  SET_SYS(dst, "truncate"); return;
    case 77:  SET_SYS(dst, "ftruncate"); return;
    case 78:  SET_SYS(dst, "getdents"); return;
    case 79:  SET_SYS(dst, "getcwd"); return;
    case 80:  SET_SYS(dst, "chdir"); return;
    case 81:  SET_SYS(dst, "fchdir"); return;
    case 82:  SET_SYS(dst, "rename"); return;
    case 83:  SET_SYS(dst, "mkdir"); return;
    case 84:  SET_SYS(dst, "rmdir"); return;
    case 85:  SET_SYS(dst, "creat"); return;
    case 86:  SET_SYS(dst, "link"); return;
    case 87:  SET_SYS(dst, "unlink"); return;
    case 88:  SET_SYS(dst, "symlink"); return;
    case 89:  SET_SYS(dst, "readlink"); return;
    case 90:  SET_SYS(dst, "chmod"); return;
    case 91:  SET_SYS(dst, "fchmod"); return;
    case 92:  SET_SYS(dst, "chown"); return;
    case 93:  SET_SYS(dst, "fchown"); return;
    case 94:  SET_SYS(dst, "lchown"); return;
    case 95:  SET_SYS(dst, "umask"); return;
    case 96:  SET_SYS(dst, "gettimeofday"); return;
    case 97:  SET_SYS(dst, "getrlimit"); return;
    case 98:  SET_SYS(dst, "getrusage"); return;
    case 99:  SET_SYS(dst, "sysinfo"); return;
    case 102: SET_SYS(dst, "getuid"); return;
    case 104: SET_SYS(dst, "getgid"); return;
    case 105: SET_SYS(dst, "setuid"); return;
    case 106: SET_SYS(dst, "setgid"); return;
    case 107: SET_SYS(dst, "geteuid"); return;
    case 108: SET_SYS(dst, "getegid"); return;
    case 109: SET_SYS(dst, "setpgid"); return;
    case 110: SET_SYS(dst, "getppid"); return;
    case 111: SET_SYS(dst, "getpgrp"); return;
    case 112: SET_SYS(dst, "setsid"); return;
    case 115: SET_SYS(dst, "getgroups"); return;
    case 116: SET_SYS(dst, "setgroups"); return;
    case 117: SET_SYS(dst, "setresuid"); return;
    case 118: SET_SYS(dst, "getresuid"); return;
    case 119: SET_SYS(dst, "setresgid"); return;
    case 120: SET_SYS(dst, "getresgid"); return;
    case 121: SET_SYS(dst, "getpgid"); return;
    case 124: SET_SYS(dst, "getsid"); return;
    case 125: SET_SYS(dst, "capget"); return;
    case 126: SET_SYS(dst, "capset"); return;
    case 127: SET_SYS(dst, "rt_sigpending"); return;
    case 128: SET_SYS(dst, "rt_sigtimedwait"); return;
    case 130: SET_SYS(dst, "rt_sigsuspend"); return;
    case 131: SET_SYS(dst, "sigaltstack"); return;
    case 133: SET_SYS(dst, "mknod"); return;
    case 137: SET_SYS(dst, "statfs"); return;
    case 138: SET_SYS(dst, "fstatfs"); return;
    case 140: SET_SYS(dst, "getpriority"); return;
    case 141: SET_SYS(dst, "setpriority"); return;
    case 149: SET_SYS(dst, "mlock"); return;
    case 150: SET_SYS(dst, "munlock"); return;
    case 155: SET_SYS(dst, "pivot_root"); return;
    case 157: SET_SYS(dst, "prctl"); return;
    case 158: SET_SYS(dst, "arch_prctl"); return;
    case 160: SET_SYS(dst, "setrlimit"); return;
    case 162: SET_SYS(dst, "sync"); return;
    case 165: SET_SYS(dst, "mount"); return;
    case 166: SET_SYS(dst, "umount2"); return;
    case 186: SET_SYS(dst, "gettid"); return;
    case 187: SET_SYS(dst, "readahead"); return;
    case 188: SET_SYS(dst, "setxattr"); return;
    case 189: SET_SYS(dst, "lsetxattr"); return;
    case 190: SET_SYS(dst, "fsetxattr"); return;
    case 191: SET_SYS(dst, "getxattr"); return;
    case 192: SET_SYS(dst, "lgetxattr"); return;
    case 193: SET_SYS(dst, "fgetxattr"); return;
    case 194: SET_SYS(dst, "listxattr"); return;
    case 195: SET_SYS(dst, "llistxattr"); return;
    case 196: SET_SYS(dst, "flistxattr"); return;
    case 197: SET_SYS(dst, "removexattr"); return;
    case 198: SET_SYS(dst, "lremovexattr"); return;
    case 199: SET_SYS(dst, "fremovexattr"); return;
    case 200: SET_SYS(dst, "tkill"); return;
    case 201: SET_SYS(dst, "time"); return;
    case 202: SET_SYS(dst, "futex"); return;
    case 203: SET_SYS(dst, "sched_setaffinity"); return;
    case 204: SET_SYS(dst, "sched_getaffinity"); return;
    case 206: SET_SYS(dst, "io_setup"); return;
    case 207: SET_SYS(dst, "io_destroy"); return;
    case 208: SET_SYS(dst, "io_getevents"); return;
    case 209: SET_SYS(dst, "io_submit"); return;
    case 210: SET_SYS(dst, "io_cancel"); return;
    case 213: SET_SYS(dst, "epoll_create"); return;
    case 217: SET_SYS(dst, "getdents64"); return;
    case 218: SET_SYS(dst, "set_tid_address"); return;
    case 219: SET_SYS(dst, "restart_syscall"); return;
    case 220: SET_SYS(dst, "semtimedop"); return;
    case 221: SET_SYS(dst, "fadvise64"); return;
    case 222: SET_SYS(dst, "timer_create"); return;
    case 223: SET_SYS(dst, "timer_settime"); return;
    case 224: SET_SYS(dst, "timer_gettime"); return;
    case 225: SET_SYS(dst, "timer_getoverrun"); return;
    case 226: SET_SYS(dst, "timer_delete"); return;
    case 227: SET_SYS(dst, "clock_settime"); return;
    case 228: SET_SYS(dst, "clock_gettime"); return;
    case 229: SET_SYS(dst, "clock_getres"); return;
    case 230: SET_SYS(dst, "clock_nanosleep"); return;
    case 231: SET_SYS(dst, "exit_group"); return;
    case 232: SET_SYS(dst, "epoll_wait"); return;
    case 233: SET_SYS(dst, "epoll_ctl"); return;
    case 234: SET_SYS(dst, "tgkill"); return;
    case 242: SET_SYS(dst, "mq_timedsend"); return;
    case 243: SET_SYS(dst, "mq_timedreceive"); return;
    case 247: SET_SYS(dst, "waitid"); return;
    case 250: SET_SYS(dst, "keyctl"); return;
    case 253: SET_SYS(dst, "inotify_init"); return;
    case 254: SET_SYS(dst, "inotify_add_watch"); return;
    case 255: SET_SYS(dst, "inotify_rm_watch"); return;
    case 257: SET_SYS(dst, "openat"); return;
    case 258: SET_SYS(dst, "mkdirat"); return;
    case 259: SET_SYS(dst, "mknodat"); return;
    case 260: SET_SYS(dst, "fchownat"); return;
    case 262: SET_SYS(dst, "newfstatat"); return;
    case 263: SET_SYS(dst, "unlinkat"); return;
    case 264: SET_SYS(dst, "renameat"); return;
    case 265: SET_SYS(dst, "linkat"); return;
    case 266: SET_SYS(dst, "symlinkat"); return;
    case 267: SET_SYS(dst, "readlinkat"); return;
    case 268: SET_SYS(dst, "fchmodat"); return;
    case 269: SET_SYS(dst, "faccessat"); return;
    case 270: SET_SYS(dst, "pselect6"); return;
    case 271: SET_SYS(dst, "ppoll"); return;
    case 272: SET_SYS(dst, "unshare"); return;
    case 273: SET_SYS(dst, "set_robust_list"); return;
    case 274: SET_SYS(dst, "get_robust_list"); return;
    case 275: SET_SYS(dst, "splice"); return;
    case 276: SET_SYS(dst, "tee"); return;
    case 277: SET_SYS(dst, "sync_file_range"); return;
    case 280: SET_SYS(dst, "utimensat"); return;
    case 281: SET_SYS(dst, "epoll_pwait"); return;
    case 283: SET_SYS(dst, "timerfd_create"); return;
    case 284: SET_SYS(dst, "eventfd"); return;
    case 285: SET_SYS(dst, "fallocate"); return;
    case 286: SET_SYS(dst, "timerfd_settime"); return;
    case 287: SET_SYS(dst, "timerfd_gettime"); return;
    case 288: SET_SYS(dst, "accept4"); return;
    case 289: SET_SYS(dst, "signalfd4"); return;
    case 290: SET_SYS(dst, "eventfd2"); return;
    case 291: SET_SYS(dst, "epoll_create1"); return;
    case 292: SET_SYS(dst, "dup3"); return;
    case 293: SET_SYS(dst, "pipe2"); return;
    case 294: SET_SYS(dst, "inotify_init1"); return;
    case 295: SET_SYS(dst, "preadv"); return;
    case 296: SET_SYS(dst, "pwritev"); return;
    case 298: SET_SYS(dst, "perf_event_open"); return;
    case 299: SET_SYS(dst, "recvmmsg"); return;
    case 300: SET_SYS(dst, "fanotify_init"); return;
    case 301: SET_SYS(dst, "fanotify_mark"); return;
    case 302: SET_SYS(dst, "prlimit64"); return;
    case 306: SET_SYS(dst, "syncfs"); return;
    case 307: SET_SYS(dst, "sendmmsg"); return;
    case 308: SET_SYS(dst, "setns"); return;
    case 309: SET_SYS(dst, "getcpu"); return;
    case 316: SET_SYS(dst, "renameat2"); return;
    case 317: SET_SYS(dst, "seccomp"); return;
    case 318: SET_SYS(dst, "getrandom"); return;
    case 319: SET_SYS(dst, "memfd_create"); return;
    case 321: SET_SYS(dst, "bpf"); return;
    case 322: SET_SYS(dst, "execveat"); return;
    case 323: SET_SYS(dst, "userfaultfd"); return;
    case 324: SET_SYS(dst, "membarrier"); return;
    case 326: SET_SYS(dst, "copy_file_range"); return;
    case 327: SET_SYS(dst, "preadv2"); return;
    case 328: SET_SYS(dst, "pwritev2"); return;
    case 332: SET_SYS(dst, "statx"); return;
    case 333: SET_SYS(dst, "io_pgetevents"); return;
    case 334: SET_SYS(dst, "rseq"); return;
    case 424: SET_SYS(dst, "pidfd_send_signal"); return;
    case 425: SET_SYS(dst, "io_uring_setup"); return;
    case 426: SET_SYS(dst, "io_uring_enter"); return;
    case 427: SET_SYS(dst, "io_uring_register"); return;
    case 428: SET_SYS(dst, "open_tree"); return;
    case 429: SET_SYS(dst, "move_mount"); return;
    case 430: SET_SYS(dst, "fsopen"); return;
    case 431: SET_SYS(dst, "fsconfig"); return;
    case 432: SET_SYS(dst, "fsmount"); return;
    case 433: SET_SYS(dst, "fspick"); return;
    case 434: SET_SYS(dst, "pidfd_open"); return;
    case 435: SET_SYS(dst, "clone3"); return;
    case 436: SET_SYS(dst, "close_range"); return;
    case 437: SET_SYS(dst, "openat2"); return;
    case 438: SET_SYS(dst, "pidfd_getfd"); return;
    case 439: SET_SYS(dst, "faccessat2"); return;
    case 440: SET_SYS(dst, "process_madvise"); return;
    case 441: SET_SYS(dst, "epoll_pwait2"); return;
    case 442: SET_SYS(dst, "mount_setattr"); return;
    case 449: SET_SYS(dst, "futex_waitv"); return;
    case 451: SET_SYS(dst, "cachestat"); return;
    case 452: SET_SYS(dst, "fchmodat2"); return;
    case 454: SET_SYS(dst, "futex_wake"); return;
    case 455: SET_SYS(dst, "futex_wait"); return;
    case 456: SET_SYS(dst, "futex_requeue"); return;
    case 457: SET_SYS(dst, "statmount"); return;
    case 458: SET_SYS(dst, "listmount"); return;
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

static __always_inline void resolve_errno_name(u16 code, char *name_out) {
    switch (code) {
    case ERR_EPERM:        SET_ERR(name_out, "EPERM"); return;
    case ERR_ENOENT:       SET_ERR(name_out, "ENOENT"); return;
    case 3:                SET_ERR(name_out, "ESRCH"); return;
    case ERR_EINTR:        SET_ERR(name_out, "EINTR"); return;
    case ERR_EIO:          SET_ERR(name_out, "EIO"); return;
    case 6:                SET_ERR(name_out, "ENXIO"); return;
    case 7:                SET_ERR(name_out, "E2BIG"); return;
    case 8:                SET_ERR(name_out, "ENOEXEC"); return;
    case ERR_EBADF:        SET_ERR(name_out, "EBADF"); return;
    case 10:               SET_ERR(name_out, "ECHILD"); return;
    case ERR_EAGAIN:       SET_ERR(name_out, "EAGAIN"); return;
    case ERR_ENOMEM:       SET_ERR(name_out, "ENOMEM"); return;
    case ERR_EACCES:       SET_ERR(name_out, "EACCES"); return;
    case ERR_EFAULT:       SET_ERR(name_out, "EFAULT"); return;
    case 15:               SET_ERR(name_out, "ENOTBLK"); return;
    case ERR_EBUSY:        SET_ERR(name_out, "EBUSY"); return;
    case ERR_EEXIST:       SET_ERR(name_out, "EEXIST"); return;
    case 18:               SET_ERR(name_out, "EXDEV"); return;
    case 19:               SET_ERR(name_out, "ENODEV"); return;
    case ERR_ENOTDIR:      SET_ERR(name_out, "ENOTDIR"); return;
    case ERR_EISDIR:       SET_ERR(name_out, "EISDIR"); return;
    case ERR_EINVAL:       SET_ERR(name_out, "EINVAL"); return;
    case 23:               SET_ERR(name_out, "ENFILE"); return;
    case ERR_EMFILE:       SET_ERR(name_out, "EMFILE"); return;
    case 25:               SET_ERR(name_out, "ENOTTY"); return;
    case 26:               SET_ERR(name_out, "ETXTBSY"); return;
    case 27:               SET_ERR(name_out, "EFBIG"); return;
    case ERR_ENOSPC:       SET_ERR(name_out, "ENOSPC"); return;
    case 29:               SET_ERR(name_out, "ESPIPE"); return;
    case 30:               SET_ERR(name_out, "EROFS"); return;
    case 31:               SET_ERR(name_out, "EMLINK"); return;
    case ERR_EPIPE:        SET_ERR(name_out, "EPIPE"); return;
    case 33:               SET_ERR(name_out, "EDOM"); return;
    case 34:               SET_ERR(name_out, "ERANGE"); return;
    case 35:               SET_ERR(name_out, "EDEADLK"); return;
    case ERR_ENAMETOOLONG: SET_ERR(name_out, "ENAMETOOLONG"); return;
    case 37:               SET_ERR(name_out, "ENOLCK"); return;
    case ERR_ENOSYS:       SET_ERR(name_out, "ENOSYS"); return;
    case 39:               SET_ERR(name_out, "ENOTEMPTY"); return;
    case 40:               SET_ERR(name_out, "ELOOP"); return;
    case 42:               SET_ERR(name_out, "ENOMSG"); return;
    case 43:               SET_ERR(name_out, "EIDRM"); return;
    case 60:               SET_ERR(name_out, "ENOSTR"); return;
    case 61:               SET_ERR(name_out, "ENODATA"); return;
    case 62:               SET_ERR(name_out, "ETIME"); return;
    case 63:               SET_ERR(name_out, "ENOSR"); return;
    case 67:               SET_ERR(name_out, "ENOLINK"); return;
    case 71:               SET_ERR(name_out, "EPROTO"); return;
    case 74:               SET_ERR(name_out, "EBADMSG"); return;
    case 75:               SET_ERR(name_out, "EOVERFLOW"); return;
    case 77:               SET_ERR(name_out, "EBADFD"); return;
    case 84:               SET_ERR(name_out, "EILSEQ"); return;
    case 88:               SET_ERR(name_out, "ENOTSOCK"); return;
    case 89:               SET_ERR(name_out, "EDESTADDRREQ"); return;
    case 90:               SET_ERR(name_out, "EMSGSIZE"); return;
    case 91:               SET_ERR(name_out, "EPROTOTYPE"); return;
    case 92:               SET_ERR(name_out, "ENOPROTOOPT"); return;
    case 93:               SET_ERR(name_out, "EPROTONOSUPPORT"); return;
    case 94:               SET_ERR(name_out, "ESOCKTNOSUPPORT"); return;
    case 95:               SET_ERR(name_out, "EOPNOTSUPP"); return;
    case 96:               SET_ERR(name_out, "EPFNOSUPPORT"); return;
    case 97:               SET_ERR(name_out, "EAFNOSUPPORT"); return;
    case ERR_EADDRINUSE:   SET_ERR(name_out, "EADDRINUSE"); return;
    case ERR_EADDRNOTAVAIL:SET_ERR(name_out, "EADDRNOTAVAIL"); return;
    case 100:              SET_ERR(name_out, "ENETDOWN"); return;
    case 101:              SET_ERR(name_out, "ENETUNREACH"); return;
    case 102:              SET_ERR(name_out, "ENETRESET"); return;
    case 103:              SET_ERR(name_out, "ECONNABORTED"); return;
    case ERR_ECONNRESET:   SET_ERR(name_out, "ECONNRESET"); return;
    case 105:              SET_ERR(name_out, "ENOBUFS"); return;
    case 106:              SET_ERR(name_out, "EISCONN"); return;
    case 107:              SET_ERR(name_out, "ENOTCONN"); return;
    case 108:              SET_ERR(name_out, "ESHUTDOWN"); return;
    case 109:              SET_ERR(name_out, "ETOOMANYREFS"); return;
    case ERR_ETIMEDOUT:    SET_ERR(name_out, "ETIMEDOUT"); return;
    case ERR_ECONNREFUSED: SET_ERR(name_out, "ECONNREFUSED"); return;
    case 112:              SET_ERR(name_out, "EHOSTDOWN"); return;
    case ERR_EHOSTUNREACH: SET_ERR(name_out, "EHOSTUNREACH"); return;
    case 114:              SET_ERR(name_out, "EALREADY"); return;
    case ERR_EINPROGRESS:  SET_ERR(name_out, "EINPROGRESS"); return;
    case 116:              SET_ERR(name_out, "ESTALE"); return;
    case 121:              SET_ERR(name_out, "EREMOTEIO"); return;
    case 122:              SET_ERR(name_out, "EDQUOT"); return;
    case 123:              SET_ERR(name_out, "ENOMEDIUM"); return;
    case 124:              SET_ERR(name_out, "EMEDIUMTYPE"); return;
    case 125:              SET_ERR(name_out, "ECANCELED"); return;
    case 126:              SET_ERR(name_out, "ENOKEY"); return;
    case 127:              SET_ERR(name_out, "EKEYEXPIRED"); return;
    case 128:              SET_ERR(name_out, "EKEYREVOKED"); return;
    case 129:              SET_ERR(name_out, "EKEYREJECTED"); return;
    case 130:              SET_ERR(name_out, "EOWNERDEAD"); return;
    case 131:              SET_ERR(name_out, "ENOTRECOVERABLE"); return;
    case 132:              SET_ERR(name_out, "ERFKILL"); return;
    case 133:              SET_ERR(name_out, "EHWPOISON"); return;
    case 512:              SET_ERR(name_out, "ERESTARTSYS"); return;
    case 513:              SET_ERR(name_out, "ERESTARTNOINTR"); return;
    case 514:              SET_ERR(name_out, "ERESTARTNOHAND"); return;
    case 515:              SET_ERR(name_out, "ENOIOCTLCMD"); return;
    case 516:              SET_ERR(name_out, "ERESTARTBLOCK"); return;
    default:
        name_out[0] = 'E';
        name_out[1] = 'R';
        name_out[2] = 'R';
        name_out[3] = '_';
        if (code >= 1000 && code <= 4095) {
            name_out[4] = (char)('0' + (code / 1000));
            name_out[5] = (char)('0' + ((code / 100) % 10));
            name_out[6] = (char)('0' + ((code / 10) % 10));
            name_out[7] = (char)('0' + (code % 10));
            name_out[8] = '\0';
        } else if (code >= 100) {
            name_out[4] = (char)('0' + (code / 100));
            name_out[5] = (char)('0' + ((code / 10) % 10));
            name_out[6] = (char)('0' + (code % 10));
            name_out[7] = '\0';
        } else if (code >= 10) {
            name_out[4] = (char)('0' + (code / 10));
            name_out[5] = (char)('0' + (code % 10));
            name_out[6] = '\0';
        } else {
            name_out[4] = (char)('0' + code);
            name_out[5] = '\0';
        }
        return;
    }
}

static __always_inline int is_transient_err_for_idle(int idle_wait, u16 code) {
    if (code == ERR_EAGAIN || code == ERR_EINPROGRESS) {
        return 1;
    }
    // Kernel-internal syscall restart pseudo-errors visible at raw_tracepoint/sys_exit
    if (code == 512 || code == 513 || code == 514 || code == 516) {
        return 1;
    }
    // Normal timed condvar/poll/AIO expirations and signal interruptions on blocking wait syscalls
    if (idle_wait && (code == ERR_ETIMEDOUT || code == 62 /* ETIME */ || code == ERR_EINTR)) {
        return 1;
    }
    return 0;
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

static __always_inline void update_syscall_stats(const struct syscall_stat_key_t *key, u64 delta_ns, int is_error) {
    struct syscall_stat_t *st = bpf_map_lookup_elem(&syscall_stats, key);
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
        bpf_map_update_elem(&syscall_stats, key, &new_st, BPF_ANY);
    }
}

static __always_inline void update_errno_stats(const struct errno_stat_key_t *key) {
    struct errno_stat_t *st = bpf_map_lookup_elem(&errno_stats, key);
    if (st) {
        __sync_fetch_and_add(&st->error_count, 1);
    } else {
        struct errno_stat_t new_st = {
            .error_count = 1,
        };
        bpf_map_update_elem(&errno_stats, key, &new_st, BPF_ANY);
    }
}

static __always_inline void emit_syscall_event(
    u32 pid, u32 tid, const char *comm, u32 syscall_id, const struct syscall_stat_key_t *sys_key,
    u32 daddr, u16 dport, u16 err_code, const struct errno_stat_key_t *err_key,
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
    __builtin_memcpy(e->syscall, sys_key->syscall, sizeof(e->syscall));
    e->daddr = daddr;
    e->dport = dport;
    e->errno_code = err_code;
    __builtin_memcpy(e->errno_name, err_key->errno_name, sizeof(e->errno_name));
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

    u32 zero = 0;
    struct scratch_t *sc = bpf_map_lookup_elem(&scratch_map, &zero);
    if (!sc) {
        bpf_map_delete_elem(&spec_args_map, &tid);
        return 0;
    }

    u16 raw_err = (ret < 0 && ret >= -4095) ? (u16)(-ret) : 0;
    sc->err_code = raw_err;
    __builtin_memset(&sc->err_key, 0, sizeof(sc->err_key));
    if (raw_err == 0) {
        SET_ERR(sc->err_key.errno_name, "OK");
    } else {
        resolve_errno_name(raw_err, sc->err_key.errno_name);
    }

    u16 err_code = *(volatile u16 *)&sc->err_code;
    u64 thresh = slow_threshold_us > 0 ? slow_threshold_us : 10000ULL;
    int transient = is_transient_err_for_idle(is_idle_sleep_syscall(syscall_id), err_code);
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
            __builtin_memset(&sc->sys_key, 0, sizeof(sc->sys_key));
            resolve_syscall_name(syscall_id, sc->sys_key.syscall);
            emit_syscall_event(pid, tid, comm, syscall_id, &sc->sys_key, daddr, dport, err_code, &sc->err_key, duration_us, arg->target);
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

    u32 zero = 0;
    struct scratch_t *sc = bpf_map_lookup_elem(&scratch_map, &zero);
    if (!sc) {
        return 0;
    }

    long ret = (long)ctx->args[1];
    u16 raw_err = (ret < 0 && ret >= -4095) ? (u16)(-ret) : 0;
    sc->syscall_id = syscall_id;
    sc->err_code = raw_err;

    __builtin_memset(&sc->err_key, 0, sizeof(sc->err_key));
    if (raw_err == 0) {
        SET_ERR(sc->err_key.errno_name, "OK");
    } else {
        resolve_errno_name(raw_err, sc->err_key.errno_name);
    }

    u16 err_code = *(volatile u16 *)&sc->err_code;
    u32 sid = *(volatile u32 *)&sc->syscall_id;

    __builtin_memset(&sc->sys_key, 0, sizeof(sc->sys_key));
    resolve_syscall_name(sid, sc->sys_key.syscall);

    err_code = *(volatile u16 *)&sc->err_code;
    sid = *(volatile u32 *)&sc->syscall_id;

    int idle_wait = is_idle_sleep_syscall(sid);
    int transient = is_transient_err_for_idle(idle_wait, err_code);
    int is_real_error = (err_code != 0 && (!transient || include_transient));

    // 1. Always update 1Hz strace -c style leaderboard and failing-errno breakdown (including openat/openat2/connect)
    update_syscall_stats(&sc->sys_key, delta_ns, is_real_error);
    if (is_real_error) {
        update_errno_stats(&sc->err_key);
    }

    // 2. Specialized tracepoints emit detailed openat/openat2/connect records to syscall_events
    if (sid == SYS_NR_OPENAT || sid == SYS_NR_OPENAT2 || sid == SYS_NR_CONNECT) {
        return 0;
    }

    u64 thresh = slow_threshold_us > 0 ? slow_threshold_us : 10000ULL;
    int should_emit = 0;

    if (errors_only) {
        if (is_real_error) {
            should_emit = 1;
        }
    } else {
        if (is_real_error) {
            should_emit = 1;
        } else if (!idle_wait && duration_us >= thresh) {
            should_emit = 1;
        }
    }

    if (should_emit) {
        emit_syscall_event(pid, tid, comm, sid, &sc->sys_key, 0, 0, err_code, &sc->err_key, duration_us, NULL);
    }

    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
