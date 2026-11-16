// SPDX-License-Identifier: GPL-2.0-only OR MIT
#ifndef __EPROBE_TRACEPOINT_H
#define __EPROBE_TRACEPOINT_H

// Shared tracepoint context structure for sys_enter tracepoints.
// Used by modules hooking syscalls via tracepoint/syscalls/sys_enter_*.
// This replaces duplicate inline definitions across modules (Finding #18).
struct trace_event_raw_sys_enter {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int id;
    unsigned long args[6];
};

struct trace_event_raw_sys_exit {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int id;
    long ret;
};

#endif /* __EPROBE_TRACEPOINT_H */
