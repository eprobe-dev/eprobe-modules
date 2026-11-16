// SPDX-License-Identifier: GPL-2.0-only OR MIT
#ifndef __EPROBE_CGROUP_H
#define __EPROBE_CGROUP_H

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// Self-contained CO-RE flavor definitions for cgroup v1/v2 container ID extraction.
// Using the `___eprobe_cg` flavor avoids struct redefinition collisions with module-local types.
struct kernfs_node___eprobe_cg {
    const char *name;
} __attribute__((preserve_access_index));

struct cgroup___eprobe_cg {
    struct kernfs_node___eprobe_cg *kn;
} __attribute__((preserve_access_index));

struct cgroup_subsys_state___eprobe_cg {
    struct cgroup___eprobe_cg *cgroup;
} __attribute__((preserve_access_index));

struct css_set___eprobe_cg {
    struct cgroup___eprobe_cg *dfl_cgrp;
    struct cgroup_subsys_state___eprobe_cg *subsys[13];
} __attribute__((preserve_access_index));

struct task_struct___eprobe_cg {
    struct css_set___eprobe_cg *cgroups;
} __attribute__((preserve_access_index));

static __always_inline int eprobe_is_hex_char(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

// Extract 12-char hex container ID non-invasively from a task_struct pointer's cgroup name.
// Returns 1 if a container ID was found (dst[0..11] populated + NUL), or 0 for host tasks.
static __always_inline int parse_container_id_from_task(const void *task_ptr, char *dst) {
    if (!task_ptr) return 0;

    const struct task_struct___eprobe_cg *task = (const struct task_struct___eprobe_cg *)task_ptr;
    const char *kn_name = BPF_CORE_READ(task, cgroups, subsys[0], cgroup, kn, name);
    if (!kn_name) {
        kn_name = BPF_CORE_READ(task, cgroups, dfl_cgrp, kn, name);
    }
    if (!kn_name) {
        return 0;
    }

    char buf[64] = {0};
    bpf_probe_read_kernel_str(buf, sizeof(buf), kn_name);

    int start_idx = -1;

    // Docker: "docker-<id>.scope" or "docker/<id>"
    if (buf[0] == 'd' && buf[1] == 'o' && buf[2] == 'c' && buf[3] == 'k' && buf[4] == 'e' && buf[5] == 'r' &&
        (buf[6] == '-' || buf[6] == '/')) {
        start_idx = 7;
    }
    // CRI-Containerd: "cri-containerd-<id>.scope"
    else if (buf[0] == 'c' && buf[1] == 'r' && buf[2] == 'i' && buf[3] == '-' && buf[4] == 'c' && buf[5] == 'o' && buf[6] == 'n' &&
             buf[7] == 't' && buf[8] == 'a' && buf[9] == 'i' && buf[10] == 'n' && buf[11] == 'e' && buf[12] == 'r' && buf[13] == 'd' && buf[14] == '-') {
        start_idx = 15;
    }
    // Podman / Libpod: "libpod-<id>.scope"
    else if (buf[0] == 'l' && buf[1] == 'i' && buf[2] == 'b' && buf[3] == 'p' && buf[4] == 'o' && buf[5] == 'd' && buf[6] == '-') {
        start_idx = 7;
    }
    // Raw 12+ character hexadecimal container ID (cgroupfs / containerd direct)
    else if (eprobe_is_hex_char(buf[0]) && eprobe_is_hex_char(buf[1]) && eprobe_is_hex_char(buf[2]) && eprobe_is_hex_char(buf[3]) &&
             eprobe_is_hex_char(buf[4]) && eprobe_is_hex_char(buf[5]) && eprobe_is_hex_char(buf[6]) && eprobe_is_hex_char(buf[7]) &&
             eprobe_is_hex_char(buf[8]) && eprobe_is_hex_char(buf[9]) && eprobe_is_hex_char(buf[10]) && eprobe_is_hex_char(buf[11])) {
        start_idx = 0;
    }

    if (start_idx < 0) {
        return 0;
    }

    int done = 0;
    #pragma clang loop unroll(full)
    for (int i = 0; i < 12; i++) {
        char c = buf[(start_idx + i) & 0x3F];
        if (c == '\0' || c == '.') {
            done = 1;
        }
        dst[i] = done ? '\0' : c;
    }
    dst[12] = '\0';
    return 1;
}

// Convenience wrapper extracting container ID for the current task.
static __always_inline int parse_container_id(char *dst) {
    return parse_container_id_from_task((const void *)bpf_get_current_task(), dst);
}

#endif /* __EPROBE_CGROUP_H */
