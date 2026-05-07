// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Ferith Tools
//
// kernelradar — self-protection
//
// LSM hook on task_kill that returns -EPERM when somebody tries to
// signal kernelradar's own TGID. The protected TGID is held in a
// single-entry BPF array map, populated from userspace right after
// program load.
//
// Configurable escape hatch: signals from PID 1 (systemd) for clean
// shutdown are always allowed. An admin can also clear the protected
// TGID via the userspace control channel.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

/* The single-entry map holds the TGID we want to protect. */
struct {
    __uint(type,        BPF_MAP_TYPE_ARRAY);
    __type(key,         __u32);
    __type(value,       __u32);
    __uint(max_entries, 1);
} kr_protected_tgid SEC(".maps");

/* lsm/task_kill is the LSM hook called when one task signals another.
 * Signature on modern kernels:
 *   int task_kill(struct task_struct *p, struct kernel_siginfo *info,
 *                 int sig, const struct cred *cred);
 * Returning a non-zero value denies the operation. */
SEC("lsm/task_kill")
int BPF_PROG(kr_task_kill, struct task_struct *p,
             struct kernel_siginfo *info, int sig,
             const struct cred *cred)
{
    __u32 key = 0;
    __u32 *protected = bpf_map_lookup_elem(&kr_protected_tgid, &key);
    if (!protected || *protected == 0)
        return 0; /* protection disabled */

    __u32 target_tgid = BPF_CORE_READ(p, tgid);
    if (target_tgid != *protected)
        return 0; /* not our process */

    /* Allow systemd (PID 1) to terminate us cleanly. */
    __u64 sender = bpf_get_current_pid_tgid();
    __u32 sender_tgid = (__u32)(sender >> 32);
    if (sender_tgid == 1)
        return 0;

    /* Allow ourselves (Ctrl+C from interactive run, internal signals). */
    if (sender_tgid == *protected)
        return 0;

    /* Block everyone else. */
    return -1; /* -EPERM */
}
