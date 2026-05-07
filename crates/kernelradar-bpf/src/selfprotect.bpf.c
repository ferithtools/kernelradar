// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Ferith Tools
//
// kernelradar - self-protection
//
// LSM hook on task_kill that returns -EPERM when somebody tries to
// signal kernelradar's own TGID. The protected TGID is held in a
// single-entry BPF array map, populated from userspace right after
// program load.
//
// Configurable escape hatch: signals from PID 1 (systemd) for clean
// shutdown are always allowed. An admin can also clear the protected
// TGID via the userspace control channel.
//
// On every denial we emit a kr_event into our own ring buffer AND
// bump KR_STAT_SELFPROTECT_DENIED. Userspace reader (see lsm.rs)
// turns that into a CRITICAL alert through journald / Prometheus.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../include/events.h"
#include "../include/stats.h"

char LICENSE[] SEC("license") = "GPL";

/* The single-entry map holds the TGID we want to protect. */
struct {
    __uint(type,        BPF_MAP_TYPE_ARRAY);
    __type(key,         __u32);
    __type(value,       __u32);
    __uint(max_entries, 1);
} kr_protected_tgid SEC(".maps");

/* Ring buffer for denial events. Userspace reads it and emits a
 * CRITICAL alert per entry. 64 KB is plenty - denials are rare. */
struct {
    __uint(type,        BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);
} kr_selfprotect_events SEC(".maps");

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
    __u64 sender_id = bpf_get_current_pid_tgid();
    __u32 sender_tgid = (__u32)(sender_id >> 32);
    if (sender_tgid == 1)
        return 0;

    /* Allow ourselves (Ctrl+C from interactive run, internal signals). */
    if (sender_tgid == *protected)
        return 0;

    /* Block everyone else - and emit a noisy event so userspace knows
     * an attempt happened. The kernel-side stat counter is bumped
     * unconditionally; the ring-buffer push is best-effort (drops
     * are reflected in KR_STAT_SELFPROTECT_DROPPED). */
    kr_stat_inc(KR_STAT_SELFPROTECT_DENIED);

    struct kr_event *e = bpf_ringbuf_reserve(&kr_selfprotect_events,
                                              sizeof(*e), 0);
    if (!e) {
        kr_stat_inc(KR_STAT_SELFPROTECT_DROPPED);
        return -1; /* still deny even if we couldn't log */
    }

    __u64 ug = bpf_get_current_uid_gid();
    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid          = sender_tgid;
    e->tid          = (__u32)sender_id;
    e->uid          = (__u32)ug;
    e->gid          = (__u32)(ug >> 32);
    e->detector_id  = KR_DETECTOR_SELFPROTECT;
    e->severity     = KR_SEV_CRITICAL;
    e->event_type   = KR_SP_KILL_DENIED;
    /* data[0] = signal number, data[1] = target_tgid (always == protected) */
    e->data[0]      = (__u64)sig;
    e->data[1]      = (__u64)target_tgid;
    e->data[2]      = 0;
    e->data[3]      = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);

    return -1; /* -EPERM */
}
