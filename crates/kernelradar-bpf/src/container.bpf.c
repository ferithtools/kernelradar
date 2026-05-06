// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Ferith Tools
//
// kernelradar — Container Escape Detector
//
// Watches two syscalls that are classic signals of namespace-based
// container escape attempts:
//
//   sys_enter_unshare — create new namespaces (detach from container)
//   sys_enter_setns   — join a different namespace (pivot to host)
//
// Both are tracepoints: read-only, no blocking.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../include/events.h"
#include "../include/stats.h"

char LICENSE[] SEC("license") = "GPL";

/* Namespace-related clone flags (from uapi/linux/sched.h) */
#define CLONE_NEWNS      0x00020000
#define CLONE_NEWUSER    0x10000000
#define CLONE_NEWPID     0x20000000
#define CLONE_NEWNET     0x40000000
#define CLONE_NEWIPC     0x08000000
#define CLONE_NEWUTS     0x04000000
#define CLONE_NEWCGROUP  0x02000000

#define KR_CONTAINER_UNSHARE  1
#define KR_CONTAINER_SETNS    2

struct {
    __uint(type,        BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} kr_container_events SEC(".maps");

static __always_inline void emit(struct trace_event_raw_sys_enter *ctx,
                                  __u16 event_type, __u64 d0, __u64 d1)
{
    kr_stat_inc(KR_STAT_CONTAINER_OBSERVED);

    struct kr_event *e = bpf_ringbuf_reserve(&kr_container_events,
                                              sizeof(*e), 0);
    if (!e) {
        kr_stat_inc(KR_STAT_CONTAINER_DROPPED);
        return;
    }

    __u64 id = bpf_get_current_pid_tgid();
    __u64 ug = bpf_get_current_uid_gid();

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid          = (__u32)(id >> 32);
    e->tid          = (__u32)id;
    e->uid          = (__u32)ug;
    e->gid          = (__u32)(ug >> 32);
    e->detector_id  = KR_DETECTOR_CONTAINER;
    e->severity     = KR_SEV_WARNING;
    e->event_type   = event_type;
    e->data[0]      = d0;
    e->data[1]      = d1;
    e->data[2]      = 0;
    e->data[3]      = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
}

/* Catch unshare() — creating new namespaces */
SEC("tracepoint/syscalls/sys_enter_unshare")
int kr_tp_unshare(struct trace_event_raw_sys_enter *ctx)
{
    unsigned long flags = (unsigned long)ctx->args[0];

    /* Only care about namespace-related flags */
    unsigned long ns_flags = CLONE_NEWNS | CLONE_NEWUSER | CLONE_NEWPID |
                             CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWUTS |
                             CLONE_NEWCGROUP;
    if (!(flags & ns_flags))
        return 0;

    emit(ctx, KR_CONTAINER_UNSHARE, flags, 0);
    return 0;
}

/* Catch setns() — joining a different namespace */
SEC("tracepoint/syscalls/sys_enter_setns")
int kr_tp_setns(struct trace_event_raw_sys_enter *ctx)
{
    int fd      = (int)ctx->args[0];
    int nstype  = (int)ctx->args[1];
    emit(ctx, KR_CONTAINER_SETNS, (__u64)fd, (__u64)nstype);
    return 0;
}
