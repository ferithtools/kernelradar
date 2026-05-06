// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Ferith Tools
//
// kernelradar — Kernel Module Rootkit Detector
//
// Watches two syscalls used to load kernel modules:
//
//   sys_enter_finit_module — load module from file descriptor (modprobe)
//   sys_enter_init_module  — load module from memory buffer (rare, suspicious)
//
// Any module load from an unexpected process is worth auditing.
// Tracepoints: read-only, no blocking.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../include/events.h"

char LICENSE[] SEC("license") = "GPL";

#define KR_KMOD_FINIT  1   /* finit_module: load from fd */
#define KR_KMOD_INIT   2   /* init_module:  load from memory — very suspicious */

struct {
    __uint(type,        BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} kr_kmod_events SEC(".maps");

static __always_inline void emit_kmod(struct trace_event_raw_sys_enter *ctx,
                                       __u16 event_type, __u64 d0)
{
    struct kr_event *e = bpf_ringbuf_reserve(&kr_kmod_events,
                                              sizeof(*e), 0);
    if (!e) return;

    __u64 id = bpf_get_current_pid_tgid();
    __u64 ug = bpf_get_current_uid_gid();

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid          = (__u32)(id >> 32);
    e->tid          = (__u32)id;
    e->uid          = (__u32)ug;
    e->gid          = (__u32)(ug >> 32);
    e->detector_id  = KR_DETECTOR_KMOD;

    /* init_module from memory = ALERT (rootkit technique) */
    e->severity     = (event_type == KR_KMOD_INIT)
                      ? KR_SEV_ALERT : KR_SEV_WARNING;
    e->event_type   = event_type;
    e->data[0]      = d0;
    e->data[1]      = 0;
    e->data[2]      = 0;
    e->data[3]      = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
}

/* finit_module(fd, params, flags) — normal module load */
SEC("tracepoint/syscalls/sys_enter_finit_module")
int kr_tp_finit_module(struct trace_event_raw_sys_enter *ctx)
{
    int fd = (int)ctx->args[0];
    emit_kmod(ctx, KR_KMOD_FINIT, (__u64)fd);
    return 0;
}

/* init_module(buf, len, params) — load from memory, classic rootkit path */
SEC("tracepoint/syscalls/sys_enter_init_module")
int kr_tp_init_module(struct trace_event_raw_sys_enter *ctx)
{
    emit_kmod(ctx, KR_KMOD_INIT, 0);
    return 0;
}
