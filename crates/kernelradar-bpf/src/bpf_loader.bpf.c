// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Ferith Tools
//
// kernelradar — BPF Program Loader Auditor
//
// Hook: sys_enter_bpf
//   args[0] = cmd
//   args[1] = uattr (userspace pointer to bpf_attr)
//   args[2] = size
//
// Emits an event whenever BPF_PROG_LOAD (cmd=5) is called.
// Userspace decides whether the process is in the allowlist.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../include/events.h"
#include "../include/stats.h"

char LICENSE[] SEC("license") = "GPL";

#define BPF_PROG_LOAD  5

struct {
    __uint(type,        BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} kr_bpfl_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_bpf")
int kr_tp_bpf_load(struct trace_event_raw_sys_enter *ctx)
{
    /* Only care about BPF_PROG_LOAD */
    int cmd = (int)ctx->args[0];
    if (cmd != BPF_PROG_LOAD)
        return 0;

    kr_stat_inc(KR_STAT_BPFL_OBSERVED);

    struct kr_event *e = bpf_ringbuf_reserve(&kr_bpfl_events,
                                              sizeof(*e), 0);
    if (!e) {
        kr_stat_inc(KR_STAT_BPFL_DROPPED);
        return 0;
    }

    __u64 id = bpf_get_current_pid_tgid();
    __u64 ug = bpf_get_current_uid_gid();

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid          = (__u32)(id >> 32);
    e->tid          = (__u32)id;
    e->uid          = (__u32)ug;
    e->gid          = (__u32)(ug >> 32);
    e->detector_id  = KR_DETECTOR_BPF_LOADER;
    e->severity     = KR_SEV_WARNING;
    e->event_type   = KR_BPF_PROG_LOAD;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* data[0]: prog_type — read from userspace bpf_attr.prog_type
     * bpf_attr layout: prog_type is the first field (__u32 at offset 0) */
    __u32 prog_type = 0;
    void *uattr = (void *)ctx->args[1];
    bpf_probe_read_user(&prog_type, sizeof(prog_type), uattr);
    e->data[0] = prog_type;
    e->data[1] = 0;
    e->data[2] = 0;
    e->data[3] = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
