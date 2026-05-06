// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Ferith Tools
//
// kernelradar — Process injection detector (T-0.7)
//
// Hooks:
//   sys_enter_ptrace            — only emit for ATTACH/SEIZE/POKE*
//                                 (read-side requests are noisy and
//                                 mostly debugger activity)
//   sys_enter_process_vm_writev — modern cross-process memory write
//
// Both are read-only tracepoints, no enforcement, no blocking.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../include/events.h"

char LICENSE[] SEC("license") = "GPL";

/* ptrace requests (uapi/linux/ptrace.h) */
#define PTRACE_TRACEME      0
#define PTRACE_PEEKTEXT     1
#define PTRACE_PEEKDATA     2
#define PTRACE_PEEKUSER     3
#define PTRACE_POKETEXT     4
#define PTRACE_POKEDATA     5
#define PTRACE_POKEUSER     6
#define PTRACE_CONT         7
#define PTRACE_KILL         8
#define PTRACE_ATTACH      16
#define PTRACE_DETACH      17
#define PTRACE_SEIZE   0x4206

struct {
    __uint(type,        BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} kr_inj_events SEC(".maps");

static __always_inline void emit_inj(struct trace_event_raw_sys_enter *ctx,
                                      __u16 event_type, __u8 severity,
                                      __u64 d0, __u64 d1)
{
    struct kr_event *e = bpf_ringbuf_reserve(&kr_inj_events,
                                              sizeof(*e), 0);
    if (!e) return;

    __u64 id = bpf_get_current_pid_tgid();
    __u64 ug = bpf_get_current_uid_gid();

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid          = (__u32)(id >> 32);
    e->tid          = (__u32)id;
    e->uid          = (__u32)ug;
    e->gid          = (__u32)(ug >> 32);
    e->detector_id  = KR_DETECTOR_INJECTION;
    e->severity     = severity;
    e->event_type   = event_type;
    e->data[0]      = d0;
    e->data[1]      = d1;
    e->data[2]      = 0;
    e->data[3]      = 0;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int kr_tp_ptrace(struct trace_event_raw_sys_enter *ctx)
{
    long request = (long)ctx->args[0];
    long target  = (long)ctx->args[1];

    /* Attach-class: process gains control over another process */
    if (request == PTRACE_ATTACH || request == PTRACE_SEIZE) {
        emit_inj(ctx, KR_INJ_PTRACE_ATTACH, KR_SEV_ALERT,
                 (__u64)request, (__u64)target);
        return 0;
    }

    /* Poke-class: process writes into another process's memory */
    if (request == PTRACE_POKETEXT ||
        request == PTRACE_POKEDATA ||
        request == PTRACE_POKEUSER) {
        emit_inj(ctx, KR_INJ_PTRACE_POKE, KR_SEV_CRITICAL,
                 (__u64)request, (__u64)target);
        return 0;
    }

    /* PEEK*, CONT, DETACH, KILL, TRACEME — not in scope for first cut */
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_process_vm_writev")
int kr_tp_pvm_writev(struct trace_event_raw_sys_enter *ctx)
{
    long target = (long)ctx->args[0];
    emit_inj(ctx, KR_INJ_VM_WRITEV, KR_SEV_CRITICAL,
             (__u64)target, 0);
    return 0;
}
