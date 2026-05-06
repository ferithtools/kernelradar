// SPDX-License-Identifier: GPL-2.0
//
// kernelradar — Privilege Escalation Tracker
//
// Hooks:
//   sys_enter_setuid   — uid transition
//   sys_enter_setgid   — gid transition
//
// On each call: emit kr_event into the ring buffer so userspace
// can apply rules (e.g. uid → 0 from unprivileged process = alert).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../include/events.h"
#include "../include/stats.h"

char LICENSE[] SEC("license") = "GPL";

/* Ring buffer for events → userspace */
struct {
    __uint(type,        BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);    /* 256 KB */
} kr_events SEC(".maps");

/* ── Helper ────────────────────────────────────────────────────────── */

static __always_inline void fill_common(struct kr_event *e,
                                         __u8 detector, __u8 severity,
                                         __u16 event_type)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u64 ug = bpf_get_current_uid_gid();

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid          = (__u32)(id >> 32);
    e->tid          = (__u32)id;
    e->uid          = (__u32)ug;
    e->gid          = (__u32)(ug >> 32);
    e->detector_id  = detector;
    e->severity     = severity;
    e->event_type   = event_type;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

/* ── setuid hook ───────────────────────────────────────────────────── */

SEC("tracepoint/syscalls/sys_enter_setuid")
int kr_tp_setuid(struct trace_event_raw_sys_enter *ctx)
{
    __u32 new_uid = (__u32)ctx->args[0];

    /* Only care about gaining root */
    if (new_uid != 0)
        return 0;

    /* Current uid already root? not interesting */
    __u32 cur_uid = (__u32)bpf_get_current_uid_gid();
    if (cur_uid == 0)
        return 0;

    kr_stat_inc(KR_STAT_PRIVESC_OBSERVED);

    struct kr_event *e = bpf_ringbuf_reserve(&kr_events,
                                              sizeof(*e), 0);
    if (!e) {
        kr_stat_inc(KR_STAT_PRIVESC_DROPPED);
        return 0;
    }

    fill_common(e, KR_DETECTOR_PRIVESC,
                KR_SEV_ALERT, KR_PRIVESC_SETUID);
    e->data[0] = cur_uid;
    e->data[1] = new_uid;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── setgid hook ───────────────────────────────────────────────────── */

SEC("tracepoint/syscalls/sys_enter_setgid")
int kr_tp_setgid(struct trace_event_raw_sys_enter *ctx)
{
    __u32 new_gid = (__u32)ctx->args[0];

    if (new_gid != 0)
        return 0;

    __u32 cur_gid = (__u32)(bpf_get_current_uid_gid() >> 32);
    if (cur_gid == 0)
        return 0;

    kr_stat_inc(KR_STAT_PRIVESC_OBSERVED);

    struct kr_event *e = bpf_ringbuf_reserve(&kr_events,
                                              sizeof(*e), 0);
    if (!e) {
        kr_stat_inc(KR_STAT_PRIVESC_DROPPED);
        return 0;
    }

    fill_common(e, KR_DETECTOR_PRIVESC,
                KR_SEV_ALERT, KR_PRIVESC_SETGID);
    e->data[0] = cur_gid;
    e->data[1] = new_gid;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
