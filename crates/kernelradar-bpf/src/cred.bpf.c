// SPDX-License-Identifier: GPL-2.0
//
// kernelradar — Credential theft detector (T-0.8)
//
// Watches sys_enter_openat for READ access to a narrow set of
// credential files: /etc/shadow, /etc/gshadow, /root/.ssh/...,
// /home/*/.ssh/id_* (private keys).
//
// Read-mode filter is the inverse of FIM. Both detectors can attach
// to the same tracepoint without conflict — BPF allows multiple
// subscribers per tracepoint.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../include/events.h"

char LICENSE[] SEC("license") = "GPL";

#define O_WRONLY  0x0001
#define O_RDWR    0x0002
#define O_CREAT   0x0040
#define O_TRUNC   0x0200
#define O_APPEND  0x0400

#define WRITE_MASK (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND)

struct {
    __uint(type,        BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} kr_cred_events SEC(".maps");

/* Cheap prefix filter — only fire for paths starting with /etc/sh,
 * /etc/gs, /etc/su, /root, /home/. Userspace does fine matching. */
static __always_inline int is_cred_candidate(const char *p)
{
    if (p[0] != '/') return 0;

    /* /etc/shadow, /etc/gshadow, /etc/sudoers — start with /etc/s or /etc/g */
    if (p[1] == 'e' && p[2] == 't' && p[3] == 'c' && p[4] == '/' &&
        (p[5] == 's' || p[5] == 'g'))
        return 1;
    /* /root */
    if (p[1] == 'r' && p[2] == 'o' && p[3] == 'o' && p[4] == 't')
        return 1;
    /* /home/ */
    if (p[1] == 'h' && p[2] == 'o' && p[3] == 'm' && p[4] == 'e'
        && p[5] == '/')
        return 1;
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int kr_tp_openat_read(struct trace_event_raw_sys_enter *ctx)
{
    int flags = (int)ctx->args[2];

    /* Read mode: NO write/append/create/trunc flags set.
     * O_RDONLY is value 0, so all bits cleared in WRITE_MASK = read. */
    if (flags & WRITE_MASK)
        return 0;

    char path[32] = {};
    long len = bpf_probe_read_user_str(path, sizeof(path),
                                        (void *)ctx->args[1]);
    if (len <= 0)
        return 0;

    if (!is_cred_candidate(path))
        return 0;

    struct kr_event *e = bpf_ringbuf_reserve(&kr_cred_events,
                                              sizeof(*e), 0);
    if (!e) return 0;

    __u64 id = bpf_get_current_pid_tgid();
    __u64 ug = bpf_get_current_uid_gid();

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid          = (__u32)(id >> 32);
    e->tid          = (__u32)id;
    e->uid          = (__u32)ug;
    e->gid          = (__u32)(ug >> 32);
    e->detector_id  = KR_DETECTOR_CRED;
    e->severity     = KR_SEV_WARNING;
    e->event_type   = KR_CRED_READ;

    __builtin_memcpy(&e->data[0], path, 32);

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}
