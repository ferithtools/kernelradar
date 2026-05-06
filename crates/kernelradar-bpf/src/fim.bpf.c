// SPDX-License-Identifier: GPL-2.0
//
// kernelradar — File Integrity Monitor (T-0.5)
//
// Hooks sys_enter_openat. Filters in BPF: only emit events for
// openat() with write/append/create flags AND path under sensitive
// directories (/etc, /root, /home).
//
// The path (up to 32 bytes, NUL-terminated) is packed into the
// kr_event.data field. Userspace does fine-grained matching.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../include/events.h"

char LICENSE[] SEC("license") = "GPL";

/* open(2) flags from <fcntl.h>. We only watch write modes. */
#define O_WRONLY  0x0001
#define O_RDWR    0x0002
#define O_CREAT   0x0040
#define O_TRUNC   0x0200
#define O_APPEND  0x0400

#define WRITE_MASK (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND)

struct {
    __uint(type,        BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} kr_fim_events SEC(".maps");

/* Cheap prefix filter — we only care about /etc/, /root, /home/ */
static __always_inline int is_sensitive_prefix(const char *p)
{
    if (p[0] != '/') return 0;

    /* /etc/ — five chars */
    if (p[1] == 'e' && p[2] == 't' && p[3] == 'c' && p[4] == '/')
        return 1;
    /* /root — five chars (matches /root, /root/, /root/.ssh/...) */
    if (p[1] == 'r' && p[2] == 'o' && p[3] == 'o' && p[4] == 't')
        return 1;
    /* /home/ — six chars */
    if (p[1] == 'h' && p[2] == 'o' && p[3] == 'm'
        && p[4] == 'e' && p[5] == '/')
        return 1;

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int kr_tp_openat(struct trace_event_raw_sys_enter *ctx)
{
    int flags = (int)ctx->args[2];

    /* Only write modes interest us */
    if (!(flags & WRITE_MASK))
        return 0;

    /* Read up to 32 bytes of the path on stack first
     * so we can do the prefix check before allocating ringbuf.
     */
    char path[32] = {};
    long len = bpf_probe_read_user_str(path, sizeof(path),
                                        (void *)ctx->args[1]);
    if (len <= 0)
        return 0;

    if (!is_sensitive_prefix(path))
        return 0;

    /* Sensitive — emit full event */
    struct kr_event *e = bpf_ringbuf_reserve(&kr_fim_events,
                                              sizeof(*e), 0);
    if (!e)
        return 0;

    __u64 id = bpf_get_current_pid_tgid();
    __u64 ug = bpf_get_current_uid_gid();

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid          = (__u32)(id >> 32);
    e->tid          = (__u32)id;
    e->uid          = (__u32)ug;
    e->gid          = (__u32)(ug >> 32);
    e->detector_id  = KR_DETECTOR_FIM;
    e->severity     = KR_SEV_WARNING;
    e->event_type   = KR_FIM_OPEN_WRITE;

    /* Pack path bytes into the 32-byte data[] field.
     * data is __u64[4] = 32 bytes; we treat it as char[32]. */
    __builtin_memcpy(&e->data[0], path, 32);

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}
