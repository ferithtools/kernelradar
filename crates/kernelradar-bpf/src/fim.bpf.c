// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Ferith Tools
//
// kernelradar - File Integrity Monitor
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
#include "../include/stats.h"

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

/* Cheap prefix filter - we only care about /etc/, /root, /home/ */
static __always_inline int is_sensitive_prefix(const char *p)
{
    if (p[0] != '/') return 0;

    /* /etc/ - five chars */
    if (p[1] == 'e' && p[2] == 't' && p[3] == 'c' && p[4] == '/')
        return 1;
    /* /root - five chars (matches /root, /root/, /root/.ssh/...) */
    if (p[1] == 'r' && p[2] == 'o' && p[3] == 'o' && p[4] == 't')
        return 1;
    /* /home/ - six chars */
    if (p[1] == 'h' && p[2] == 'o' && p[3] == 'm'
        && p[4] == 'e' && p[5] == '/')
        return 1;

    return 0;
}

/* Returns 1 if `p` (NUL-terminated, scanned up to `max` bytes)
 * contains a "/../" or "/..\0" sequence (parent-directory
 * reference - i.e. a real path-traversal token, not just three
 * arbitrary bytes). Earlier versions matched any `/`, `.`, `.`
 * triple, which false-positived on filenames like
 * "/var/cache/...metadata", "/srv/repo.git/...pack", or
 * "/home/u/...build". Now we require the next byte to be a path
 * separator or NUL terminator so that `..` actually means
 * "parent dir" rather than the start of a longer filename.
 *
 * Limitations (see docs/threat-model.md):
 *   - chdir()+relative openat (path arg becomes "shadow") is NOT
 *     covered here - this only sees the path actually passed to
 *     openat(), not its kernel-resolved canonical form.
 *   - openat(dirfd, "shadow", ...) likewise.
 *   - bind-mount tricks (`/mnt/etc/shadow` shadowing /etc) are not
 *     detected. Full coverage requires lsm/file_open + bpf_d_path,
 *     scheduled for v0.2.
 */
static __always_inline int contains_dotdot(const char *p, int max)
{
    #pragma unroll
    for (int i = 0; i < 29; i++) {
        if (i + 3 >= max)
            return 0;
        if (p[i] == 0)
            return 0;
        if (p[i] == '/' && p[i + 1] == '.' && p[i + 2] == '.'
            && (p[i + 3] == '/' || p[i + 3] == 0))
            return 1;
    }
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

    int sensitive = is_sensitive_prefix(path);
    int traversal = contains_dotdot(path, 32);

    if (!sensitive && !traversal)
        return 0;

    kr_stat_inc(KR_STAT_FIM_OBSERVED);

    /* Sensitive - emit full event. Path-traversal attempts always
     * raise CRITICAL because the only legitimate caller hitting
     * write-mode openat with `/..` in the argument is a deliberate
     * obfuscation. */
    struct kr_event *e = bpf_ringbuf_reserve(&kr_fim_events,
                                              sizeof(*e), 0);
    if (!e) {
        kr_stat_inc(KR_STAT_FIM_DROPPED);
        return 0;
    }

    __u64 id = bpf_get_current_pid_tgid();
    __u64 ug = bpf_get_current_uid_gid();

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid          = (__u32)(id >> 32);
    e->tid          = (__u32)id;
    e->uid          = (__u32)ug;
    e->gid          = (__u32)(ug >> 32);
    e->detector_id  = KR_DETECTOR_FIM;
    e->severity     = traversal ? KR_SEV_CRITICAL : KR_SEV_WARNING;
    e->event_type   = traversal ? KR_FIM_PATH_TRAVERSAL : KR_FIM_OPEN_WRITE;

    /* Pack path bytes into the 32-byte data[] field.
     * data is __u64[4] = 32 bytes; we treat it as char[32]. */
    __builtin_memcpy(&e->data[0], path, 32);

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}
