// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Ferith Tools
//
// kernelradar - Network anomaly detector
//
// Hooks sys_enter_connect. Filters in BPF: emit events only for
// AF_INET connections to non-private IPv4 addresses (filters out
// loopback, RFC1918, link-local). Userspace adds severity rules
// for known-bad ports.
//
// Volume concern: a busy server may make hundreds of public
// connections per second (DNS, NTP, package mirrors). Userspace
// applies allowlist + future rate limiting.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../include/events.h"
#include "../include/stats.h"

char LICENSE[] SEC("license") = "GPL";

#define AF_INET   2

struct {
    __uint(type,        BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} kr_net_events SEC(".maps");

/* Returns 1 if IPv4 address is private/loopback/link-local.
 * addr is in network byte order (big-endian). */
static __always_inline int is_private_ipv4(__u32 addr_be)
{
    __u8 b0 = (__u8)(addr_be & 0xff);          /* first octet */
    __u8 b1 = (__u8)((addr_be >> 8) & 0xff);   /* second octet */

    if (b0 == 127) return 1;                                     /* 127/8 loopback */
    if (b0 ==  10) return 1;                                     /* 10/8 RFC1918 */
    if (b0 == 172 && b1 >= 16 && b1 <= 31) return 1;             /* 172.16/12 */
    if (b0 == 192 && b1 == 168) return 1;                        /* 192.168/16 */
    if (b0 == 169 && b1 == 254) return 1;                        /* 169.254/16 link-local */
    if (b0 == 100 && b1 >= 64 && b1 <= 127) return 1;            /* 100.64/10 CGNAT */
    if (b0 >= 224) return 1;                                     /* 224/4 multicast + 240/4 reserved */
    if (b0 == 0)   return 1;                                     /* 0.0.0.0/8 */
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int kr_tp_connect(struct trace_event_raw_sys_enter *ctx)
{
    void *uaddr  = (void *)ctx->args[1];
    int   addrlen = (int)ctx->args[2];

    /* Need at least 8 bytes for sockaddr_in (family + port + ipv4) */
    if (addrlen < 8)
        return 0;

    __u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), uaddr);
    if (family != AF_INET)
        return 0;

    __u16 port_be = 0;
    __u32 addr_be = 0;
    bpf_probe_read_user(&port_be, sizeof(port_be), uaddr + 2);
    bpf_probe_read_user(&addr_be, sizeof(addr_be), uaddr + 4);

    if (is_private_ipv4(addr_be))
        return 0;

    kr_stat_inc(KR_STAT_NETWORK_OBSERVED);

    struct kr_event *e = bpf_ringbuf_reserve(&kr_net_events,
                                              sizeof(*e), 0);
    if (!e) {
        kr_stat_inc(KR_STAT_NETWORK_DROPPED);
        return 0;
    }

    __u64 id = bpf_get_current_pid_tgid();
    __u64 ug = bpf_get_current_uid_gid();

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid          = (__u32)(id >> 32);
    e->tid          = (__u32)id;
    e->uid          = (__u32)ug;
    e->gid          = (__u32)(ug >> 32);
    e->detector_id  = KR_DETECTOR_NETWORK;
    e->severity     = KR_SEV_WARNING;
    e->event_type   = KR_NET_CONNECT_PUBLIC;

    /* Pack: data[0] low 32 = AF<<16 | port_be, data[1] = addr_be */
    e->data[0] = ((__u64)family << 16) | (__u64)port_be;
    e->data[1] = (__u64)addr_be;
    e->data[2] = 0;
    e->data[3] = 0;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}
