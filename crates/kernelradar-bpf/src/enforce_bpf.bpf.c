// SPDX-License-Identifier: GPL-2.0
//
// kernelradar — bpf-loader enforcement (T-0.9)
//
// LSM hook on `bpf` that DENIES BPF_PROG_LOAD when the calling
// process's `comm` is not in our allowlist map.
//
// SAFETY: this is OFF by default. Enabling it can break legitimate
// services that load BPF dynamically (Cilium, Falco running alongside,
// custom telemetry agents). Pre-populate the allowlist carefully.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define BPF_PROG_LOAD 5
#define COMM_LEN      16

struct comm_key { char name[COMM_LEN]; };

/* Userspace populates this map at startup with comm strings of
 * processes allowed to load BPF programs. Non-empty value = allowed. */
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __type(key,         struct comm_key);
    __type(value,       __u8);
    __uint(max_entries, 256);
} kr_bpf_allowed SEC(".maps");

SEC("lsm/bpf")
int BPF_PROG(kr_bpf_enforce, int cmd, union bpf_attr *attr, unsigned int size)
{
    if (cmd != BPF_PROG_LOAD)
        return 0;

    /* uid 0 is normally the only one allowed to load anyway, but
     * let userspace decide via the map — this leaves the door open
     * for delegated unprivileged BPF in the future. */
    struct comm_key k = {};
    bpf_get_current_comm(&k.name, sizeof(k.name));

    __u8 *ok = bpf_map_lookup_elem(&kr_bpf_allowed, &k);
    if (ok && *ok != 0)
        return 0;

    return -1; /* -EPERM */
}
