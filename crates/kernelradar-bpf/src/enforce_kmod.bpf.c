// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Ferith Tools
//
// kernelradar - kmod enforcement
//
// LSM hook on kernel_read_file that denies READING_MODULE when the
// calling process is not allowlisted. OFF by default.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define COMM_LEN 16

/* enum kernel_read_file_id (uapi/linux/kmod.h) */
#define READING_MODULE 1

struct comm_key { char name[COMM_LEN]; };

struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __type(key,         struct comm_key);
    __type(value,       __u8);
    __uint(max_entries, 256);
} kr_kmod_allowed SEC(".maps");

/* int kernel_read_file(struct file *file, enum kernel_read_file_id id) */
SEC("lsm/kernel_read_file")
int BPF_PROG(kr_kmod_enforce, struct file *file, int id)
{
    if (id != READING_MODULE)
        return 0;

    struct comm_key k = {};
    bpf_get_current_comm(&k.name, sizeof(k.name));

    __u8 *ok = bpf_map_lookup_elem(&kr_kmod_allowed, &k);
    if (ok && *ok != 0)
        return 0;

    return -1; /* -EPERM */
}
