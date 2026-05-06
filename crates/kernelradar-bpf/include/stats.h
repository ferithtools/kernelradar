/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 Ferith Tools
 *
 * Shared kr_stats map definition. Each BPF program SHOULD include
 * this once and use the helper macros to bump counters.
 *
 * Pinned by-name to /sys/fs/bpf/kr_stats so multiple BPF objects
 * share the same map even though they are loaded as separate Ebpf
 * instances.
 */

#pragma once

#include "events.h"

struct {
    __uint(type,        BPF_MAP_TYPE_ARRAY);
    __type(key,         __u32);
    __type(value,       __u64);
    __uint(max_entries, KR_STAT_SLOTS);
} kr_stats SEC(".maps");

static __always_inline void kr_stat_inc(__u32 slot)
{
    __u64 *v = bpf_map_lookup_elem(&kr_stats, &slot);
    if (v) __sync_fetch_and_add(v, 1);
}
