// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Ferith Tools
//
// Part of the kernelradar project - Linux kernel anomaly detection via BPF.
// See LICENSE for terms.

use anyhow::Result;

use crate::allowlist::SharedAllowlist;
use crate::runtime::TracepointDetector;
use crate::util::{comm_str, make_alert, print_alert, read_exe_path_verified};
use kernelradar_core::event::KrEvent;

const PROG_TYPES: &[&str] = &[
    "UNSPEC",
    "SOCKET_FILTER",
    "KPROBE",
    "SCHED_CLS",
    "SCHED_ACT",
    "TRACEPOINT",
    "XDP",
    "PERF_EVENT",
    "CGROUP_SKB",
    "CGROUP_SOCK",
    "LWT_IN",
    "LWT_OUT",
    "LWT_XMIT",
    "SOCK_OPS",
    "SK_SKB",
    "CGROUP_DEVICE",
    "SK_MSG",
    "RAW_TRACEPOINT",
    "CGROUP_SOCK_ADDR",
    "LWT_SEG6LOCAL",
    "LIRC_MODE2",
    "SK_REUSEPORT",
    "FLOW_DISSECTOR",
    "CGROUP_SYSCTL",
    "RAW_TRACEPOINT_WRITABLE",
    "CGROUP_SOCKOPT",
    "TRACING",
    "STRUCT_OPS",
    "EXT",
    "LSM",
    "SK_LOOKUP",
    "SYSCALL",
    "NETFILTER",
];

fn prog_type_name(t: u32) -> &'static str {
    PROG_TYPES.get(t as usize).copied().unwrap_or("UNKNOWN")
}

pub struct BpfLoaderDetector {
    bpf_obj_path: String,
    allowlist: SharedAllowlist,
}

impl BpfLoaderDetector {
    pub fn new(bpf_obj_path: &str, allowlist: SharedAllowlist) -> Self {
        Self {
            bpf_obj_path: bpf_obj_path.to_string(),
            allowlist,
        }
    }

    pub async fn run(&self) -> Result<()> {
        let mut det = TracepointDetector::load("bpf_loader", &self.bpf_obj_path, "bpfl")?;
        det.attach_tracepoint("kr_tp_bpf_load", "syscalls", "sys_enter_bpf")?;

        tracing::info!(
            detector = "bpf-loader",
            allowlist_size = self.allowlist.snapshot().len(),
            "watching BPF_PROG_LOAD"
        );

        det.run("kr_bpfl_events", |ev| self.handle(ev)).await
    }

    fn handle(&self, ev: &KrEvent) {
        let comm = comm_str(ev);
        let exe = read_exe_path_verified(ev.pid, &comm);
        let al = self.allowlist.snapshot();
        if al.is_allowed(&comm, exe.as_deref()) {
            return;
        }

        let prog_type = prog_type_name(ev.data[0] as u32);
        let title = format!("BPF_PROG_LOAD type={prog_type} by {comm}");
        let ctx = serde_json::json!({
            "prog_type": prog_type,
            "exe":       exe,
        });
        let alert = make_alert(ev, exe.as_deref(), "bpf-loader", &title, ctx);
        print_alert(&alert, false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known BPF prog type indices map to their kernel names.
    #[test]
    fn prog_type_name_known_indices() {
        assert_eq!(prog_type_name(0), "UNSPEC");
        assert_eq!(prog_type_name(2), "KPROBE");
        assert_eq!(prog_type_name(5), "TRACEPOINT");
        assert_eq!(prog_type_name(6), "XDP");
        assert_eq!(prog_type_name(26), "TRACING");
        assert_eq!(prog_type_name(29), "LSM");
        assert_eq!(prog_type_name(31), "SYSCALL");
        assert_eq!(prog_type_name(32), "NETFILTER");
    }

    /// Out-of-range and saturating-large indices fall back to "UNKNOWN".
    #[test]
    fn prog_type_name_unknown_for_oob() {
        assert_eq!(prog_type_name(PROG_TYPES.len() as u32), "UNKNOWN");
        assert_eq!(prog_type_name(99), "UNKNOWN");
        assert_eq!(prog_type_name(u32::MAX), "UNKNOWN");
    }

    /// Every defined index resolves (no holes in the table).
    #[test]
    fn prog_type_name_table_complete() {
        for i in 0..PROG_TYPES.len() as u32 {
            assert_ne!(
                prog_type_name(i),
                "UNKNOWN",
                "index {i} unexpectedly returns UNKNOWN"
            );
        }
    }
}
