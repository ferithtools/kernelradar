// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Ferith Tools
//
// Part of the kernelradar project — Linux kernel anomaly detection via BPF.
// See LICENSE for terms.

use anyhow::{Context, Result};
use aya::{maps::RingBuf, programs::TracePoint, Ebpf};
use std::path::Path;
use tokio::signal;

use crate::allowlist::SharedAllowlist;
use crate::integrity::verify as verify_bpf;
use crate::util::{comm_str, is_allowed, make_alert, print_alert, read_exe_path_verified};
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
        let path = Path::new(&self.bpf_obj_path);
        anyhow::ensure!(path.exists(), "BPF object not found: {}", self.bpf_obj_path);

        let bytes = std::fs::read(path)?;
        // Hash key matches build.rs `names` table (filename, underscore).
        verify_bpf("bpf_loader", &bytes)?;
        let mut bpf = Ebpf::load(&bytes).context("verifier rejected bpf_loader BPF")?;

        // Pin kr_stats so external tools and the Prometheus exporter
        // can read observed/dropped counts.
        if let Some(stats) = bpf.map_mut("kr_stats") {
            let _ = stats.pin("/sys/fs/bpf/kr_stats_bpfl");
        }

        let tp: &mut TracePoint = bpf
            .program_mut("kr_tp_bpf_load")
            .context("kr_tp_bpf_load")?
            .try_into()?;
        tp.load()?;
        tp.attach("syscalls", "sys_enter_bpf")?;
        tracing::info!("attached tracepoint: syscalls/sys_enter_bpf");

        let mut ring: RingBuf<_> = RingBuf::try_from(
            bpf.map_mut("kr_bpfl_events")
                .context("kr_bpfl_events not found")?,
        )?;

        tracing::info!(
            detector = "bpf-loader",
            allowlist_size = self.allowlist.snapshot().len(),
            "watching BPF_PROG_LOAD"
        );

        loop {
            tokio::select! {
                _ = signal::ctrl_c() => break,
                _ = tokio::time::sleep(tokio::time::Duration::from_millis(100)) => {
                    while let Some(item) = ring.next() {
                        if item.len() < std::mem::size_of::<KrEvent>() { continue; }
                        let ev: KrEvent = unsafe {
                            std::ptr::read_unaligned(item.as_ptr() as *const KrEvent)
                        };
                        self.handle(&ev);
                    }
                }
            }
        }
        Ok(())
    }

    fn handle(&self, ev: &KrEvent) {
        let comm = comm_str(ev);
        let exe = read_exe_path_verified(ev.pid, &comm);
        let al = self.allowlist.snapshot();
        if is_allowed(&comm, exe.as_deref(), &al) {
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
