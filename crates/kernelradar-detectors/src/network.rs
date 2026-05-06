// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Ferith Tools
//
// Part of the kernelradar project — Linux kernel anomaly detection via BPF.
// See LICENSE for terms.

/// Network anomaly detector — T-0.6
///
/// Watches outbound connect() to public (non-private) IPv4 addresses.
/// BPF filters out loopback, RFC1918, link-local, CGNAT, multicast.
/// Userspace adds severity rules for ports commonly used by
/// reverse shells (4444, 4445, 5555, 6666, 6667, 1337, 31337).
use anyhow::{Context, Result};
use aya::{maps::RingBuf, programs::TracePoint, Ebpf};
use std::net::Ipv4Addr;
use std::path::Path;
use tokio::signal;

use crate::allowlist::SharedAllowlist;
use crate::cidr::SharedCidrList;
use crate::integrity::verify as verify_bpf;
use crate::util::{comm_str, is_allowed, make_alert, print_alert, read_exe_path};
use kernelradar_core::event::KrEvent;

/// Ports often associated with reverse shells / C2.
/// A connect() to one of these → severity bumped to ALERT.
const SUSPICIOUS_PORTS: &[u16] = &[
    1337, 4444, 4445, 5555, 6666, 6667, 6697, 8080, 9001, 9050, 31337,
];

pub struct NetworkDetector {
    bpf_obj_path: String,
    allowlist: SharedAllowlist,
    /// Destination CIDR allowlist (F-1). Connections to addresses inside
    /// any listed CIDR are suppressed before process-allowlist evaluation.
    cidrs: SharedCidrList,
}

impl NetworkDetector {
    pub fn new(bpf_obj_path: &str, allowlist: SharedAllowlist, cidrs: SharedCidrList) -> Self {
        Self {
            bpf_obj_path: bpf_obj_path.to_string(),
            allowlist,
            cidrs,
        }
    }

    pub async fn run(&self) -> Result<()> {
        let path = Path::new(&self.bpf_obj_path);
        anyhow::ensure!(path.exists(), "BPF object not found: {}", self.bpf_obj_path);

        let bytes = std::fs::read(path)?;
        verify_bpf("network", &bytes)?;
        let mut bpf = Ebpf::load(&bytes).context("verifier rejected network BPF")?;

        // H-3: pin kr_stats for external tooling.
        if let Some(stats) = bpf.map_mut("kr_stats") {
            let _ = stats.pin("/sys/fs/bpf/kr_stats_network");
        }

        let tp: &mut TracePoint = bpf
            .program_mut("kr_tp_connect")
            .context("kr_tp_connect")?
            .try_into()?;
        tp.load()?;
        tp.attach("syscalls", "sys_enter_connect")?;
        tracing::info!("attached tracepoint: syscalls/sys_enter_connect");

        let mut ring: RingBuf<_> = RingBuf::try_from(
            bpf.map_mut("kr_net_events")
                .context("kr_net_events not found")?,
        )?;

        tracing::info!(
            detector = "network",
            allowlist_size = self.allowlist.snapshot().len(),
            cidr_allowlist_size = self.cidrs.len(),
            "watching connect() to public IPs"
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
        // data[0] low 32 bits = (family << 16) | port_be
        // data[1] = ipv4 addr_be
        let port_be = (ev.data[0] & 0xffff) as u16;
        let addr_be = (ev.data[1] & 0xffffffff) as u32;

        let port = u16::from_be(port_be);
        let ip_host = u32::from_be(addr_be);
        let ip = Ipv4Addr::from(ip_host);

        // F-1: destination CIDR allowlist short-circuits before process
        // attribution — saves the /proc/<pid>/exe read for whitelisted
        // destinations on busy hosts (Telegram heartbeats, etc.).
        if self.cidrs.contains(ip_host) {
            return;
        }

        let comm = comm_str(ev);
        let exe = read_exe_path(ev.pid);
        let al = self.allowlist.snapshot();
        if is_allowed(&comm, exe.as_deref(), &al) {
            return;
        }

        let suspicious = SUSPICIOUS_PORTS.contains(&port);
        let mut ev_copy = ev.clone();
        if suspicious {
            ev_copy.severity = 3; // CRITICAL
        }

        let title = format!(
            "connect → {ip}:{port} by {comm}{}",
            if suspicious {
                "  ⚠ SUSPICIOUS PORT"
            } else {
                ""
            }
        );
        let ctx = serde_json::json!({
            "remote_ip":   ip.to_string(),
            "remote_port": port,
            "suspicious":  suspicious,
            "exe":         exe,
        });
        let alert = make_alert(&ev_copy, exe.as_deref(), "network", &title, ctx);
        print_alert(&alert, false);
    }
}
