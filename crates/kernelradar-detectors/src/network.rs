// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Ferith Tools
//
// Part of the kernelradar project - Linux kernel anomaly detection via BPF.
// See LICENSE for terms.

/// Network anomaly detector.
///
/// Watches outbound connect() to public (non-private) IPv4 addresses.
/// BPF filters out loopback, RFC1918, link-local, CGNAT, multicast.
/// Userspace adds severity rules for ports commonly used by
/// reverse shells (4444, 4445, 5555, 6666, 6667, 1337, 31337).
use anyhow::Result;
use std::net::Ipv4Addr;

use crate::allowlist::SharedAllowlist;
use crate::cidr::SharedCidrList;
use crate::runtime::TracepointDetector;
use crate::util::{comm_str, make_alert, print_alert, read_exe_path_verified};
use kernelradar_core::event::KrEvent;

/// Ports often associated with reverse shells / C2.
/// A connect() to one of these → severity bumped to ALERT.
const SUSPICIOUS_PORTS: &[u16] = &[
    1337, 4444, 4445, 5555, 6666, 6667, 6697, 8080, 9001, 9050, 31337,
];

pub struct NetworkDetector {
    bpf_obj_path: String,
    allowlist: SharedAllowlist,
    /// Destination CIDR allowlist. Connections to addresses inside any
    /// listed CIDR are suppressed before process-allowlist evaluation.
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
        let mut det = TracepointDetector::load("network", &self.bpf_obj_path, "network")?;
        det.attach_tracepoint("kr_tp_connect", "syscalls", "sys_enter_connect")?;

        tracing::info!(
            detector = "network",
            allowlist_size = self.allowlist.snapshot().len(),
            cidr_allowlist_size = self.cidrs.len(),
            "watching connect() to public IPs"
        );

        det.run("kr_net_events", |ev| self.handle(ev)).await
    }

    fn handle(&self, ev: &KrEvent) {
        // data[0] low 32 bits = (family << 16) | port_be
        // data[1] = ipv4 addr_be
        let port_be = (ev.data[0] & 0xffff) as u16;
        let addr_be = (ev.data[1] & 0xffffffff) as u32;

        let port = u16::from_be(port_be);
        let ip_host = u32::from_be(addr_be);
        let ip = Ipv4Addr::from(ip_host);

        // Destination CIDR allowlist short-circuits before process
        // attribution - saves the /proc/<pid>/exe read for whitelisted
        // destinations on busy hosts (Telegram heartbeats, etc.).
        if self.cidrs.contains(ip_host) {
            return;
        }

        let comm = comm_str(ev);
        let exe = read_exe_path_verified(ev.pid, &comm);
        let al = self.allowlist.snapshot();
        if al.is_allowed(&comm, exe.as_deref()) {
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
