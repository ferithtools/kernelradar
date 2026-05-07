// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Ferith Tools
//
// Part of the kernelradar project - Linux kernel anomaly detection via BPF.
// See LICENSE for terms.

use anyhow::Result;

use crate::allowlist::SharedAllowlist;
use crate::runtime::TracepointDetector;
use crate::util::{comm_str, is_allowed, make_alert, print_alert, read_exe_path_verified};
use kernelradar_core::event::KrEvent;

const CLONE_NEWNS: u64 = 0x00020000;
const CLONE_NEWUSER: u64 = 0x10000000;
const CLONE_NEWPID: u64 = 0x20000000;
const CLONE_NEWNET: u64 = 0x40000000;
const CLONE_NEWIPC: u64 = 0x08000000;
const CLONE_NEWUTS: u64 = 0x04000000;
const CLONE_NEWCGROUP: u64 = 0x02000000;

fn decode_ns_flags(flags: u64) -> String {
    let mut parts = Vec::new();
    if flags & CLONE_NEWNS != 0 {
        parts.push("NEWNS");
    }
    if flags & CLONE_NEWUSER != 0 {
        parts.push("NEWUSER");
    }
    if flags & CLONE_NEWPID != 0 {
        parts.push("NEWPID");
    }
    if flags & CLONE_NEWNET != 0 {
        parts.push("NEWNET");
    }
    if flags & CLONE_NEWIPC != 0 {
        parts.push("NEWIPC");
    }
    if flags & CLONE_NEWUTS != 0 {
        parts.push("NEWUTS");
    }
    if flags & CLONE_NEWCGROUP != 0 {
        parts.push("NEWCGROUP");
    }
    if parts.is_empty() {
        format!("0x{:x}", flags)
    } else {
        parts.join("|")
    }
}

pub struct ContainerDetector {
    bpf_obj_path: String,
    allowlist: SharedAllowlist,
}

impl ContainerDetector {
    pub fn new(bpf_obj_path: &str, allowlist: SharedAllowlist) -> Self {
        Self {
            bpf_obj_path: bpf_obj_path.to_string(),
            allowlist,
        }
    }

    pub async fn run(&self) -> Result<()> {
        let mut det = TracepointDetector::load("container", &self.bpf_obj_path, "container")?;
        det.attach_tracepoint("kr_tp_unshare", "syscalls", "sys_enter_unshare")?
            .attach_tracepoint("kr_tp_setns", "syscalls", "sys_enter_setns")?;

        tracing::info!(
            detector = "container",
            allowlist_size = self.allowlist.snapshot().len(),
            "watching unshare() + setns()"
        );

        det.run("kr_container_events", |ev| self.handle(ev)).await
    }

    fn handle(&self, ev: &KrEvent) {
        let comm = comm_str(ev);
        let exe = read_exe_path_verified(ev.pid, &comm);
        let al = self.allowlist.snapshot();
        if is_allowed(&comm, exe.as_deref(), &al) {
            return;
        }

        let (title, ctx) = if ev.event_type == 1 {
            let flags = decode_ns_flags(ev.data[0]);
            (
                format!("unshare({flags}) by {comm}"),
                serde_json::json!({"syscall":"unshare","flags":flags,"exe":exe}),
            )
        } else {
            (
                format!("setns(nstype=0x{:x}) by {comm}", ev.data[1]),
                serde_json::json!({
                    "syscall": "setns",
                    "fd":      ev.data[0],
                    "nstype":  format!("0x{:x}", ev.data[1]),
                    "exe":     exe,
                }),
            )
        };

        let alert = make_alert(ev, exe.as_deref(), "container", &title, ctx);
        print_alert(&alert, false);
    }
}
