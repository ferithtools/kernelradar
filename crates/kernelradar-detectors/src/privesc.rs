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

pub struct PrivEscDetector {
    bpf_obj_path: String,
    allowlist: SharedAllowlist,
}

impl PrivEscDetector {
    pub fn new(bpf_obj_path: &str, allowlist: SharedAllowlist) -> Self {
        Self {
            bpf_obj_path: bpf_obj_path.to_string(),
            allowlist,
        }
    }

    pub async fn run(&self) -> Result<()> {
        let mut det = TracepointDetector::load("privesc", &self.bpf_obj_path, "privesc")?;
        det.attach_tracepoint("kr_tp_setuid", "syscalls", "sys_enter_setuid")?
            .attach_tracepoint("kr_tp_setgid", "syscalls", "sys_enter_setgid")?;

        tracing::info!(
            detector = "privesc",
            allowlist_size = self.allowlist.snapshot().len(),
            "watching setuid/setgid → root"
        );

        det.run("kr_events", |ev| self.handle(ev)).await
    }

    fn handle(&self, ev: &KrEvent) {
        let comm = comm_str(ev);
        let exe = read_exe_path_verified(ev.pid, &comm);
        let al = self.allowlist.snapshot();
        if al.is_allowed(&comm, exe.as_deref()) {
            return;
        }

        let call = if ev.event_type == 1 {
            "setuid"
        } else {
            "setgid"
        };
        let title = format!("{call}(0) - uid {} → 0 by {}", ev.data[0], comm);
        let ctx = serde_json::json!({
            "call":    call,
            "old_id":  ev.data[0],
            "new_id":  ev.data[1],
            "exe":     exe,
        });
        let alert = make_alert(ev, exe.as_deref(), "privesc", &title, ctx);
        print_alert(&alert, false);
    }
}
