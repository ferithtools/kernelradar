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

pub struct KmodDetector {
    bpf_obj_path: String,
    allowlist: SharedAllowlist,
}

impl KmodDetector {
    pub fn new(bpf_obj_path: &str, allowlist: SharedAllowlist) -> Self {
        Self {
            bpf_obj_path: bpf_obj_path.to_string(),
            allowlist,
        }
    }

    pub async fn run(&self) -> Result<()> {
        let mut det = TracepointDetector::load("kmod", &self.bpf_obj_path, "kmod")?;
        det.attach_tracepoint("kr_tp_finit_module", "syscalls", "sys_enter_finit_module")?
            .attach_tracepoint("kr_tp_init_module", "syscalls", "sys_enter_init_module")?;

        tracing::info!(
            detector = "kmod",
            allowlist_size = self.allowlist.snapshot().len(),
            "watching finit_module() + init_module()"
        );

        det.run("kr_kmod_events", |ev| self.handle(ev)).await
    }

    fn handle(&self, ev: &KrEvent) {
        let comm = comm_str(ev);
        let exe = read_exe_path_verified(ev.pid, &comm);
        let al = self.allowlist.snapshot();
        if al.is_allowed(&comm, exe.as_deref()) {
            return;
        }

        let (title, ctx) = if ev.event_type == 2 {
            (
                format!("init_module() LOAD FROM MEMORY by {comm} - rootkit technique"),
                serde_json::json!({"syscall":"init_module","exe":exe}),
            )
        } else {
            (
                format!("finit_module(fd={}) by {comm}", ev.data[0]),
                serde_json::json!({"syscall":"finit_module","fd":ev.data[0],"exe":exe}),
            )
        };

        let alert = make_alert(ev, exe.as_deref(), "kmod", &title, ctx);
        print_alert(&alert, false);
    }
}
