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
        let path = Path::new(&self.bpf_obj_path);
        anyhow::ensure!(path.exists(), "BPF object not found: {}", self.bpf_obj_path);

        let bytes = std::fs::read(path)?;
        verify_bpf("kmod", &bytes)?;
        let mut bpf = Ebpf::load(&bytes).context("verifier rejected kmod BPF")?;

        // H-3: pin kr_stats for external tooling.
        if let Some(stats) = bpf.map_mut("kr_stats") {
            let _ = stats.pin("/sys/fs/bpf/kr_stats_kmod");
        }

        for (name, tp) in [
            ("kr_tp_finit_module", "sys_enter_finit_module"),
            ("kr_tp_init_module", "sys_enter_init_module"),
        ] {
            let prog: &mut TracePoint = bpf.program_mut(name).context(name)?.try_into()?;
            prog.load()?;
            prog.attach("syscalls", tp)
                .with_context(|| format!("attach {tp}"))?;
            tracing::info!("attached tracepoint: syscalls/{tp}");
        }

        let mut ring: RingBuf<_> = RingBuf::try_from(
            bpf.map_mut("kr_kmod_events")
                .context("kr_kmod_events not found")?,
        )?;

        tracing::info!(
            detector = "kmod",
            allowlist_size = self.allowlist.snapshot().len(),
            "watching finit_module() + init_module()"
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

        let (title, ctx) = if ev.event_type == 2 {
            (
                format!("init_module() LOAD FROM MEMORY by {comm} — rootkit technique"),
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
