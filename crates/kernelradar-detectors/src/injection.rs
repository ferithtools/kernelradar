// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Ferith Tools
//
// Part of the kernelradar project — Linux kernel anomaly detection via BPF.
// See LICENSE for terms.

/// Process injection detector — T-0.7
///
/// Watches ptrace() ATTACH/SEIZE/POKE and process_vm_writev() —
/// the three classic mechanisms for cross-process memory manipulation.
///
/// Default allowlist includes well-known debuggers (gdb, lldb, strace)
/// and tracing tools so legitimate development isn't flagged.
use anyhow::{Context, Result};
use aya::{maps::RingBuf, programs::TracePoint, Ebpf};
use std::path::Path;
use tokio::signal;

use crate::allowlist::SharedAllowlist;
use crate::integrity::verify as verify_bpf;
use crate::util::{comm_str, is_allowed, make_alert, print_alert, read_exe_path};
use kernelradar_core::event::KrEvent;

/// ptrace request → human-readable name
fn ptrace_request_name(req: u64) -> &'static str {
    match req {
        4 => "PTRACE_POKETEXT",
        5 => "PTRACE_POKEDATA",
        6 => "PTRACE_POKEUSER",
        16 => "PTRACE_ATTACH",
        0x4206 => "PTRACE_SEIZE",
        _ => "PTRACE_OTHER",
    }
}

pub struct InjectionDetector {
    bpf_obj_path: String,
    allowlist: SharedAllowlist,
}

impl InjectionDetector {
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
        verify_bpf("injection", &bytes);
        let mut bpf = Ebpf::load(&bytes).context("verifier rejected injection BPF")?;

        for (name, tp) in [
            ("kr_tp_ptrace", "sys_enter_ptrace"),
            ("kr_tp_pvm_writev", "sys_enter_process_vm_writev"),
        ] {
            let prog: &mut TracePoint = bpf.program_mut(name).context(name)?.try_into()?;
            prog.load()?;
            prog.attach("syscalls", tp)
                .with_context(|| format!("attach {tp}"))?;
            tracing::info!("attached tracepoint: syscalls/{tp}");
        }

        let mut ring: RingBuf<_> = RingBuf::try_from(
            bpf.map_mut("kr_inj_events")
                .context("kr_inj_events not found")?,
        )?;

        tracing::info!(
            detector = "injection",
            allowlist_size = self.allowlist.snapshot().len(),
            "watching ptrace() + process_vm_writev()"
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
        let exe = read_exe_path(ev.pid);
        let al = self.allowlist.snapshot();
        if is_allowed(&comm, exe.as_deref(), &al) {
            return;
        }

        let (title, ctx) = match ev.event_type {
            1 => {
                // PTRACE_ATTACH/SEIZE
                let req = ptrace_request_name(ev.data[0]);
                let target = ev.data[1] as u32;
                (
                    format!("{req} target_pid={target} by {comm}"),
                    serde_json::json!({
                        "syscall": "ptrace",
                        "request": req,
                        "target_pid": target,
                        "exe": exe,
                    }),
                )
            }
            2 => {
                // PTRACE_POKE*
                let req = ptrace_request_name(ev.data[0]);
                let target = ev.data[1] as u32;
                (
                    format!("{req} target_pid={target} by {comm} — memory write"),
                    serde_json::json!({
                        "syscall": "ptrace",
                        "request": req,
                        "target_pid": target,
                        "memory_write": true,
                        "exe": exe,
                    }),
                )
            }
            3 => {
                // process_vm_writev
                let target = ev.data[0] as u32;
                (
                    format!("process_vm_writev target_pid={target} by {comm}"),
                    serde_json::json!({
                        "syscall": "process_vm_writev",
                        "target_pid": target,
                        "exe": exe,
                    }),
                )
            }
            _ => return,
        };

        let alert = make_alert(ev, exe.as_deref(), "injection", &title, ctx);
        print_alert(&alert, false);
    }
}
