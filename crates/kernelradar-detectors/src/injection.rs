// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Ferith Tools
//
// Part of the kernelradar project - Linux kernel anomaly detection via BPF.
// See LICENSE for terms.

/// Process injection detector.
///
/// Watches ptrace() ATTACH/SEIZE/POKE and process_vm_writev() -
/// the three classic mechanisms for cross-process memory manipulation.
///
/// Default allowlist includes well-known debuggers (gdb, lldb, strace)
/// and tracing tools so legitimate development isn't flagged.
use anyhow::Result;

use crate::allowlist::SharedAllowlist;
use crate::runtime::TracepointDetector;
use crate::util::{comm_str, is_allowed, make_alert, print_alert, read_exe_path_verified};
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
        let mut det = TracepointDetector::load("injection", &self.bpf_obj_path, "injection")?;
        det.attach_tracepoint("kr_tp_ptrace", "syscalls", "sys_enter_ptrace")?
            .attach_tracepoint(
                "kr_tp_pvm_writev",
                "syscalls",
                "sys_enter_process_vm_writev",
            )?;

        tracing::info!(
            detector = "injection",
            allowlist_size = self.allowlist.snapshot().len(),
            "watching ptrace() + process_vm_writev()"
        );

        det.run("kr_inj_events", |ev| self.handle(ev)).await
    }

    fn handle(&self, ev: &KrEvent) {
        let comm = comm_str(ev);
        let exe = read_exe_path_verified(ev.pid, &comm);
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
                    format!("{req} target_pid={target} by {comm} - memory write"),
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
