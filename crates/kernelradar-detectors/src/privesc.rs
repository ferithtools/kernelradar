/// Privilege Escalation Tracker
///
/// Loads privesc.bpf.o and attaches two READ-ONLY tracepoints:
///   sys_enter_setuid  — fires when any process calls setuid(0)
///   sys_enter_setgid  — fires when any process calls setgid(0)
///
/// Safety: tracepoints are observation-only. They cannot block or kill
/// processes. Aya drops all BPF resources when the struct is dropped.

use anyhow::{Context, Result};
use aya::{
    maps::RingBuf,
    programs::TracePoint,
    Ebpf,
};
use std::path::Path;
use tokio::signal;

use kernelradar_core::event::{KrEvent, Severity};

pub struct PrivEscDetector {
    bpf_obj_path: String,
}

impl PrivEscDetector {
    pub fn new(bpf_obj_path: &str) -> Self {
        Self { bpf_obj_path: bpf_obj_path.to_string() }
    }

    pub async fn run(&self) -> Result<()> {
        let path = Path::new(&self.bpf_obj_path);
        if !path.exists() {
            anyhow::bail!(
                "BPF object not found: {}\n\
                 Build it first:\n  \
                 cd crates/kernelradar-bpf && make",
                self.bpf_obj_path
            );
        }

        let bytes = std::fs::read(path)
            .with_context(|| format!("reading {}", self.bpf_obj_path))?;

        tracing::info!(path = %self.bpf_obj_path, "loading BPF object");
        let mut bpf = Ebpf::load(&bytes)
            .context("BPF verifier rejected the program")?;

        // ── Attach tracepoints (read-only, safe) ────────────────────────
        let tp_setuid: &mut TracePoint = bpf
            .program_mut("kr_tp_setuid")
            .context("kr_tp_setuid not found in BPF object")?
            .try_into()?;
        tp_setuid.load()?;
        tp_setuid
            .attach("syscalls", "sys_enter_setuid")
            .context("attach sys_enter_setuid")?;
        tracing::info!("attached tracepoint: syscalls/sys_enter_setuid");

        let tp_setgid: &mut TracePoint = bpf
            .program_mut("kr_tp_setgid")
            .context("kr_tp_setgid not found in BPF object")?
            .try_into()?;
        tp_setgid.load()?;
        tp_setgid
            .attach("syscalls", "sys_enter_setgid")
            .context("attach sys_enter_setgid")?;
        tracing::info!("attached tracepoint: syscalls/sys_enter_setgid");

        // ── Ring buffer reader ───────────────────────────────────────────
        let ring_buf = bpf
            .map_mut("kr_events")
            .context("kr_events map not found")?;
        let mut ring: RingBuf<_> = RingBuf::try_from(ring_buf)?;

        println!("kernelradar privesc: watching setuid/setgid → root calls");
        println!("Press Ctrl+C to stop.\n");

        loop {
            tokio::select! {
                _ = signal::ctrl_c() => {
                    tracing::info!("shutting down — BPF programs unloaded");
                    break;
                }
                _ = tokio::time::sleep(tokio::time::Duration::from_millis(100)) => {
                    while let Some(item) = ring.next() {
                        if item.len() < std::mem::size_of::<KrEvent>() {
                            continue;
                        }
                        // SAFETY: we control the BPF program that produces
                        // exactly sizeof(kr_event) bytes in the correct layout.
                        let ev: KrEvent = unsafe {
                            std::ptr::read_unaligned(item.as_ptr() as *const KrEvent)
                        };
                        print_event(&ev);
                    }
                }
            }
        }

        // bpf is dropped here — Aya detaches all programs automatically
        Ok(())
    }
}

fn print_event(ev: &KrEvent) {
    let comm = String::from_utf8_lossy(
        ev.comm.split(|&b| b == 0).next().unwrap_or(&[]),
    );
    let sev = match ev.severity {
        s if s >= Severity::Critical as u8 => "CRITICAL",
        s if s >= Severity::Alert   as u8 => "ALERT",
        s if s >= Severity::Warning as u8 => "WARNING",
        _                                  => "INFO",
    };
    let old_id = ev.data[0] as u32;
    let new_id = ev.data[1] as u32;
    let call   = if ev.event_type == 1 { "setuid" } else { "setgid" };

    println!(
        "[{sev}] pid={pid} uid={uid} comm={comm} → {call}({new_id}) [was {old_id}]",
        pid  = ev.pid,
        uid  = ev.uid,
        comm = comm,
    );
}
