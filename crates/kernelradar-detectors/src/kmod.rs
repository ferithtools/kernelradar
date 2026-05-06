/// Kernel Module Rootkit Detector
///
/// Watches finit_module() and init_module() syscalls.
/// init_module (load from memory) is especially suspicious —
/// legitimate tools use finit_module (load from fd).

use anyhow::{Context, Result};
use aya::{maps::RingBuf, programs::TracePoint, Ebpf};
use std::path::Path;
use tokio::signal;

use kernelradar_core::event::KrEvent;

pub struct KmodDetector {
    bpf_obj_path: String,
    allowlist:    Vec<String>,
}

impl KmodDetector {
    pub fn new(bpf_obj_path: &str, allowlist: Vec<String>) -> Self {
        Self { bpf_obj_path: bpf_obj_path.to_string(), allowlist }
    }

    pub async fn run(&self) -> Result<()> {
        let path = Path::new(&self.bpf_obj_path);
        anyhow::ensure!(path.exists(),
            "BPF object not found: {}", self.bpf_obj_path);

        let bytes = std::fs::read(path)?;
        let mut bpf = Ebpf::load(&bytes)
            .context("verifier rejected kmod BPF")?;

        for (name, tracepoint) in [
            ("kr_tp_finit_module", "sys_enter_finit_module"),
            ("kr_tp_init_module",  "sys_enter_init_module"),
        ] {
            let tp: &mut TracePoint = bpf
                .program_mut(name).context(name)?.try_into()?;
            tp.load()?;
            tp.attach("syscalls", tracepoint)
                .with_context(|| format!("attach {tracepoint}"))?;
            tracing::info!("attached tracepoint: syscalls/{tracepoint}");
        }

        let mut ring: RingBuf<_> = RingBuf::try_from(
            bpf.map_mut("kr_kmod_events")
               .context("kr_kmod_events map not found")?
        )?;

        println!("kernelradar kmod: watching finit_module() + init_module()");
        println!("Allowlist: {:?}", self.allowlist);
        println!("Press Ctrl+C to stop.\n");

        loop {
            tokio::select! {
                _ = signal::ctrl_c() => break,
                _ = tokio::time::sleep(
                        tokio::time::Duration::from_millis(100)) => {
                    while let Some(item) = ring.next() {
                        if item.len() < std::mem::size_of::<KrEvent>() {
                            continue;
                        }
                        let ev: KrEvent = unsafe {
                            std::ptr::read_unaligned(
                                item.as_ptr() as *const KrEvent)
                        };
                        self.handle(&ev);
                    }
                }
            }
        }
        Ok(())
    }

    fn handle(&self, ev: &KrEvent) {
        let comm = String::from_utf8_lossy(
            ev.comm.split(|&b| b == 0).next().unwrap_or(&[])
        ).to_string();

        if self.allowlist.iter().any(|a| a == &comm) {
            return;
        }

        let (sev, detail) = if ev.event_type == 2 {
            // init_module — from memory, rootkit technique
            ("ALERT",   "init_module() — LOAD FROM MEMORY".to_string())
        } else {
            // finit_module — from fd, normal
            ("WARNING", format!("finit_module(fd={})", ev.data[0]))
        };

        println!(
            "[{sev}] pid={pid} uid={uid} comm={comm} → {detail}",
            pid  = ev.pid,
            uid  = ev.uid,
        );
    }
}
