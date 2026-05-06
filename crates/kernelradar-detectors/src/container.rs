/// Container Escape Detector
///
/// Watches unshare() and setns() — the two main syscalls used to
/// break out of container namespace isolation.

use anyhow::{Context, Result};
use aya::{maps::RingBuf, programs::TracePoint, Ebpf};
use std::path::Path;
use tokio::signal;

use kernelradar_core::event::KrEvent;

const CLONE_NEWNS:     u64 = 0x00020000;
const CLONE_NEWUSER:   u64 = 0x10000000;
const CLONE_NEWPID:    u64 = 0x20000000;
const CLONE_NEWNET:    u64 = 0x40000000;
const CLONE_NEWIPC:    u64 = 0x08000000;
const CLONE_NEWUTS:    u64 = 0x04000000;
const CLONE_NEWCGROUP: u64 = 0x02000000;

fn decode_ns_flags(flags: u64) -> String {
    let mut parts = Vec::new();
    if flags & CLONE_NEWNS     != 0 { parts.push("NEWNS");     }
    if flags & CLONE_NEWUSER   != 0 { parts.push("NEWUSER");   }
    if flags & CLONE_NEWPID    != 0 { parts.push("NEWPID");    }
    if flags & CLONE_NEWNET    != 0 { parts.push("NEWNET");    }
    if flags & CLONE_NEWIPC    != 0 { parts.push("NEWIPC");    }
    if flags & CLONE_NEWUTS    != 0 { parts.push("NEWUTS");    }
    if flags & CLONE_NEWCGROUP != 0 { parts.push("NEWCGROUP"); }
    if parts.is_empty() {
        format!("0x{:x}", flags)
    } else {
        parts.join("|")
    }
}

pub struct ContainerDetector {
    bpf_obj_path: String,
    allowlist:    Vec<String>,
}

impl ContainerDetector {
    pub fn new(bpf_obj_path: &str, allowlist: Vec<String>) -> Self {
        Self { bpf_obj_path: bpf_obj_path.to_string(), allowlist }
    }

    pub async fn run(&self) -> Result<()> {
        let path = Path::new(&self.bpf_obj_path);
        anyhow::ensure!(path.exists(),
            "BPF object not found: {}", self.bpf_obj_path);

        let bytes = std::fs::read(path)?;
        let mut bpf = Ebpf::load(&bytes)
            .context("verifier rejected container BPF")?;

        for (name, tracepoint) in [
            ("kr_tp_unshare", "sys_enter_unshare"),
            ("kr_tp_setns",   "sys_enter_setns"),
        ] {
            let tp: &mut TracePoint = bpf
                .program_mut(name).context(name)?.try_into()?;
            tp.load()?;
            tp.attach("syscalls", tracepoint)
                .with_context(|| format!("attach {tracepoint}"))?;
            tracing::info!("attached tracepoint: syscalls/{tracepoint}");
        }

        let mut ring: RingBuf<_> = RingBuf::try_from(
            bpf.map_mut("kr_container_events")
               .context("kr_container_events map not found")?
        )?;

        println!("kernelradar container: watching unshare() + setns()");
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

        let detail = if ev.event_type == 1 {
            // unshare: data[0] = flags
            format!("unshare({})", decode_ns_flags(ev.data[0]))
        } else {
            // setns: data[0] = fd, data[1] = nstype
            format!("setns(fd={}, nstype=0x{:x})", ev.data[0], ev.data[1])
        };

        println!(
            "[WARNING] pid={pid} uid={uid} comm={comm} → {detail}",
            pid  = ev.pid,
            uid  = ev.uid,
        );
    }
}
