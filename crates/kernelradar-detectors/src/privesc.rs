use anyhow::{Context, Result};
use aya::{maps::RingBuf, programs::TracePoint, Ebpf};
use std::path::Path;
use tokio::signal;

use kernelradar_core::event::KrEvent;
use crate::allowlist::SharedAllowlist;
use crate::integrity::verify as verify_bpf;
use crate::util::{comm_str, is_allowed, make_alert, print_alert, read_exe_path};

pub struct PrivEscDetector {
    bpf_obj_path: String,
    allowlist:    SharedAllowlist,
}

impl PrivEscDetector {
    pub fn new(bpf_obj_path: &str, allowlist: SharedAllowlist) -> Self {
        Self { bpf_obj_path: bpf_obj_path.to_string(), allowlist }
    }

    pub async fn run(&self) -> Result<()> {
        let path = Path::new(&self.bpf_obj_path);
        anyhow::ensure!(path.exists(),
            "BPF object not found: {}\nBuild: cd crates/kernelradar-bpf && make",
            self.bpf_obj_path);

        let bytes = std::fs::read(path)?;
        verify_bpf("privesc", &bytes);
        let mut bpf = Ebpf::load(&bytes)
            .context("verifier rejected privesc BPF")?;

        // T-7.2/T-7.3: pin kr_stats so external tools (bpftool,
        // benchmark harness) can read it without owning the map.
        if let Some(stats) = bpf.map_mut("kr_stats") {
            let _ = stats.pin("/sys/fs/bpf/kr_stats_privesc");
        }

        for (name, tp) in [
            ("kr_tp_setuid", "sys_enter_setuid"),
            ("kr_tp_setgid", "sys_enter_setgid"),
        ] {
            let prog: &mut TracePoint = bpf
                .program_mut(name).context(name)?.try_into()?;
            prog.load()?;
            prog.attach("syscalls", tp)
                .with_context(|| format!("attach {tp}"))?;
            tracing::info!("attached tracepoint: syscalls/{tp}");
        }

        let mut ring: RingBuf<_> = RingBuf::try_from(
            bpf.map_mut("kr_events").context("kr_events not found")?
        )?;

        tracing::info!(detector = "privesc",
                        allowlist_size = self.allowlist.snapshot().len(),
                        "watching setuid/setgid → root");

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
        let exe  = read_exe_path(ev.pid);
        let al   = self.allowlist.snapshot();
        if is_allowed(&comm, exe.as_deref(), &al) { return; }

        let call = if ev.event_type == 1 { "setuid" } else { "setgid" };
        let title = format!(
            "{call}(0) — uid {} → 0 by {}",
            ev.data[0], comm
        );
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
