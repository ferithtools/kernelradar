use anyhow::{Context, Result};
use aya::{maps::RingBuf, programs::TracePoint, Ebpf};
use std::path::Path;
use tokio::signal;

use kernelradar_core::event::KrEvent;
use crate::allowlist::SharedAllowlist;
use crate::util::{comm_str, is_allowed, make_alert, print_alert, read_exe_path};

const PROG_TYPES: &[&str] = &[
    "UNSPEC","SOCKET_FILTER","KPROBE","SCHED_CLS","SCHED_ACT",
    "TRACEPOINT","XDP","PERF_EVENT","CGROUP_SKB","CGROUP_SOCK",
    "LWT_IN","LWT_OUT","LWT_XMIT","SOCK_OPS","SK_SKB",
    "CGROUP_DEVICE","SK_MSG","RAW_TRACEPOINT","CGROUP_SOCK_ADDR",
    "LWT_SEG6LOCAL","LIRC_MODE2","SK_REUSEPORT","FLOW_DISSECTOR",
    "CGROUP_SYSCTL","RAW_TRACEPOINT_WRITABLE","CGROUP_SOCKOPT",
    "TRACING","STRUCT_OPS","EXT","LSM","SK_LOOKUP","SYSCALL","NETFILTER",
];

fn prog_type_name(t: u32) -> &'static str {
    PROG_TYPES.get(t as usize).copied().unwrap_or("UNKNOWN")
}

pub struct BpfLoaderDetector {
    bpf_obj_path: String,
    allowlist:    SharedAllowlist,
}

impl BpfLoaderDetector {
    pub fn new(bpf_obj_path: &str, allowlist: SharedAllowlist) -> Self {
        Self { bpf_obj_path: bpf_obj_path.to_string(), allowlist }
    }

    pub async fn run(&self) -> Result<()> {
        let path = Path::new(&self.bpf_obj_path);
        anyhow::ensure!(path.exists(), "BPF object not found: {}", self.bpf_obj_path);

        let mut bpf = Ebpf::load(&std::fs::read(path)?)
            .context("verifier rejected bpf_loader BPF")?;

        let tp: &mut TracePoint = bpf
            .program_mut("kr_tp_bpf_load").context("kr_tp_bpf_load")?.try_into()?;
        tp.load()?;
        tp.attach("syscalls", "sys_enter_bpf")?;
        tracing::info!("attached tracepoint: syscalls/sys_enter_bpf");

        let mut ring: RingBuf<_> = RingBuf::try_from(
            bpf.map_mut("kr_bpfl_events").context("kr_bpfl_events not found")?
        )?;

        tracing::info!(detector = "bpf-loader",
                        allowlist_size = self.allowlist.snapshot().len(),
                        "watching BPF_PROG_LOAD");

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

        let prog_type = prog_type_name(ev.data[0] as u32);
        let title = format!("BPF_PROG_LOAD type={prog_type} by {comm}");
        let ctx = serde_json::json!({
            "prog_type": prog_type,
            "exe":       exe,
        });
        let alert = make_alert(ev, exe.as_deref(), "bpf-loader", &title, ctx);
        print_alert(&alert, false);
    }
}
