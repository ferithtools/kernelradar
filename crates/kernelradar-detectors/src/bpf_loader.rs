/// BPF Program Loader Auditor
///
/// Attaches a READ-ONLY tracepoint to sys_enter_bpf.
/// Emits an alert whenever BPF_PROG_LOAD is called by a process
/// not in the allowlist.
///
/// Why this matters: BPF-based rootkits load malicious programs
/// (BPF_PROG_TYPE_LSM, BPF_PROG_TYPE_KPROBE) to hook kernel functions.
/// Legitimate loaders are known (bpftrace, falco, kernelradar itself).

use anyhow::{Context, Result};
use aya::{maps::RingBuf, programs::TracePoint, Ebpf};
use std::path::Path;
use tokio::signal;

use kernelradar_core::event::{KrEvent, Severity};

/// Human-readable names for BPF program types (from uapi/linux/bpf.h)
const PROG_TYPES: &[&str] = &[
    "UNSPEC", "SOCKET_FILTER", "KPROBE", "SCHED_CLS", "SCHED_ACT",
    "TRACEPOINT", "XDP", "PERF_EVENT", "CGROUP_SKB", "CGROUP_SOCK",
    "LWT_IN", "LWT_OUT", "LWT_XMIT", "SOCK_OPS", "SK_SKB",
    "CGROUP_DEVICE", "SK_MSG", "RAW_TRACEPOINT", "CGROUP_SOCK_ADDR",
    "LWT_SEG6LOCAL", "LIRC_MODE2", "SK_REUSEPORT", "FLOW_DISSECTOR",
    "CGROUP_SYSCTL", "RAW_TRACEPOINT_WRITABLE", "CGROUP_SOCKOPT",
    "TRACING", "STRUCT_OPS", "EXT", "LSM", "SK_LOOKUP", "SYSCALL",
    "NETFILTER",
];

fn prog_type_name(t: u32) -> String {
    PROG_TYPES
        .get(t as usize)
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("UNKNOWN({})", t))
}

pub struct BpfLoaderDetector {
    bpf_obj_path: String,
    allowlist:    Vec<String>,
}

impl BpfLoaderDetector {
    pub fn new(bpf_obj_path: &str, allowlist: Vec<String>) -> Self {
        Self {
            bpf_obj_path: bpf_obj_path.to_string(),
            allowlist,
        }
    }

    pub async fn run(&self) -> Result<()> {
        let path = Path::new(&self.bpf_obj_path);
        if !path.exists() {
            anyhow::bail!(
                "BPF object not found: {}\nBuild with: cd crates/kernelradar-bpf && make",
                self.bpf_obj_path
            );
        }

        let bytes = std::fs::read(path)
            .with_context(|| format!("reading {}", self.bpf_obj_path))?;

        tracing::info!(path = %self.bpf_obj_path, "loading BPF object");
        let mut bpf = Ebpf::load(&bytes)
            .context("BPF verifier rejected bpf_loader program")?;

        let tp: &mut TracePoint = bpf
            .program_mut("kr_tp_bpf_load")
            .context("kr_tp_bpf_load not found in BPF object")?
            .try_into()?;
        tp.load()?;
        tp.attach("syscalls", "sys_enter_bpf")
            .context("attach sys_enter_bpf")?;
        tracing::info!("attached tracepoint: syscalls/sys_enter_bpf");

        let ring_buf = bpf
            .map_mut("kr_bpfl_events")
            .context("kr_bpfl_events map not found")?;
        let mut ring: RingBuf<_> = RingBuf::try_from(ring_buf)?;

        println!("kernelradar bpf-loader: watching BPF_PROG_LOAD calls");
        println!("Allowlist: {:?}", self.allowlist);
        println!("Press Ctrl+C to stop.\n");

        loop {
            tokio::select! {
                _ = signal::ctrl_c() => {
                    tracing::info!("shutting down");
                    break;
                }
                _ = tokio::time::sleep(tokio::time::Duration::from_millis(100)) => {
                    while let Some(item) = ring.next() {
                        if item.len() < std::mem::size_of::<KrEvent>() {
                            continue;
                        }
                        let ev: KrEvent = unsafe {
                            std::ptr::read_unaligned(item.as_ptr() as *const KrEvent)
                        };
                        self.handle_event(&ev);
                    }
                }
            }
        }

        Ok(())
    }

    fn handle_event(&self, ev: &KrEvent) {
        let comm = String::from_utf8_lossy(
            ev.comm.split(|&b| b == 0).next().unwrap_or(&[]),
        ).to_string();

        let prog_type = prog_type_name(ev.data[0] as u32);

        let allowed = self.allowlist.iter().any(|a| {
            a == &comm || a.ends_with(&comm)
        });

        if allowed {
            tracing::debug!(
                pid = ev.pid, uid = ev.uid, comm = %comm,
                prog_type = %prog_type, "BPF load by allowlisted process"
            );
            return;
        }

        let sev_label = match ev.severity {
            s if s >= Severity::Critical as u8 => "CRITICAL",
            s if s >= Severity::Alert   as u8 => "ALERT",
            _                                  => "WARNING",
        };

        println!(
            "[{sev}] pid={pid} uid={uid} comm={comm} loaded BPF prog_type={ptype}",
            sev   = sev_label,
            pid   = ev.pid,
            uid   = ev.uid,
            comm  = comm,
            ptype = prog_type,
        );
    }
}
