/// BPF Program Loader Auditor — Phase 1
///
/// Observes:
///   - sys_enter_bpf with cmd=BPF_PROG_LOAD
///
/// Alerts when:
///   - BPF_PROG_LOAD issued by a process not in the allowlist
///   - Unusual prog_type (e.g. BPF_PROG_TYPE_LSM from non-root)
///   - BPF program load at unusual time (post-startup)

use anyhow::Result;

pub struct BpfLoaderDetector {
    allowlist: Vec<String>,
}

impl BpfLoaderDetector {
    pub fn new(allowlist: Vec<String>) -> Result<Self> {
        Ok(Self { allowlist })
    }

    pub async fn run(&self) -> Result<()> {
        tracing::info!("BpfLoader detector: BPF programs not yet compiled");
        tracing::info!("Allowlist: {:?}", self.allowlist);
        Ok(())
    }
}
