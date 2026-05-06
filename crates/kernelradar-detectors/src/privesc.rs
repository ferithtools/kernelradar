/// Privilege Escalation Tracker — Phase 1
///
/// Observes:
///   - sys_enter_setuid / sys_enter_setresuid
///   - sys_enter_setgid / sys_enter_setresgid
///   - task_newtask (fork with changed credentials)
///
/// Alerts when:
///   - A process drops to uid=0 unexpectedly
///   - Credential transition happens outside of known-good paths (sudo, su, PAM)
///   - uid goes 0 → nonzero → 0 within a short window (classic privesc pattern)

// BPF skeleton will be generated here once BPF C sources are compiled.
// For now: placeholder with planned interface.

use anyhow::Result;
use kernelradar_core::alert::Alert;

pub struct PrivEscDetector {
    // bpf: PrivEscSkel<'static>,  // uncomment when BPF skeleton is ready
}

impl PrivEscDetector {
    pub fn new() -> Result<Self> {
        Ok(Self {})
    }

    pub async fn run(&self) -> Result<()> {
        tracing::info!("PrivEsc detector: BPF programs not yet compiled");
        tracing::info!("Next: implement crates/kernelradar-bpf/src/privesc.bpf.c");
        Ok(())
    }
}
