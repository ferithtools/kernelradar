use serde::{Deserialize, Serialize};

/// Mirror of the BPF-side `kr_event` struct.
/// Must match `crates/kernelradar-bpf/include/events.h` exactly.
#[repr(C)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KrEvent {
    pub timestamp_ns: u64,
    pub pid:          u32,
    pub tid:          u32,
    pub uid:          u32,
    pub gid:          u32,
    pub comm:         [u8; 16],
    pub detector_id:  u8,
    pub severity:     u8,
    pub event_type:   u16,
    /// Detector-specific payload, 32 bytes
    pub data:         [u64; 4],
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectorId {
    PrivEsc    = 1,
    BpfRootkit = 2,
    Container  = 3,
    KernelMod  = 4,
    Fim        = 5,
    Network    = 6,
    Injection  = 7,
    Cred       = 8,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info     = 0,
    Warning  = 1,
    Alert    = 2,
    Critical = 3,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info     => write!(f, "INFO"),
            Severity::Warning  => write!(f, "WARNING"),
            Severity::Alert    => write!(f, "ALERT"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}
