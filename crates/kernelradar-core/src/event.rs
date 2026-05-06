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

#[cfg(test)]
mod tests {
    use super::*;

    /// T-9.5 — KrEvent layout matches BPF-side struct.
    #[test]
    fn krevent_layout_is_repr_c_and_known_size() {
        let s = std::mem::size_of::<KrEvent>();
        // BPF emits 80 bytes; userspace must accept exactly the same
        // (mismatch would silently truncate ring-buffer events).
        assert_eq!(s, 80, "KrEvent size changed — BPF/Rust layouts diverged");
        assert_eq!(std::mem::align_of::<KrEvent>(), 8);
    }

    /// T-9.5 — Severity variants order matches the BPF KR_SEV_* defines.
    #[test]
    fn severity_numeric_values() {
        assert_eq!(Severity::Info     as u8, 0);
        assert_eq!(Severity::Warning  as u8, 1);
        assert_eq!(Severity::Alert    as u8, 2);
        assert_eq!(Severity::Critical as u8, 3);
        assert!(Severity::Critical > Severity::Alert);
        assert!(Severity::Alert    > Severity::Warning);
        assert!(Severity::Warning  > Severity::Info);
    }

    /// T-9.5 — DetectorId values match the BPF KR_DETECTOR_* defines (1..=8).
    #[test]
    fn detector_id_numeric_values() {
        assert_eq!(DetectorId::PrivEsc    as u8, 1);
        assert_eq!(DetectorId::BpfRootkit as u8, 2);
        assert_eq!(DetectorId::Container  as u8, 3);
        assert_eq!(DetectorId::KernelMod  as u8, 4);
        assert_eq!(DetectorId::Fim        as u8, 5);
        assert_eq!(DetectorId::Network    as u8, 6);
        assert_eq!(DetectorId::Injection  as u8, 7);
        assert_eq!(DetectorId::Cred       as u8, 8);
    }

    /// T-9.8 — fuzz: arbitrary bytes coming out of a BPF ring buffer must
    /// never panic the userspace parser. Mirrors the detector pattern of
    /// `read_unaligned` after a length check.
    #[test]
    fn ringbuf_parse_never_panics_on_arbitrary_bytes() {
        let mut state: u64 = 0x1234_5678_9ABC_DEF0;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };

        // Exercise: buffers that are too short, exactly right, and too long.
        for iteration in 0..2000_u32 {
            // Vary length around size_of::<KrEvent>() and beyond.
            let len = (iteration as usize % 200).max(1);
            let mut buf = vec![0u8; len];
            for chunk in buf.chunks_mut(8) {
                let n = next();
                let bytes = n.to_le_bytes();
                let take = chunk.len();
                chunk.copy_from_slice(&bytes[..take]);
            }

            // Detector's exact pattern: length-gate, then unaligned read.
            if buf.len() < std::mem::size_of::<KrEvent>() {
                continue;
            }
            let ev: KrEvent = unsafe {
                std::ptr::read_unaligned(buf.as_ptr() as *const KrEvent)
            };

            // Downstream operations on arbitrary content must not panic.
            // - Severity match arms (numeric compare, no panic possible)
            // - serde_json round-trip (must succeed on any KrEvent)
            let json = serde_json::to_string(&ev).expect("KrEvent must serialize");
            let _back: KrEvent = serde_json::from_str(&json)
                .expect("KrEvent must round-trip through serde_json");
        }
    }
}
