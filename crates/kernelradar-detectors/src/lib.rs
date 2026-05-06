/// Detector 1 — Privilege escalation tracker
/// Watches credential transitions: who changed their uid/gid and how.
pub mod privesc;

/// Detector 2 — BPF program loader auditor
/// Alerts on BPF programs loaded by processes not in the allowlist.
pub mod bpf_loader;

// Detector 3 and 4 stubs (Phase 2)
// pub mod container;
// pub mod kmod;
