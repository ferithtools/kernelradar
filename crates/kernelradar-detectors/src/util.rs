// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Ferith Tools
//
// Part of the kernelradar project — Linux kernel anomaly detection via BPF.
// See LICENSE for terms.

/// Shared utilities for all detectors.

use std::sync::atomic::{AtomicU64, Ordering};
use chrono::Utc;
use uuid::Uuid;
use kernelradar_core::{
    alert::Alert,
    event::{KrEvent, Severity},
};

use crate::baseline::record_and_score as baseline_score;
use crate::dedup::{check as rate_check, Decision};
use crate::output::{alert_to_falco_json, global_output_format, OutputFormat};
use crate::metrics::{record_alert, record_anomaly, record_burst, record_suppressed};
use crate::webhook::submit as webhook_submit;

static ALERT_ID: AtomicU64 = AtomicU64::new(1);

/// Read the executable path of a process from /proc/<pid>/exe.
/// Returns None if the process has already exited (race is fine).
pub fn read_exe_path(pid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{}/exe", pid))
        .ok()
        .map(|p| p.to_string_lossy().to_string())
}

/// Check whether a process is in the allowlist.
///
/// Each allowlist entry is matched in this order:
///   • `/regex/` — Rust regex against comm and basename(exe)
///   • exact comm or comm prefix
///   • exact exe path or basename(exe)
pub fn is_allowed(comm: &str, exe: Option<&str>, allowlist: &[String]) -> bool {
    let exe_basename = exe.and_then(|p| p.rsplit('/').next());

    for entry in allowlist {
        // Regex: /pattern/
        if let Some(pat) = entry.strip_prefix('/').and_then(|s| s.strip_suffix('/')) {
            // Compile once per call. Bad regex is silently ignored
            // (validate at config load time via Config::validate).
            if let Ok(re) = regex::Regex::new(pat) {
                if re.is_match(comm) { return true; }
                if let Some(b) = exe_basename {
                    if re.is_match(b) { return true; }
                }
                if let Some(p) = exe {
                    if re.is_match(p) { return true; }
                }
            }
            continue;
        }

        if entry == comm                       { return true; }
        if comm.starts_with(entry.as_str())    { return true; }
        if let Some(p) = exe {
            if p == entry.as_str()              { return true; }
            if exe_basename == Some(entry.as_str()) { return true; }
        }
    }
    false
}

/// Build an Alert from a BPF event.
pub fn make_alert(
    ev:       &KrEvent,
    exe:      Option<&str>,
    detector: &str,
    title:    &str,
    context:  serde_json::Value,
) -> Alert {
    let comm = comm_str(ev);
    let sev = match ev.severity {
        s if s >= Severity::Critical as u8 => Severity::Critical,
        s if s >= Severity::Alert    as u8 => Severity::Alert,
        s if s >= Severity::Warning  as u8 => Severity::Warning,
        _                                   => Severity::Info,
    };

    Alert {
        id:             ALERT_ID.fetch_add(1, Ordering::Relaxed),
        correlation_id: Uuid::now_v7(),
        timestamp:      Utc::now(),
        severity:       sev,
        detector:       detector.to_string(),
        event_type:     ev.event_type,
        title:          title.to_string(),
        description:    exe.map(|e| format!("exe={e}")).unwrap_or_default(),
        pid:            ev.pid,
        uid:            ev.uid,
        comm,
        context,
    }
}

/// Emit an alert through the configured output channel.
///
/// Per-process global format (set once at startup):
///   Plain    — stdout, human-readable
///   Json     — stdout, one JSON object per line
///   Journald — tracing event with structured fields,
///              consumed by tracing-journald layer
pub fn print_alert(alert: &Alert, _legacy_json: bool) {
    // T-4: Update baseline + score regardless of rate limit decision.
    // Suppressed events still feed the model — that IS the model.
    let z = baseline_score(&alert.detector, &alert.comm);

    // T-3: rate limit / burst / backoff
    let decision = rate_check(
        &alert.detector,
        &alert.comm,
        alert.event_type,
        alert.severity,
    );

    match decision {
        Decision::Suppress => {
            record_suppressed(&alert.detector, alert.severity);
            // Anomaly side-channel: even rate-limited events that are
            // statistically anomalous deserve a one-off ANOMALY alert.
            if let Some(score) = z {
                emit_anomaly_marker(alert, score);
                record_anomaly(&alert.detector);
            }
            return;
        }
        Decision::Allow => {
            record_alert(&alert.detector, alert.severity);
            emit(alert);
            if let Some(score) = z {
                emit_anomaly_marker(alert, score);
                record_anomaly(&alert.detector);
            }
        }
        Decision::Burst => {
            record_alert(&alert.detector, alert.severity);
            record_burst(&alert.detector);
            emit(alert);
            emit_burst_marker(alert);
            if let Some(score) = z {
                emit_anomaly_marker(alert, score);
                record_anomaly(&alert.detector);
            }
        }
    }
}

fn emit(alert: &Alert) {
    // Always submit to webhook (no-op if disabled)
    webhook_submit(alert);

    match global_output_format() {
        OutputFormat::Plain    => emit_plain(alert),
        OutputFormat::Json     => emit_json(alert),
        OutputFormat::Journald => emit_journald(alert),
        OutputFormat::Falco    => emit_falco(alert),
    }
}

fn emit_falco(alert: &Alert) {
    println!("{}", alert_to_falco_json(alert));
}

/// Emit a synthetic ANOMALY alert when baseline scores high z-score.
fn emit_anomaly_marker(orig: &Alert, z: f64) {
    let anomaly = Alert {
        id:             orig.id,
        correlation_id: orig.correlation_id,
        timestamp:      Utc::now(),
        severity:       kernelradar_core::event::Severity::Alert,
        detector:       format!("{}.anomaly", orig.detector),
        event_type:     orig.event_type,
        title:          format!("ANOMALY: {} {} by {} — z={:.1}σ",
                                orig.detector, orig.event_type, orig.comm, z),
        description:    "rate diverges from learned baseline".to_string(),
        pid:            orig.pid,
        uid:            orig.uid,
        comm:           orig.comm.clone(),
        context: serde_json::json!({
            "anomaly":          true,
            "z_score":          z,
            "of_alert_id":      orig.id,
            "of_correlation_id": orig.correlation_id.to_string(),
        }),
    };
    emit(&anomaly);
}

/// Emit a synthetic BURST alert that follows the original alert.
fn emit_burst_marker(orig: &Alert) {
    let burst = Alert {
        id:             orig.id, // marked as same ID for grouping
        correlation_id: orig.correlation_id,
        timestamp:      Utc::now(),
        severity:       kernelradar_core::event::Severity::Critical,
        detector:       format!("{}.burst", orig.detector),
        event_type:     orig.event_type,
        title:          format!("BURST: {} {} fired ≥ threshold per second by {}",
                                orig.detector, orig.event_type, orig.comm),
        description:    "rate-limit burst threshold exceeded".to_string(),
        pid:            orig.pid,
        uid:            orig.uid,
        comm:           orig.comm.clone(),
        context: serde_json::json!({
            "burst": true,
            "of_alert_id": orig.id,
            "of_correlation_id": orig.correlation_id.to_string(),
        }),
    };
    emit(&burst);
}

fn emit_plain(alert: &Alert) {
    println!("{alert}");
    if !alert.description.is_empty() {
        println!("          └ {}", alert.description);
    }
    if alert.context != serde_json::Value::Null {
        println!("          └ {}", alert.context);
    }
}

fn emit_json(alert: &Alert) {
    if let Ok(s) = serde_json::to_string(alert) {
        println!("{s}");
    }
}

fn emit_journald(alert: &Alert) {
    // tracing event — tracing-journald translates structured fields
    // into journald custom fields (DETECTOR=, PID=, etc.) and the
    // message string is the human-readable headline.
    let level = match alert.severity {
        Severity::Critical => tracing::Level::ERROR,
        Severity::Alert    => tracing::Level::WARN,
        Severity::Warning  => tracing::Level::WARN,
        Severity::Info     => tracing::Level::INFO,
    };

    let comm        = alert.comm.as_str();
    let detector    = alert.detector.as_str();
    let title       = alert.title.as_str();
    let description = alert.description.as_str();
    let severity    = format!("{}", alert.severity);
    let cid         = alert.correlation_id.to_string();
    let context     = alert.context.to_string();

    match level {
        tracing::Level::ERROR => tracing::error!(
            target: "kernelradar.alert",
            detector, severity = %severity, pid = alert.pid, uid = alert.uid,
            comm, correlation_id = %cid, context = %context, description,
            "{title}"
        ),
        tracing::Level::WARN => tracing::warn!(
            target: "kernelradar.alert",
            detector, severity = %severity, pid = alert.pid, uid = alert.uid,
            comm, correlation_id = %cid, context = %context, description,
            "{title}"
        ),
        _ => tracing::info!(
            target: "kernelradar.alert",
            detector, severity = %severity, pid = alert.pid, uid = alert.uid,
            comm, correlation_id = %cid, context = %context, description,
            "{title}"
        ),
    }
}

/// Extract null-terminated comm string from BPF event.
pub fn comm_str(ev: &KrEvent) -> String {
    String::from_utf8_lossy(
        ev.comm.split(|&b| b == 0).next().unwrap_or(&[])
    ).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernelradar_core::event::KrEvent;

    fn ev_with_comm(bytes: &[u8]) -> KrEvent {
        let mut comm = [0u8; 16];
        let n = bytes.len().min(16);
        comm[..n].copy_from_slice(&bytes[..n]);
        KrEvent {
            timestamp_ns: 0, pid: 0, tid: 0, uid: 0, gid: 0,
            comm, detector_id: 0, severity: 0, event_type: 0,
            data: [0; 4],
        }
    }

    /// T-9.5 — comm_str trims at first NUL byte.
    #[test]
    fn comm_str_trims_at_nul() {
        assert_eq!(comm_str(&ev_with_comm(b"sshd\0\0\0")), "sshd");
        assert_eq!(comm_str(&ev_with_comm(b"sudo\0extra")), "sudo");
        assert_eq!(comm_str(&ev_with_comm(b"\0")), "");
    }

    /// T-9.5 — comm_str without NUL uses full 16 bytes.
    #[test]
    fn comm_str_no_nul_uses_full_buffer() {
        let buf = [b'A'; 16];
        let ev = ev_with_comm(&buf);
        assert_eq!(comm_str(&ev), "AAAAAAAAAAAAAAAA");
    }

    /// T-9.5 — invalid UTF-8 is replaced lossily, no panic.
    #[test]
    fn comm_str_lossy_on_invalid_utf8() {
        let bytes = [0xFFu8, 0xFE, b'a', 0];
        let ev = ev_with_comm(&bytes);
        let s = comm_str(&ev);
        assert!(s.contains('a'));
        assert!(!s.contains('\0'));
    }

    /// T-9.8 — fuzz: arbitrary 16-byte comm content must never panic.
    #[test]
    fn comm_str_fuzz_never_panics() {
        let mut state: u64 = 0xCAFE_BABE_DEAD_BEEF;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..1000 {
            let mut comm = [0u8; 16];
            for b in &mut comm {
                *b = next() as u8;
            }
            let mut ev = ev_with_comm(&[]);
            ev.comm = comm;
            let s = comm_str(&ev);
            assert!(!s.contains('\0'));
        }
    }

    // ── is_allowed ───────────────────────────────────────────────────

    #[test]
    fn is_allowed_empty_list_rejects_all() {
        assert!(!is_allowed("anything", None, &[]));
        assert!(!is_allowed("anything", Some("/usr/bin/anything"), &[]));
    }

    #[test]
    fn is_allowed_exact_comm() {
        let al = vec!["sshd".to_string()];
        assert!(is_allowed("sshd", None, &al));
        assert!(is_allowed("sshd-session", None, &al));
        assert!(!is_allowed("ssh", None, &al));
    }

    #[test]
    fn is_allowed_comm_prefix() {
        let al = vec!["python".to_string()];
        assert!(is_allowed("python3", None, &al));
        assert!(is_allowed("python3.11", None, &al));
        assert!(!is_allowed("py", None, &al));
    }

    #[test]
    fn is_allowed_exact_exe_path() {
        let al = vec!["/usr/bin/sudo".to_string()];
        assert!(is_allowed("foo", Some("/usr/bin/sudo"), &al));
        assert!(!is_allowed("foo", Some("/usr/local/sudo"), &al));
    }

    #[test]
    fn is_allowed_exe_basename() {
        let al = vec!["sudo".to_string()];
        assert!(is_allowed("ssh-agent", Some("/usr/bin/sudo"), &al));
    }

    #[test]
    fn is_allowed_regex_on_comm() {
        let al = vec!["/^kworker/".to_string()];
        assert!(is_allowed("kworker/0:1", None, &al));
        assert!(is_allowed("kworker/u8:0-events", None, &al));
        assert!(!is_allowed("worker", None, &al));
    }

    #[test]
    fn is_allowed_regex_on_exe_basename() {
        let al = vec!["/.*-agent$/".to_string()];
        assert!(is_allowed("foo", Some("/usr/bin/ssh-agent"), &al));
    }

    #[test]
    fn is_allowed_invalid_regex_does_not_panic() {
        let al = vec!["/[unclosed/".to_string(), "actual-comm".to_string()];
        assert!(is_allowed("actual-comm", None, &al));
        assert!(!is_allowed("random", None, &al));
    }

    #[test]
    fn is_allowed_mixed_entries() {
        let al = vec![
            "/^k/".to_string(),
            "sudo".to_string(),
            "/usr/bin/sshd".to_string(),
        ];
        assert!(is_allowed("kworker", None, &al));
        assert!(is_allowed("sudo", None, &al));
        assert!(is_allowed("any", Some("/usr/bin/sshd"), &al));
        assert!(!is_allowed("apache", Some("/usr/sbin/apache2"), &al));
    }
}
