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
use crate::output::{global_output_format, OutputFormat};
use crate::metrics::{record_alert, record_anomaly, record_burst, record_suppressed};

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
    match global_output_format() {
        OutputFormat::Plain    => emit_plain(alert),
        OutputFormat::Json     => emit_json(alert),
        OutputFormat::Journald => emit_journald(alert),
    }
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
