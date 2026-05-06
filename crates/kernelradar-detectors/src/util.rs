/// Shared utilities for all detectors.

use std::sync::atomic::{AtomicU64, Ordering};
use chrono::Utc;
use kernelradar_core::{
    alert::Alert,
    event::{KrEvent, Severity},
};

static ALERT_ID: AtomicU64 = AtomicU64::new(1);

/// Read the executable path of a process from /proc/<pid>/exe.
/// Returns None if the process has already exited (race is fine).
pub fn read_exe_path(pid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{}/exe", pid))
        .ok()
        .map(|p| p.to_string_lossy().to_string())
}

/// Check whether a process is in the allowlist.
/// Matches against comm (exact) or exe path (exact or suffix).
pub fn is_allowed(comm: &str, exe: Option<&str>, allowlist: &[String]) -> bool {
    for entry in allowlist {
        // exact comm match
        if entry == comm { return true; }
        // comm prefix — handles "runc:[1:CHILD]"
        if comm.starts_with(entry.as_str()) { return true; }
        // exe path match
        if let Some(exe_path) = exe {
            if exe_path == entry.as_str() { return true; }
            // basename match: "/usr/sbin/runc" matches "runc"
            if exe_path.rsplit('/').next() == Some(entry.as_str()) {
                return true;
            }
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
        id:          ALERT_ID.fetch_add(1, Ordering::Relaxed),
        timestamp:   Utc::now(),
        severity:    sev,
        detector:    detector.to_string(),
        title:       title.to_string(),
        description: exe.map(|e| format!("exe={e}"))
                        .unwrap_or_default(),
        pid:         ev.pid,
        uid:         ev.uid,
        comm,
        context,
    }
}

/// Print an alert — plain text or JSON depending on flag.
pub fn print_alert(alert: &Alert, json: bool) {
    if json {
        println!("{}", serde_json::to_string(alert).unwrap_or_default());
    } else {
        println!("{alert}");
        if !alert.description.is_empty() {
            println!("          └ {}", alert.description);
        }
        if alert.context != serde_json::Value::Null {
            println!("          └ {}", alert.context);
        }
    }
}

/// Extract null-terminated comm string from BPF event.
pub fn comm_str(ev: &KrEvent) -> String {
    String::from_utf8_lossy(
        ev.comm.split(|&b| b == 0).next().unwrap_or(&[])
    ).to_string()
}
