// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Ferith Tools
//
// Part of the kernelradar project - Linux kernel anomaly detection via BPF.
// See LICENSE for terms.

use chrono::Utc;
use kernelradar_core::{
    alert::Alert,
    event::{KrEvent, Severity},
};
/// Shared utilities for all detectors.
use std::sync::atomic::{AtomicU64, Ordering};
use uuid::Uuid;

use crate::baseline::record_and_score as baseline_score;
use crate::dedup::{check as rate_check, Decision};
use crate::metrics::{record_alert, record_anomaly, record_burst, record_suppressed};
use crate::output::{alert_to_falco_json, global_output_format, OutputFormat};
use crate::webhook::submit as webhook_submit;

static ALERT_ID: AtomicU64 = AtomicU64::new(1);

/// Return the daemon's host (init-namespace) tgid. `std::process::id()`
/// returns the namespace-local pid, which is often `1` inside a
/// container - BPF events carry the host tgid (read off `task_struct`),
/// so the two would never match and any "is this event from us?"
/// filter that compared them would silently fail.
///
/// `/proc/self/status` carries an `NSpid:` line listing the pid in
/// every namespace, leftmost first (host) and rightmost last
/// (innermost namespace). When unsupported (kernels < 4.1) the field
/// is absent and we fall back to `std::process::id()` with a warning.
pub(crate) fn host_tgid() -> u32 {
    let status = match std::fs::read_to_string("/proc/self/status") {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e,
                "host_tgid: cannot read /proc/self/status, using std::process::id()");
            return std::process::id();
        }
    };
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("NSpid:") {
            // Tab-separated list of numeric pids, leftmost is host.
            if let Some(first) = rest.split_whitespace().next() {
                if let Ok(n) = first.parse::<u32>() {
                    let local = std::process::id();
                    if n != local {
                        tracing::warn!(
                            host_tgid = n,
                            local_pid = local,
                            "host_tgid: daemon is in a non-root pid namespace; \
                             using host tgid for self-event filtering"
                        );
                    }
                    return n;
                }
            }
        }
    }
    tracing::warn!(
        "host_tgid: /proc/self/status has no NSpid: field, \
         falling back to std::process::id() - self-event filtering may \
         be a no-op if the daemon is pid-namespaced"
    );
    std::process::id()
}

/// Read the executable path of a process from /proc/<pid>/exe.
///
/// Plain version, no consistency check. Prefer
/// [`read_exe_path_verified`] from event-handling hot paths so that a
/// re-used PID or a post-event execve doesn't smuggle a wrong exe
/// path into the alert.
pub fn read_exe_path(pid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{}/exe", pid))
        .ok()
        .map(|p| p.to_string_lossy().to_string())
}

/// Read /proc/<pid>/exe, but only if the current `comm` of that PID
/// still matches the `comm` captured by BPF at event time. Returns
/// None if the comm differs - that's the signal that the PID was
/// reused or the process execve'd into something else between the
/// event and userspace catch-up (TOCTOU mitigation).
///
/// Note: TASK_COMM_LEN is 16, so a target comm sharing the first
/// 15 bytes with the original can still slip through. This narrows
/// the window dramatically without claiming to close it.
pub fn read_exe_path_verified(pid: u32, ev_comm: &str) -> Option<String> {
    let now_comm = std::fs::read_to_string(format!("/proc/{}/comm", pid)).ok()?;
    let now_comm = now_comm.trim_end_matches('\n');
    if now_comm != ev_comm {
        return None;
    }
    std::fs::read_link(format!("/proc/{}/exe", pid))
        .ok()
        .map(|p| p.to_string_lossy().to_string())
}

// `is_allowed` was moved to `crate::allowlist::CompiledAllowlist::is_allowed`
// where the regex set is pre-compiled at allowlist build / hot-reload
// time instead of per event. Detectors call `al.is_allowed(comm, exe)`
// directly on the snapshot returned by `SharedAllowlist::snapshot()`.

/// Build an Alert from a BPF event. `detector` is a string literal kept
/// as `&'static str` to avoid per-event allocation through the alert
/// pipeline.
pub fn make_alert(
    ev: &KrEvent,
    exe: Option<&str>,
    detector: &'static str,
    title: &str,
    context: serde_json::Value,
) -> Alert {
    let comm = comm_str(ev);
    let sev = match ev.severity {
        s if s >= Severity::Critical as u8 => Severity::Critical,
        s if s >= Severity::Alert as u8 => Severity::Alert,
        s if s >= Severity::Warning as u8 => Severity::Warning,
        _ => Severity::Info,
    };

    Alert {
        id: ALERT_ID.fetch_add(1, Ordering::Relaxed),
        // Random v4 (not v7) so the correlation_id does not embed a
        // millisecond unix timestamp - that would leak host start time
        // and alert cadence to anyone reading the journald stream or
        // the Prometheus exporter.
        correlation_id: Uuid::new_v4(),
        timestamp: Utc::now(),
        severity: sev,
        detector: std::borrow::Cow::Borrowed(detector),
        event_type: ev.event_type,
        title: title.to_string(),
        description: exe.map(|e| format!("exe={e}")).unwrap_or_default(),
        pid: ev.pid,
        uid: ev.uid,
        comm,
        context,
    }
}

/// Emit an alert through the configured output channel.
///
/// Per-process global format (set once at startup):
///   Plain    - stdout, human-readable
///   Json     - stdout, one JSON object per line
///   Journald - tracing event with structured fields,
///              consumed by tracing-journald layer
pub fn print_alert(alert: &Alert, _legacy_json: bool) {
    // Update baseline + score regardless of rate limit decision.
    // Suppressed events still feed the model - that IS the model.
    let z = baseline_score(&alert.detector, &alert.comm);

    // Rate limit / burst / backoff. `alert.detector.clone()` is a
    // pointer copy in the common Cow::Borrowed case - no allocation.
    let decision = rate_check(
        alert.detector.clone(),
        &alert.comm,
        alert.event_type,
        alert.severity,
    );

    match decision {
        Decision::Suppress => {
            record_suppressed(alert.detector.clone(), alert.severity);
            // Anomaly side-channel: even rate-limited events that are
            // statistically anomalous deserve a one-off ANOMALY alert.
            if let Some(score) = z {
                emit_anomaly_marker(alert, score);
                record_anomaly(alert.detector.clone());
            }
        }
        Decision::Allow => {
            record_alert(alert.detector.clone(), alert.severity);
            emit(alert);
            if let Some(score) = z {
                emit_anomaly_marker(alert, score);
                record_anomaly(alert.detector.clone());
            }
        }
        Decision::Burst => {
            record_alert(alert.detector.clone(), alert.severity);
            record_burst(alert.detector.clone());
            emit(alert);
            emit_burst_marker(alert);
            if let Some(score) = z {
                emit_anomaly_marker(alert, score);
                record_anomaly(alert.detector.clone());
            }
        }
    }
}

fn emit(alert: &Alert) {
    // Always submit to webhook (no-op if disabled)
    webhook_submit(alert);

    match global_output_format() {
        OutputFormat::Plain => emit_plain(alert),
        OutputFormat::Json => emit_json(alert),
        OutputFormat::Journald => emit_journald(alert),
        OutputFormat::Falco => emit_falco(alert),
    }
}

fn emit_falco(alert: &Alert) {
    println!("{}", alert_to_falco_json(alert));
}

/// Emit a synthetic ANOMALY alert when baseline scores high z-score.
fn emit_anomaly_marker(orig: &Alert, z: f64) {
    let anomaly = Alert {
        id: orig.id,
        correlation_id: orig.correlation_id,
        timestamp: Utc::now(),
        severity: kernelradar_core::event::Severity::Alert,
        detector: std::borrow::Cow::Owned(format!("{}.anomaly", orig.detector)),
        event_type: orig.event_type,
        title: format!(
            "ANOMALY: {} {} by {} - z={:.1}σ",
            orig.detector, orig.event_type, orig.comm, z
        ),
        description: "rate diverges from learned baseline".to_string(),
        pid: orig.pid,
        uid: orig.uid,
        comm: orig.comm.clone(),
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
        id: orig.id, // marked as same ID for grouping
        correlation_id: orig.correlation_id,
        timestamp: Utc::now(),
        severity: kernelradar_core::event::Severity::Critical,
        detector: std::borrow::Cow::Owned(format!("{}.burst", orig.detector)),
        event_type: orig.event_type,
        title: format!(
            "BURST: {} {} fired ≥ threshold per second by {}",
            orig.detector, orig.event_type, orig.comm
        ),
        description: "rate-limit burst threshold exceeded".to_string(),
        pid: orig.pid,
        uid: orig.uid,
        comm: orig.comm.clone(),
        context: serde_json::json!({
            "burst": true,
            "of_alert_id": orig.id,
            "of_correlation_id": orig.correlation_id.to_string(),
        }),
    };
    emit(&burst);
}

fn emit_plain(alert: &Alert) {
    // Sanitise every attacker-controllable field before printing to a
    // tty. `comm` is set by the source process via prctl(PR_SET_NAME)
    // and can contain ESC, CR, NL, VT etc; `title` carries that
    // `comm` plus user-supplied paths (FIM/cred event_type=2) that
    // bypass the rule table. An admin tailing the log in a real
    // terminal would otherwise see the attacker's ANSI escape
    // sequence (`\x1b[2J\x1b[H` clears the screen, `\x1b]0;...\x07`
    // rewrites the title bar) and `\n`-injected fake log lines that
    // appear to come from kernelradar itself. JSON / journald /
    // Falco modes escape automatically; only the plain-text tty
    // path needs this.
    println!(
        "[{}] {} | {} | pid={} uid={} comm={} | {} | cid={}",
        alert.severity,
        alert.timestamp.format("%Y-%m-%dT%H:%M:%S%.3fZ"),
        alert.detector,
        alert.pid,
        alert.uid,
        sanitize_for_tty(&alert.comm),
        sanitize_for_tty(&alert.title),
        alert.correlation_id,
    );
    if !alert.description.is_empty() {
        println!("          └ {}", sanitize_for_tty(&alert.description));
    }
    if alert.context != serde_json::Value::Null {
        // `to_string()` on a serde_json::Value produces a JSON string
        // literal where control chars are already escaped as \uXXXX.
        // Print as-is.
        println!("          └ {}", alert.context);
    }
}

/// Replace control characters and Unicode bidi/format/line-separator
/// codepoints with their `\u{XXXX}` representation so the result is
/// safe to splat into a terminal. Avoids ANSI escape sequence
/// smuggling AND Unicode visual-spoofing tricks (RIGHT-TO-LEFT
/// OVERRIDE U+202E to make `/etc/wodahs` look like `/etc/shadow`,
/// LINE SEPARATOR U+2028 to fake a new log line in some terminals,
/// zero-width joiners that hide content) via `comm` / path / title
/// fields.
fn sanitize_for_tty(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if ch == ' ' || is_safe_for_tty(ch) {
            out.push(ch);
        } else {
            let n = ch as u32;
            if n <= 0xff {
                out.push_str(&format!("\\x{n:02x}"));
            } else {
                out.push_str(&format!("\\u{{{n:04x}}}"));
            }
        }
    }
    out
}

/// Whitelist for tty output. Rejects `char::is_control()` (Cc) and
/// Unicode codepoints that have no visible width but DO change how
/// the terminal renders the surrounding text:
///
/// - U+200B..U+200F  (zero-width space / non-joiner / joiner / LRM / RLM)
/// - U+202A..U+202E  (LRE / RLE / PDF / LRO / RLO - bidi overrides)
/// - U+2060..U+2064  (word joiner / invisible separators)
/// - U+2066..U+2069  (LRI / RLI / FSI / PDI - bidi isolates)
/// - U+2028..U+2029  (LINE SEPARATOR / PARAGRAPH SEPARATOR - Zl/Zp)
/// - U+FEFF          (zero-width no-break space / BOM)
/// - U+FFF9..U+FFFB  (interlinear annotation markers)
fn is_safe_for_tty(ch: char) -> bool {
    if ch.is_control() {
        return false;
    }
    let n = ch as u32;
    !matches!(
        n,
        0x200B..=0x200F  // zero-width + LRM/RLM
            | 0x202A..=0x202E  // bidi overrides
            | 0x2028..=0x2029  // line/paragraph separators
            | 0x2060..=0x2064  // word joiner + invisible separators
            | 0x2066..=0x2069  // bidi isolates
            | 0xFEFF           // BOM / ZWNBSP
            | 0xFFF9..=0xFFFB  // interlinear annotation
    )
}

#[cfg(test)]
mod sanitize_tty_tests {
    use super::sanitize_for_tty as s;

    #[test]
    fn passes_normal_text() {
        assert_eq!(s("hello world"), "hello world");
        assert_eq!(s("/etc/shadow"), "/etc/shadow");
    }

    #[test]
    fn escapes_ansi_clear_screen() {
        // \x1b[2J\x1b[H = clear-screen + home cursor
        assert_eq!(s("\x1b[2J\x1b[H"), "\\x1b[2J\\x1b[H");
    }

    #[test]
    fn escapes_newline_and_carriage_return() {
        assert_eq!(s("foo\nbar\rbaz"), "foo\\x0abar\\x0dbaz");
    }

    #[test]
    fn escapes_terminal_title_setter() {
        // OSC 0 ; <title> BEL - rewrites terminal title in xterm/iTerm2
        assert_eq!(s("\x1b]0;FAKE\x07"), "\\x1b]0;FAKE\\x07");
    }

    #[test]
    fn escapes_ansi_color_codes() {
        // \x1b[31mRED\x1b[0m
        assert_eq!(s("\x1b[31mRED\x1b[0m"), "\\x1b[31mRED\\x1b[0m");
    }

    #[test]
    fn keeps_unicode() {
        assert_eq!(s("привет"), "привет");
        assert_eq!(s("résumé"), "résumé");
    }

    #[test]
    fn escapes_bidi_overrides() {
        // U+202E RIGHT-TO-LEFT OVERRIDE - visual spoof tool
        assert_eq!(s("a\u{202E}b"), "a\\u{202e}b");
        // U+202A LEFT-TO-RIGHT EMBEDDING
        assert_eq!(s("\u{202A}x\u{202C}"), "\\u{202a}x\\u{202c}");
    }

    #[test]
    fn escapes_zero_width() {
        // U+200B ZERO-WIDTH SPACE
        assert_eq!(s("foo\u{200B}bar"), "foo\\u{200b}bar");
        // U+FEFF BOM as zero-width no-break space
        assert_eq!(s("\u{FEFF}foo"), "\\u{feff}foo");
    }

    #[test]
    fn escapes_line_separator() {
        // U+2028 LINE SEPARATOR can fake a new log line
        assert_eq!(s("foo\u{2028}bar"), "foo\\u{2028}bar");
        // U+2029 PARAGRAPH SEPARATOR
        assert_eq!(s("foo\u{2029}bar"), "foo\\u{2029}bar");
    }

    #[test]
    fn escapes_bidi_isolates() {
        // U+2066 LEFT-TO-RIGHT ISOLATE
        assert_eq!(s("\u{2066}fake\u{2069}"), "\\u{2066}fake\\u{2069}");
    }

    #[test]
    fn keeps_legitimate_unicode_letters() {
        // Make sure ordinary RTL scripts (Hebrew, Arabic) pass through.
        assert_eq!(s("שלום"), "שלום");
        assert_eq!(s("مرحبا"), "مرحبا");
    }
}

fn emit_json(alert: &Alert) {
    if let Ok(s) = serde_json::to_string(alert) {
        println!("{s}");
    }
}

fn emit_journald(alert: &Alert) {
    // tracing event - tracing-journald translates structured fields
    // into journald custom fields (DETECTOR=, PID=, etc.) and the
    // message string is the human-readable headline.
    let level = match alert.severity {
        Severity::Critical => tracing::Level::ERROR,
        Severity::Alert => tracing::Level::WARN,
        Severity::Warning => tracing::Level::WARN,
        Severity::Info => tracing::Level::INFO,
    };

    let comm = alert.comm.as_str();
    let detector: &str = &alert.detector;
    let title = alert.title.as_str();
    let description = alert.description.as_str();
    let severity = format!("{}", alert.severity);
    let cid = alert.correlation_id.to_string();
    let context = alert.context.to_string();

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
    String::from_utf8_lossy(ev.comm.split(|&b| b == 0).next().unwrap_or(&[])).to_string()
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
            timestamp_ns: 0,
            pid: 0,
            tid: 0,
            uid: 0,
            gid: 0,
            comm,
            detector_id: 0,
            severity: 0,
            event_type: 0,
            data: [0; 4],
        }
    }

    /// comm_str trims at first NUL byte.
    #[test]
    fn comm_str_trims_at_nul() {
        assert_eq!(comm_str(&ev_with_comm(b"sshd\0\0\0")), "sshd");
        assert_eq!(comm_str(&ev_with_comm(b"sudo\0extra")), "sudo");
        assert_eq!(comm_str(&ev_with_comm(b"\0")), "");
    }

    /// comm_str without NUL uses full 16 bytes.
    #[test]
    fn comm_str_no_nul_uses_full_buffer() {
        let buf = [b'A'; 16];
        let ev = ev_with_comm(&buf);
        assert_eq!(comm_str(&ev), "AAAAAAAAAAAAAAAA");
    }

    /// Invalid UTF-8 is replaced lossily, no panic.
    #[test]
    fn comm_str_lossy_on_invalid_utf8() {
        let bytes = [0xFFu8, 0xFE, b'a', 0];
        let ev = ev_with_comm(&bytes);
        let s = comm_str(&ev);
        assert!(s.contains('a'));
        assert!(!s.contains('\0'));
    }

    /// Fuzz: arbitrary 16-byte comm content must never panic.
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
}
