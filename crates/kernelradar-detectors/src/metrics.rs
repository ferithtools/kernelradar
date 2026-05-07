// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Ferith Tools
//
// Part of the kernelradar project — Linux kernel anomaly detection via BPF.
// See LICENSE for terms.

//! Alert counters and hourly summary.
//!
//! Detector names enter the counters as `&'static str` (always string
//! literals from the detector crate), so accumulating one event into the
//! BTreeMap is just a key copy — no `to_string()` allocation per alert.
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::time::Duration;

use kernelradar_core::event::Severity;

use crate::dedup::drain_suppressed;

#[derive(Default)]
struct Counters {
    /// (detector, severity) → count since last summary
    bucket_emitted: BTreeMap<(&'static str, Severity), u64>,
    /// (detector, severity) → cumulative since process start
    total_emitted: BTreeMap<(&'static str, Severity), u64>,
    /// (detector, severity) → suppressed since last summary
    bucket_suppressed: BTreeMap<(&'static str, Severity), u64>,
    /// (detector) → burst count cumulative
    total_bursts: BTreeMap<&'static str, u64>,
    /// (detector) → anomaly count cumulative
    total_anomalies: BTreeMap<&'static str, u64>,
}

static COUNTERS: OnceLock<Mutex<Counters>> = OnceLock::new();

fn counters() -> &'static Mutex<Counters> {
    COUNTERS.get_or_init(|| Mutex::new(Counters::default()))
}

pub fn record_alert(detector: &'static str, severity: Severity) {
    if let Ok(mut c) = counters().lock() {
        *c.bucket_emitted.entry((detector, severity)).or_insert(0) += 1;
        *c.total_emitted.entry((detector, severity)).or_insert(0) += 1;
    }
}

pub fn record_suppressed(detector: &'static str, severity: Severity) {
    if let Ok(mut c) = counters().lock() {
        *c.bucket_suppressed.entry((detector, severity)).or_insert(0) += 1;
    }
}

pub fn record_burst(detector: &'static str) {
    if let Ok(mut c) = counters().lock() {
        *c.total_bursts.entry(detector).or_insert(0) += 1;
    }
}

pub fn record_anomaly(detector: &'static str) {
    if let Ok(mut c) = counters().lock() {
        *c.total_anomalies.entry(detector).or_insert(0) += 1;
    }
}

pub fn spawn_hourly_summary() {
    tokio::spawn(async {
        let mut interval = tokio::time::interval(Duration::from_secs(3600));
        // Skip the immediate first tick — wait one hour before first report
        interval.tick().await;
        loop {
            interval.tick().await;
            emit_summary();
        }
    });
}

fn emit_summary() {
    // Drain emitted bucket. Poisoned mutex → recover instead of panic.
    let (emitted, suppressed_internal) = {
        let mut c = counters().lock().unwrap_or_else(|e| e.into_inner());
        let emitted = std::mem::take(&mut c.bucket_emitted);
        let supp_int = std::mem::take(&mut c.bucket_suppressed);
        (emitted, supp_int)
    };

    // Pull rate-limiter suppressed counts (cleared on read)
    let supp_external = drain_suppressed();

    let total_emitted: u64 = emitted.values().sum();
    let total_suppressed_int: u64 = suppressed_internal.values().sum();
    let total_suppressed_ext: u64 = supp_external.iter().map(|(_, n, _)| *n).sum();

    if total_emitted == 0 && total_suppressed_int == 0 && total_suppressed_ext == 0 {
        tracing::info!(
            target: "kernelradar.summary",
            window_hours = 1u32,
            emitted = 0u64, suppressed = 0u64,
            "no alerts in the last hour"
        );
        return;
    }

    let breakdown: Vec<String> = emitted
        .iter()
        .map(|((det, sev), n)| format!("{det}/{sev}={n}"))
        .collect();

    let supp_breakdown: Vec<String> = supp_external
        .iter()
        .map(|((det, comm, et), n, sev)| format!("{det}/{comm}/{et}/{sev}={n}"))
        .collect();

    tracing::info!(
        target: "kernelradar.summary",
        window_hours = 1u32,
        emitted = total_emitted,
        suppressed = total_suppressed_ext,
        emitted_breakdown    = %breakdown.join(" "),
        suppressed_breakdown = %supp_breakdown.join(" "),
        "hourly summary: emitted={} suppressed={} ({})",
        total_emitted,
        total_suppressed_ext,
        breakdown.join(" "),
    );
}

/// Cumulative totals + bursts for `kernelradar status`.
pub fn cumulative_totals() -> BTreeMap<(&'static str, Severity), u64> {
    counters()
        .lock()
        .map(|c| c.total_emitted.clone())
        .unwrap_or_default()
}

pub fn cumulative_bursts() -> BTreeMap<&'static str, u64> {
    counters()
        .lock()
        .map(|c| c.total_bursts.clone())
        .unwrap_or_default()
}

pub fn cumulative_anomalies() -> BTreeMap<&'static str, u64> {
    counters()
        .lock()
        .map(|c| c.total_anomalies.clone())
        .unwrap_or_default()
}
