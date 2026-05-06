/// Alert counter metrics (T-1.7).
///
/// Maintains in-memory counters per (detector, severity) and emits an
/// hourly summary into the same logging channel. No external dependency
/// — pure std::sync.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::time::Duration;

use kernelradar_core::event::Severity;

#[derive(Default)]
struct Counters {
    /// (detector, severity) → count since last summary
    bucket: BTreeMap<(String, Severity), u64>,
    /// Cumulative since process start
    total:  BTreeMap<(String, Severity), u64>,
}

static COUNTERS: OnceLock<Mutex<Counters>> = OnceLock::new();

fn counters() -> &'static Mutex<Counters> {
    COUNTERS.get_or_init(|| Mutex::new(Counters::default()))
}

pub fn record_alert(detector: &str, severity: Severity) {
    if let Ok(mut c) = counters().lock() {
        let key = (detector.to_string(), severity);
        *c.bucket.entry(key.clone()).or_insert(0) += 1;
        *c.total .entry(key)        .or_insert(0) += 1;
    }
}

/// Spawn a background task that emits hourly summaries.
/// Call once at startup.
pub fn spawn_hourly_summary() {
    tokio::spawn(async {
        let mut interval = tokio::time::interval(Duration::from_secs(3600));
        // Skip first immediate tick — wait one hour before first report
        interval.tick().await;
        loop {
            interval.tick().await;
            emit_summary();
        }
    });
}

fn emit_summary() {
    let snapshot: BTreeMap<(String, Severity), u64> = {
        let mut c = counters().lock().unwrap();
        let snap = std::mem::take(&mut c.bucket);
        snap
    };

    if snapshot.is_empty() {
        tracing::info!(
            target: "kernelradar.summary",
            window_hours = 1u32,
            count = 0u32,
            "no alerts in the last hour"
        );
        return;
    }

    let total_in_window: u64 = snapshot.values().sum();
    let breakdown: Vec<String> = snapshot
        .iter()
        .map(|((det, sev), n)| format!("{det}/{sev}={n}"))
        .collect();

    tracing::info!(
        target: "kernelradar.summary",
        window_hours = 1u32,
        count = total_in_window,
        breakdown = %breakdown.join(" "),
        "hourly summary: {} alerts ({})",
        total_in_window,
        breakdown.join(" "),
    );
}

/// Get cumulative totals (for `kernelradar status` and future Prometheus).
pub fn cumulative_totals() -> BTreeMap<(String, Severity), u64> {
    counters().lock().map(|c| c.total.clone()).unwrap_or_default()
}
