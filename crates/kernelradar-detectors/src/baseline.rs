// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Ferith Tools
//
// Part of the kernelradar project — Linux kernel anomaly detection via BPF.
// See LICENSE for terms.

/// Adaptive baseline + sigma-based anomaly scoring (T-4).
///
/// For each (detector, comm) pair we keep 24 hour-of-day buckets. Each
/// bucket tracks an EWMA of events-per-minute (mean + mean of squares,
/// from which we derive an approximate stddev).
///
/// At minute boundaries we observe `count_in_minute` into the current
/// hour's bucket. On every event during the same minute we can ask
/// "is this rate anomalous?" by computing z = (observed − mean) / σ.
///
/// Persistence: serialised to JSON every save_interval and at shutdown.
/// Corrupted file → start fresh, log warning (T-4.8).
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use chrono::{DateTime, Timelike, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineConfig {
    /// How many seconds of warm-up before scoring kicks in.
    pub learning_secs: u64,
    /// Z-score threshold above which an anomaly is reported.
    pub score_threshold: f64,
    /// EWMA smoothing factor (0..1). Smaller = more inertia.
    pub alpha: f64,
    /// Where to persist the baseline.
    pub save_path: String,
    /// How often to flush to disk.
    pub save_interval_secs: u64,
    /// M-3: cap on the number of (detector, comm) pairs tracked. Once
    /// reached, pairs whose `last_seen` is older than `evict_age_hours`
    /// are dropped. Protects against unbounded HashMap growth from
    /// short-lived containers, fuzzing, or hostile flooding under
    /// many fake comms.
    pub pairs_max: usize,
    /// M-3: minimum staleness for eviction; younger pairs are kept
    /// even at cap (in which case nothing is evicted that pass).
    pub evict_age_hours: i64,
}

impl Default for BaselineConfig {
    fn default() -> Self {
        Self {
            learning_secs: 3600 * 24, // 24 hours warm-up
            score_threshold: 3.0,     // 3σ
            alpha: 0.10,
            save_path: "/var/lib/kernelradar/baseline.json".into(),
            save_interval_secs: 300, // every 5 minutes
            pairs_max: 10_000,
            evict_age_hours: 24 * 7, // 7 days
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct HourBucket {
    /// EWMA of count-per-minute
    sum: f64,
    /// EWMA of (count-per-minute)^2 — for variance approximation
    sumsq: f64,
    /// Number of minute observations recorded into this bucket
    samples: u64,
}

impl HourBucket {
    fn observe(&mut self, count_in_minute: u64, alpha: f64) {
        let c = count_in_minute as f64;
        self.sum = alpha * c + (1.0 - alpha) * self.sum;
        self.sumsq = alpha * c * c + (1.0 - alpha) * self.sumsq;
        self.samples = self.samples.saturating_add(1);
    }
    fn mean(&self) -> f64 {
        self.sum
    }
    fn var(&self) -> f64 {
        let v = self.sumsq - self.sum * self.sum;
        if v < 0.0 {
            0.0
        } else {
            v
        }
    }
    fn stddev(&self) -> f64 {
        // Floor of 0.5 so very-quiet buckets still produce sane z-scores.
        self.var().sqrt().max(0.5)
    }
    fn z_score(&self, observed: f64) -> f64 {
        (observed - self.mean()) / self.stddev()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PairStats {
    /// 24 hour-of-day buckets
    pub buckets: [HourBucket; 24],
    /// Total events ever recorded for this pair
    pub total: u64,
    /// First time we saw this pair
    pub first_seen: Option<DateTime<Utc>>,
    /// Last time we saw an event
    pub last_seen: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    pub version: u32,
    pub started: DateTime<Utc>,
    pub config: BaselineConfig,

    /// (detector, comm) → 24 buckets
    pub pairs: HashMap<String, PairStats>,

    /// Current-minute running counters
    /// (detector|comm) → (minute_id, count_in_that_minute)
    #[serde(skip)]
    cur_minute: HashMap<String, (i64, u64)>,
}

impl Baseline {
    pub fn new(config: BaselineConfig) -> Self {
        Self {
            version: 1,
            started: Utc::now(),
            config,
            pairs: HashMap::new(),
            cur_minute: HashMap::new(),
        }
    }

    fn key(detector: &str, comm: &str) -> String {
        format!("{detector}|{comm}")
    }

    /// Record an event and return Some(z_score) if anomalous, else None.
    pub fn record_and_score(&mut self, detector: &str, comm: &str) -> Option<f64> {
        let now = Utc::now();
        let cur_min = now.timestamp() / 60;
        let hour = now.hour() as usize;
        let key = Self::key(detector, comm);

        // M-3: Evict stale pairs when the table grows past the cap. We
        // only walk + retain when over cap so the steady state is free.
        if self.pairs.len() >= self.config.pairs_max {
            let cutoff = now - chrono::Duration::hours(self.config.evict_age_hours);
            let before = self.pairs.len();
            self.pairs
                .retain(|_, p| p.last_seen.map_or(false, |t| t > cutoff));
            // Drop matching cur_minute entries too — otherwise that map
            // would be the new unbounded leak.
            let live: std::collections::HashSet<_> = self.pairs.keys().cloned().collect();
            self.cur_minute.retain(|k, _| live.contains(k));
            let after = self.pairs.len();
            if after < before {
                tracing::info!(
                    evicted = before - after,
                    remaining = after,
                    cap = self.config.pairs_max,
                    "baseline: evicted stale pairs"
                );
            }
        }

        // ── Update minute window: roll over if minute changed ───────
        let stats = self.pairs.entry(key.clone()).or_default();
        stats.total = stats.total.saturating_add(1);
        if stats.first_seen.is_none() {
            stats.first_seen = Some(now);
        }
        stats.last_seen = Some(now);

        let alpha = self.config.alpha;
        let entry = self.cur_minute.entry(key).or_insert((cur_min, 0));
        if entry.0 != cur_min {
            // Minute boundary crossed: flush previous count into prev hour
            let prev_hour = ((entry.0 % (24 * 60)) / 60) as usize % 24;
            stats.buckets[prev_hour].observe(entry.1, alpha);
            *entry = (cur_min, 0);
        }
        entry.1 = entry.1.saturating_add(1);
        let observed = entry.1 as f64;

        // ── Scoring ─────────────────────────────────────────────────
        let learning_until =
            self.started + chrono::Duration::seconds(self.config.learning_secs as i64);
        if now < learning_until {
            return None; // still learning
        }

        let bucket = &stats.buckets[hour];
        if bucket.samples == 0 {
            // No prior data for this hour. Score as "new pattern":
            // use observed as raw signal compared to mean=0, σ=floor.
            let z = observed / 0.5;
            if z >= self.config.score_threshold {
                return Some(z);
            }
            return None;
        }
        let z = bucket.z_score(observed);
        if z >= self.config.score_threshold {
            Some(z)
        } else {
            None
        }
    }

    /// Save baseline to disk (JSON).
    /// File is written 0640 — readable by owner + kernelradar group only.
    /// The dump contains every observed (detector, comm) pair on this
    /// host, which is a system fingerprint and should not be world-readable.
    pub fn save(&self) -> std::io::Result<()> {
        let path = PathBuf::from(&self.config.save_path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let tmp = path.with_extension("json.tmp");
        let text = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, &path)?;

        // M-7: tighten permissions after the rename. set_permissions on a
        // freshly-renamed file is the right place — chmod on the tmp would
        // race with the rename. Failure here is logged but not fatal: the
        // file still exists, just with whatever umask gave it.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))
            {
                tracing::warn!(
                    error = %e,
                    path = %self.config.save_path,
                    "baseline: could not chmod 0640 — file may be world-readable"
                );
            }
        }
        Ok(())
    }

    /// Load from disk. Corrupted/missing → graceful Default fallback.
    pub fn load_or_default(config: BaselineConfig) -> Self {
        let path = PathBuf::from(&config.save_path);
        if !path.exists() {
            tracing::info!(path = %config.save_path,
                            "baseline: no prior file, starting fresh");
            return Self::new(config);
        }
        match std::fs::read_to_string(&path) {
            Ok(text) => match serde_json::from_str::<Baseline>(&text) {
                Ok(mut b) => {
                    // Replace stored config with current-runtime config
                    // (admin may have edited [baseline] in TOML).
                    b.config = config;
                    tracing::info!(
                        pairs = b.pairs.len(),
                        started = %b.started,
                        "baseline: loaded"
                    );
                    b
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        path = %config.save_path,
                        "baseline: corrupted file, starting fresh"
                    );
                    Self::new(config)
                }
            },
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    path = %config.save_path,
                    "baseline: cannot read, starting fresh"
                );
                Self::new(config)
            }
        }
    }

    /// Reset baseline: zero all stats.
    pub fn reset(&mut self) {
        self.started = Utc::now();
        self.pairs.clear();
        self.cur_minute.clear();
    }
}

// ── Global singleton ────────────────────────────────────────────────

static GLOBAL: OnceLock<Mutex<Baseline>> = OnceLock::new();

pub fn init_default() {
    let _ = GLOBAL.set(Mutex::new(Baseline::new(BaselineConfig::default())));
}

pub fn init_with_config(config: BaselineConfig) {
    let _ = GLOBAL.set(Mutex::new(Baseline::load_or_default(config)));
}

fn lock() -> std::sync::MutexGuard<'static, Baseline> {
    // M-8: on poison we keep going — baseline is best-effort statistical
    // data, the panic that poisoned the mutex was already reported. A
    // potentially-inconsistent record is preferable to a daemon-wide crash.
    GLOBAL
        .get_or_init(|| Mutex::new(Baseline::new(BaselineConfig::default())))
        .lock()
        .unwrap_or_else(|e| {
            tracing::warn!("baseline mutex was poisoned; continuing with recovered state");
            e.into_inner()
        })
}

/// Record an event in the baseline; returns Some(z) when anomalous.
pub fn record_and_score(detector: &str, comm: &str) -> Option<f64> {
    let mut b = lock();
    b.record_and_score(detector, comm)
}

/// Snapshot for serialisation outside (kernelradar baseline show).
pub fn snapshot() -> Baseline {
    lock().clone()
}

pub fn save() -> std::io::Result<()> {
    lock().save()
}

pub fn reset_global() {
    lock().reset();
}

pub fn spawn_periodic_save() {
    tokio::spawn(async {
        let interval_secs = lock().config.save_interval_secs;
        let mut tick = tokio::time::interval(Duration::from_secs(interval_secs));
        tick.tick().await; // skip immediate
        loop {
            tick.tick().await;
            if let Err(e) = save() {
                tracing::warn!("baseline: save failed: {e}");
            } else {
                tracing::debug!("baseline: persisted");
            }
        }
    });
}

/// Are we still in the learning warm-up phase?
pub fn in_learning() -> bool {
    let b = lock();
    let until = b.started + chrono::Duration::seconds(b.config.learning_secs as i64);
    Utc::now() < until
}
