// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Ferith Tools
//
// Part of the kernelradar project — Linux kernel anomaly detection via BPF.
// See LICENSE for terms.

/// Rate-limiting + burst detection + exponential backoff.
///
/// Single in-memory state shared across all detectors. The decision is
/// made for every alert before it is emitted by `print_alert`.
///
/// Key = (detector, comm, event_type) — the same source firing the
/// same kind of alert. Rapid repetition is suppressed; persistent
/// repetition triggers exponential backoff; absolute floods raise a
/// secondary BURST alert.
///
/// Threading: a single Mutex protects the whole state map. Lock is
/// only held for ~microseconds per alert.
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use kernelradar_core::event::Severity;

/// (detector, comm, event_type)
type Key = (String, String, u16);

#[derive(Debug, Clone, Copy)]
pub struct RateLimitConfig {
    /// Sliding window length for the basic rate limit
    pub window: Duration,
    /// Max alerts emitted within `window` per key
    pub window_max: u32,

    /// Burst detection: if more than this many events for one key
    /// arrive within `burst_window` → emit a BURST alert.
    pub burst_threshold: u32,
    pub burst_window: Duration,

    /// Exponential backoff: after `window_max` is exceeded, the next
    /// allowed alert is delayed by `backoff_initial` and doubles each
    /// time the key keeps firing, capped at `backoff_max`.
    pub backoff_initial: Duration,
    pub backoff_max: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(60),
            window_max: 10,
            burst_threshold: 100,
            burst_window: Duration::from_secs(1),
            backoff_initial: Duration::from_secs(60),
            backoff_max: Duration::from_secs(3600),
        }
    }
}

#[derive(Debug)]
struct KeyState {
    /// Start of the current sliding window
    window_start: Instant,
    /// Allowed-emissions counter for current window
    window_count: u32,
    /// Total events suppressed for this key (lifetime)
    suppressed: u64,
    /// Total events allowed for this key (lifetime)
    allowed: u64,
    /// Burst window: holds (start, count). Reset on new burst window.
    burst_start: Instant,
    burst_count: u32,
    /// Time of last allowed emission
    last_emitted: Instant,
    /// Exponential backoff state
    backoff_steps: u32,
    /// Severity carried over for summary output
    severity_seen: Severity,
}

impl KeyState {
    fn new(severity: Severity) -> Self {
        let now = Instant::now();
        Self {
            window_start: now,
            window_count: 0,
            suppressed: 0,
            allowed: 0,
            burst_start: now,
            burst_count: 0,
            last_emitted: now - Duration::from_secs(86400), // far past
            backoff_steps: 0,
            severity_seen: severity,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Emit normally
    Allow,
    /// Suppress: don't emit but counter incremented
    Suppress,
    /// Emit + emit a secondary BURST alert
    Burst,
}

pub struct RateLimiter {
    state: HashMap<Key, KeyState>,
    config: RateLimitConfig,
}

impl RateLimiter {
    fn new(config: RateLimitConfig) -> Self {
        Self {
            state: HashMap::new(),
            config,
        }
    }

    fn check(&mut self, key: Key, severity: Severity) -> Decision {
        let now = Instant::now();
        let cfg = self.config;
        let entry = self
            .state
            .entry(key)
            .or_insert_with(|| KeyState::new(severity));
        entry.severity_seen = entry.severity_seen.max(severity);

        // ── Burst window ────────────────────────────────────────────
        if now.duration_since(entry.burst_start) >= cfg.burst_window {
            entry.burst_start = now;
            entry.burst_count = 0;
        }
        entry.burst_count = entry.burst_count.saturating_add(1);
        let burst_triggered = entry.burst_count == cfg.burst_threshold;

        // ── Sliding window ──────────────────────────────────────────
        if now.duration_since(entry.window_start) >= cfg.window {
            entry.window_start = now;
            entry.window_count = 0;
            // Successful window completion gradually resets backoff
            if entry.backoff_steps > 0 {
                entry.backoff_steps -= 1;
            }
        }

        // ── Backoff: must wait at least backoff(steps) since last emit ─
        let required_gap = if entry.backoff_steps == 0 {
            Duration::from_millis(0)
        } else {
            let factor = 2u64.saturating_pow((entry.backoff_steps - 1).min(20));
            cfg.backoff_initial
                .saturating_mul(factor as u32)
                .min(cfg.backoff_max)
        };
        let gap_ok = now.duration_since(entry.last_emitted) >= required_gap;

        // ── Decision ────────────────────────────────────────────────
        let allowed = entry.window_count < cfg.window_max && gap_ok;

        if allowed {
            entry.window_count += 1;
            entry.allowed += 1;
            entry.last_emitted = now;
            if burst_triggered {
                Decision::Burst
            } else {
                Decision::Allow
            }
        } else {
            entry.suppressed += 1;
            // Bump backoff step if we just exceeded the window cap
            if entry.window_count >= cfg.window_max && entry.backoff_steps == 0 {
                entry.backoff_steps = 1;
            }
            // Burst even when over rate limit — still a security signal
            if burst_triggered {
                // Force-emit one BURST alert despite limit, but do not
                // reset entry counters
                entry.last_emitted = now;
                Decision::Burst
            } else {
                Decision::Suppress
            }
        }
    }

    /// Drain and return a snapshot of suppressed counters since last call.
    /// Resets per-key suppressed counts (cumulative `allowed` is preserved).
    fn drain_suppressed(&mut self) -> Vec<(Key, u64, Severity)> {
        let mut out = Vec::new();
        for (k, v) in self.state.iter_mut() {
            if v.suppressed > 0 {
                out.push((k.clone(), v.suppressed, v.severity_seen));
                v.suppressed = 0;
            }
        }
        out
    }
}

// ── Global singleton ─────────────────────────────────────────────────

static GLOBAL: OnceLock<Mutex<RateLimiter>> = OnceLock::new();

fn lock() -> std::sync::MutexGuard<'static, RateLimiter> {
    // Poisoned mutex → log and recover. Suppression decisions are
    // best-effort; a missed dedup is preferable to a crashed daemon.
    GLOBAL
        .get_or_init(|| Mutex::new(RateLimiter::new(RateLimitConfig::default())))
        .lock()
        .unwrap_or_else(|e| {
            tracing::warn!("rate limiter mutex was poisoned; continuing with recovered state");
            e.into_inner()
        })
}

/// Initialise / reconfigure the global rate limiter. Call once at startup.
pub fn init(config: RateLimitConfig) {
    let _ = GLOBAL.set(Mutex::new(RateLimiter::new(config)));
}

/// Make a decision for an alert.
pub fn check(detector: &str, comm: &str, event_type: u16, severity: Severity) -> Decision {
    let mut rl = lock();
    rl.check(
        (detector.to_string(), comm.to_string(), event_type),
        severity,
    )
}

/// Drain suppressed counters since last drain.
pub fn drain_suppressed() -> Vec<(Key, u64, Severity)> {
    let mut rl = lock();
    rl.drain_suppressed()
}
