// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Ferith Tools
//
// Part of the kernelradar project - Linux kernel anomaly detection via BPF.
// See LICENSE for terms.

//! Daemon bootstrap helpers - wiring the runtime services from `Config`.
//!
//! Lives outside `main.rs` so the entry point reads as the CLI control flow
//! rather than as a long sequence of subsystem initialisers.

use std::time::Duration;

use kernelradar_core::config::Config;
use kernelradar_detectors::{
    baseline::{init_with_config as init_baseline, spawn_periodic_save, BaselineConfig},
    dedup::{init as init_rate_limit, RateLimitConfig},
    lsm::{install as install_lsm, EnforcementConfig},
    metrics::spawn_hourly_summary,
    preflight::{check_bpf_dir, check_capabilities},
    prometheus::{init as init_prometheus, spawn_server as spawn_prom_server, PromConfig},
    webhook::{init as init_webhook, WebhookConfig},
};

/// Wire up shared runtime services from config: integrity-check mode,
/// webhook output, Prometheus exporter, rate limiter, adaptive baseline.
///
/// In daemon mode (`is_daemon`) we also spawn the long-running background
/// tasks: hourly summary, periodic baseline save, and the Prometheus HTTP
/// server. In one-shot modes (single-detector run, status, baseline cmd)
/// we skip the spawns since the process exits before they would fire.
pub fn init_runtime_services(cfg: &Config, is_daemon: bool) {
    // Switch BPF integrity check to strict-fail mode if configured.
    // Must happen before any detector calls verify_bpf().
    kernelradar_detectors::integrity::set_strict_mode(cfg.integrity.strict_mode);
    if cfg.integrity.strict_mode {
        tracing::info!("BPF integrity check: strict mode ON - mismatch refuses to load");
    }

    init_webhook(WebhookConfig {
        enabled: cfg.webhook.enabled,
        url: cfg.webhook.url.clone(),
        timeout_secs: cfg.webhook.timeout_secs,
        auth_token: cfg.webhook.auth_token.clone(),
        severity_filter_alert_or_higher: cfg.webhook.severity_filter_alert_or_higher,
    });

    init_prometheus(PromConfig {
        enabled: cfg.prometheus.enabled,
        listen_addr: cfg.prometheus.listen_addr.clone(),
    });

    let rl = &cfg.ratelimit;
    init_rate_limit(RateLimitConfig {
        window: Duration::from_secs(rl.window_secs),
        window_max: rl.window_max,
        burst_threshold: rl.burst_threshold,
        burst_window: Duration::from_secs(rl.burst_window_secs),
        backoff_initial: Duration::from_secs(rl.backoff_initial_secs),
        backoff_max: Duration::from_secs(rl.backoff_max_secs),
        keys_max: rl.keys_max,
    });

    if cfg.baseline.enabled {
        init_baseline(BaselineConfig {
            learning_secs: cfg.baseline.learning_secs,
            score_threshold: cfg.baseline.score_threshold,
            alpha: cfg.baseline.alpha,
            save_path: cfg.baseline.save_path.clone(),
            save_interval_secs: cfg.baseline.save_interval_secs,
            pairs_max: cfg.baseline.pairs_max,
            evict_age_hours: cfg.baseline.evict_age_hours,
            min_samples_for_scoring: cfg.baseline.min_samples_for_scoring,
        });
    }

    if is_daemon {
        spawn_hourly_summary();
        if cfg.baseline.enabled {
            spawn_periodic_save();
        }
        if cfg.prometheus.enabled {
            spawn_prom_server();
        }
    }
}

/// Run startup capability and BPF-directory permission checks.
///
/// Failures are logged as warnings but never abort startup - admins
/// running in degraded environments (kernels without `CAP_BPF`, custom
/// `bpf_dir` paths) still get a daemon, just with reduced guarantees.
pub fn run_preflight(bpf_dir: &str) {
    check_capabilities();
    check_bpf_dir(bpf_dir);
}

/// Install LSM enforcement objects (selfprotect, enforce_bpf, enforce_kmod)
/// when at least one is enabled in config. All failures are logged but
/// never propagated - the LSM stack is opt-in and never aborts the daemon.
pub fn install_lsm_if_enabled(cfg: &Config, bpf_dir: &str) {
    let enf = &cfg.enforcement;
    if !(enf.selfprotect_enabled || enf.bpf_enforce_enabled || enf.kmod_enforce_enabled) {
        return;
    }
    install_lsm(&EnforcementConfig {
        selfprotect_enabled: enf.selfprotect_enabled,
        bpf_enforce_enabled: enf.bpf_enforce_enabled,
        kmod_enforce_enabled: enf.kmod_enforce_enabled,
        selfprotect_obj_path: format!("{bpf_dir}/selfprotect.bpf.o"),
        bpf_enforce_obj_path: format!("{bpf_dir}/enforce_bpf.bpf.o"),
        kmod_enforce_obj_path: format!("{bpf_dir}/enforce_kmod.bpf.o"),
        bpf_allowlist: enf.bpf_allowlist.clone(),
        kmod_allowlist: enf.kmod_allowlist.clone(),
    });
}
