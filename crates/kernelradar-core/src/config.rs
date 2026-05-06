// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Ferith Tools
//
// Part of the kernelradar project — Linux kernel anomaly detection via BPF.
// See LICENSE for terms.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

/// Top-level kernelradar configuration.
///
/// Layout:
///   [global]
///     log_level     = "info"
///     output_format = "auto"   # auto | plain | json | journald
///
///   [detectors.privesc]
///     enabled   = true
///     allowlist = ["sshd", "su", "sudo", "/python3.*/"]
///
/// Allowlist entries are matched against the process `comm` and the
/// basename of `/proc/<pid>/exe`. An entry wrapped in `/regex/` is
/// treated as a regular expression (Rust regex syntax).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub global: GlobalConfig,
    #[serde(rename = "ratelimit")]
    pub ratelimit: RateLimitTomlConfig,
    pub baseline: BaselineTomlConfig,
    pub webhook: WebhookTomlConfig,
    pub prometheus: PromTomlConfig,
    pub enforcement: EnforcementTomlConfig,
    pub integrity: IntegrityTomlConfig,
    /// Network-detector-specific tunables (F-1).
    /// Generic per-detector knobs (enabled, allowlist) stay in `detectors`.
    pub network: NetworkTomlConfig,
    pub detectors: BTreeMap<String, DetectorConfig>,
}

/// BPF integrity check (T-6.5 + H-1). When `strict_mode = true`, a hash
/// mismatch refuses to load the affected detector instead of just
/// warning. Default `false` keeps the friendly "warn but continue"
/// behaviour for first-time installs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct IntegrityTomlConfig {
    pub strict_mode: bool,
}

/// Network-detector tunables. Currently a destination CIDR allowlist —
/// connect() to any address inside one of these CIDRs is suppressed
/// before process-allowlist evaluation. IPv4 only for now.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkTomlConfig {
    /// CIDRs to whitelist as connection destinations.
    /// Example: ["149.154.0.0/16", "64.233.160.0/19", "172.65.0.0/16"]
    /// (Telegram + a Google block + Cloudflare). Invalid entries are
    /// logged at startup and skipped.
    pub destination_cidr_allowlist: Vec<String>,
}

/// LSM enforcement (T-0.9) and self-protection (T-6.4).
/// All flags default to false — enabling these can break the system.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EnforcementTomlConfig {
    pub selfprotect_enabled: bool,
    pub bpf_enforce_enabled: bool,
    pub kmod_enforce_enabled: bool,
    pub bpf_allowlist: Vec<String>,
    pub kmod_allowlist: Vec<String>,
}

impl Default for EnforcementTomlConfig {
    fn default() -> Self {
        Self {
            selfprotect_enabled: false,
            bpf_enforce_enabled: false,
            kmod_enforce_enabled: false,
            bpf_allowlist: vec!["bpftrace".into(), "falco".into(), "kernelradar".into()],
            kmod_allowlist: vec![
                "modprobe".into(),
                "kmod".into(),
                "insmod".into(),
                "systemd-udevd".into(),
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WebhookTomlConfig {
    pub enabled: bool,
    pub url: String,
    pub timeout_secs: u64,
    pub auth_token: Option<String>,
    /// Forward only Severity ≥ Alert when true. Useful for Slack/Telegram.
    pub severity_filter_alert_or_higher: bool,
}

impl Default for WebhookTomlConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: String::new(),
            timeout_secs: 3,
            auth_token: None,
            severity_filter_alert_or_higher: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PromTomlConfig {
    pub enabled: bool,
    pub listen_addr: String,
}

impl Default for PromTomlConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            // 9101 to avoid collision with node_exporter, which owns 9100
            // by convention on every Linux host running prometheus stack.
            listen_addr: "127.0.0.1:9101".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BaselineTomlConfig {
    pub enabled: bool,
    /// Warm-up period before scoring kicks in
    pub learning_secs: u64,
    /// Z-score threshold above which an anomaly is reported
    pub score_threshold: f64,
    /// EWMA smoothing factor (0..1). Smaller = more inertia.
    pub alpha: f64,
    /// File to persist learned model
    pub save_path: String,
    /// How often to flush to disk
    pub save_interval_secs: u64,
}

impl Default for BaselineTomlConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            learning_secs: 3600 * 24,
            score_threshold: 3.0,
            alpha: 0.10,
            save_path: "/var/lib/kernelradar/baseline.json".into(),
            save_interval_secs: 300,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RateLimitTomlConfig {
    /// Sliding window length, seconds
    pub window_secs: u64,
    /// Max emissions per key per window
    pub window_max: u32,
    /// Burst detection: count threshold within burst_window
    pub burst_threshold: u32,
    pub burst_window_secs: u64,
    /// Exponential backoff initial delay
    pub backoff_initial_secs: u64,
    pub backoff_max_secs: u64,
}

impl Default for RateLimitTomlConfig {
    fn default() -> Self {
        Self {
            window_secs: 60,
            window_max: 10,
            burst_threshold: 100,
            burst_window_secs: 1,
            backoff_initial_secs: 60,
            backoff_max_secs: 3600,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GlobalConfig {
    pub log_level: String,
    pub output_format: String,
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            log_level: "info".to_string(),
            output_format: "auto".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DetectorConfig {
    pub enabled: bool,
    pub allowlist: Vec<String>,
}

impl Default for DetectorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allowlist: Vec::new(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("config file not found: {0}")]
    NotFound(String),
    #[error("read config {0}: {1}")]
    Io(String, std::io::Error),
    #[error("parse {0}: {1}")]
    Parse(String, String),
}

impl Config {
    /// Load TOML config from path. Returns NotFound if missing — caller
    /// decides whether that's fatal or use defaults.
    pub fn from_path(path: &str) -> Result<Self, ConfigError> {
        let p = Path::new(path);
        if !p.exists() {
            return Err(ConfigError::NotFound(path.to_string()));
        }
        let text = std::fs::read_to_string(p).map_err(|e| ConfigError::Io(path.to_string(), e))?;
        toml::from_str::<Config>(&text)
            .map_err(|e| ConfigError::Parse(path.to_string(), e.to_string()))
    }

    /// Resolve allowlist for a given detector, falling back to a global
    /// default list if the detector isn't configured explicitly.
    pub fn allowlist_for(&self, detector: &str, fallback: &[String]) -> Vec<String> {
        match self.detectors.get(detector) {
            Some(d) if !d.allowlist.is_empty() => d.allowlist.clone(),
            _ => fallback.to_vec(),
        }
    }

    /// Whether the detector is enabled. If absent in config: enabled.
    pub fn detector_enabled(&self, detector: &str) -> bool {
        self.detectors
            .get(detector)
            .map(|d| d.enabled)
            .unwrap_or(true)
    }

    /// Validate config for obvious errors. Returns list of issues.
    pub fn validate(&self) -> Vec<String> {
        let mut issues = Vec::new();

        match self.global.output_format.as_str() {
            "auto" | "plain" | "json" | "journald" | "falco" => {}
            other => issues.push(format!(
                "global.output_format = {other:?} \
                                          (expected auto|plain|json|journald|falco)"
            )),
        }

        if self.webhook.enabled && self.webhook.url.is_empty() {
            issues.push("webhook.enabled = true but webhook.url is empty".into());
        }
        if self.prometheus.enabled && self.prometheus.listen_addr.is_empty() {
            issues.push("prometheus.enabled = true but listen_addr is empty".into());
        }

        match self.global.log_level.as_str() {
            "trace" | "debug" | "info" | "warn" | "error" | "off" => {}
            // Composite RUST_LOG strings are also fine — pass through
            s if s.contains('=') || s.contains(',') => {}
            other => issues.push(format!(
                "global.log_level = {other:?} \
                                          (expected trace|debug|info|warn|error|off \
                                          or a RUST_LOG-style filter)"
            )),
        }

        let known: &[&str] = &[
            "privesc",
            "bpf-loader",
            "container",
            "kmod",
            "fim",
            "network",
            "injection",
            "cred",
        ];
        for name in self.detectors.keys() {
            if !known.iter().any(|k| k == name) {
                issues.push(format!(
                    "unknown detector {name:?} \
                                     (known: {known:?})"
                ));
            }
        }

        // Validate regex patterns
        for (det, cfg) in &self.detectors {
            for entry in &cfg.allowlist {
                if let Some(rx) = entry.strip_prefix('/').and_then(|s| s.strip_suffix('/')) {
                    if let Err(e) = regex::Regex::new(rx) {
                        issues.push(format!(
                            "detectors.{det}.allowlist: \
                                             bad regex {entry:?}: {e}"
                        ));
                    }
                }
            }
        }

        // Validate CIDR strings — same syntactic shape detectors/cidr.rs
        // will accept at runtime. Keep the check here local (no
        // detectors-crate dep) so config validation stays standalone.
        for entry in &self.network.destination_cidr_allowlist {
            if !is_valid_ipv4_cidr(entry) {
                issues.push(format!(
                    "network.destination_cidr_allowlist: \
                                     invalid CIDR {entry:?} \
                                     (expected a.b.c.d/N, N in 0..=32)"
                ));
            }
        }

        issues
    }
}

/// Cheap IPv4-CIDR syntactic check used by Config::validate. Mirrors the
/// runtime parser in `kernelradar_detectors::cidr::Cidr::parse`.
fn is_valid_ipv4_cidr(s: &str) -> bool {
    let Some((addr, len)) = s.split_once('/') else {
        return false;
    };
    if addr.trim().parse::<std::net::Ipv4Addr>().is_err() {
        return false;
    }
    match len.trim().parse::<u32>() {
        Ok(n) if n <= 32 => true,
        _ => false,
    }
}
