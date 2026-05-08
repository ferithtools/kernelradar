// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Ferith Tools
//
// Part of the kernelradar project - Linux kernel anomaly detection via BPF.
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
    /// Network-detector-specific tunables. Generic per-detector knobs
    /// (enabled, allowlist) stay in `detectors`.
    pub network: NetworkTomlConfig,
    pub detectors: BTreeMap<String, DetectorConfig>,
}

/// BPF integrity check. When `strict_mode = true` (default), a hash
/// mismatch or a missing build-time hash refuses to load the affected
/// detector. Operators rebuilding `.bpf.o` files in place can flip
/// this off temporarily, but shipped binaries must run strict to keep
/// supply-chain tampering visible.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IntegrityTomlConfig {
    pub strict_mode: bool,
}

impl Default for IntegrityTomlConfig {
    fn default() -> Self {
        Self { strict_mode: true }
    }
}

/// Network-detector tunables. Currently a destination CIDR allowlist -
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

/// LSM enforcement and self-protection. All flags default to false -
/// enabling these can break the system.
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
    /// SSRF guard. Default `false`: refuse webhook URLs pointing at
    /// loopback (127.0.0.0/8, ::1), link-local / cloud metadata
    /// (169.254.0.0/16, fe80::/10), or RFC1918 private ranges. Operators
    /// who legitimately want to POST to a private collector on the
    /// management network can flip this to `true`.
    pub allow_private_destinations: bool,
}

impl Default for WebhookTomlConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: String::new(),
            timeout_secs: 3,
            auth_token: None,
            severity_filter_alert_or_higher: false,
            allow_private_destinations: false,
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
    /// Cap on tracked (detector, comm) pairs. Eviction kicks in when
    /// the table reaches this size.
    pub pairs_max: usize,
    /// Pairs older than this (last_seen-wise) are evicted when at cap.
    pub evict_age_hours: i64,
    /// Minimum samples a per-hour bucket must collect before its
    /// learned (mean, sigma) is used for scoring. Until then events
    /// score against the "no prior data" branch. Defends against
    /// drift attacks that slowly train the bucket during warm-up.
    pub min_samples_for_scoring: u64,
}

impl Default for BaselineTomlConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            learning_secs: 3600 * 24,
            score_threshold: 3.0,
            alpha: 0.10,
            save_path: "/var/lib/kernelradar/state/baseline.json".into(),
            save_interval_secs: 300,
            pairs_max: 10_000,
            evict_age_hours: 24 * 7,
            min_samples_for_scoring: 24,
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
    /// Cap on (detector, comm, event_type) state entries kept in
    /// memory. Defends against unbounded growth from a hostile
    /// attacker churning through `prctl(PR_SET_NAME)` to spawn
    /// distinct keys. When exceeded the entry with the oldest
    /// `last_emitted` is evicted. Default 10 000.
    pub keys_max: usize,
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
            keys_max: 10_000,
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
    /// Load TOML config from path. Returns NotFound if missing - caller
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

        if self.webhook.enabled {
            if self.webhook.url.is_empty() {
                issues.push("webhook.enabled = true but webhook.url is empty".into());
            } else if !self.webhook.allow_private_destinations {
                if let Some(reason) = webhook_url_security_issue(&self.webhook.url) {
                    issues.push(format!(
                        "webhook.url {:?}: {reason}. \
                         Set webhook.allow_private_destinations = true to override.",
                        self.webhook.url
                    ));
                }
            }
        }
        if self.prometheus.enabled && self.prometheus.listen_addr.is_empty() {
            issues.push("prometheus.enabled = true but listen_addr is empty".into());
        }

        match self.global.log_level.as_str() {
            "trace" | "debug" | "info" | "warn" | "error" | "off" => {}
            // Composite RUST_LOG strings are also fine - pass through
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

        // Validate CIDR strings - same syntactic shape detectors/cidr.rs
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

        // Reject NaN / Inf / out-of-range floats and zero-caps. TOML 1.0
        // accepts `nan`, `+inf`, `-inf` as float literals, and earlier
        // versions silently degraded:
        //   - score_threshold = nan → `z >= nan` always false → anomaly
        //     detection silently disabled
        //   - alpha <= 0 / > 1 → meaningless EWMA scoring
        //   - keys_max = 0 / pairs_max = 0 → caps disabled, unbounded
        //     state growth
        //   - webhook.timeout_secs = 0 → "no timeout" → slow collector
        //     pins MAX_INFLIGHT permits forever
        if !self.baseline.alpha.is_finite()
            || self.baseline.alpha <= 0.0
            || self.baseline.alpha > 1.0
        {
            issues.push(format!(
                "baseline.alpha = {} (expected 0.0 < alpha <= 1.0, finite)",
                self.baseline.alpha
            ));
        }
        if !self.baseline.score_threshold.is_finite() || self.baseline.score_threshold <= 0.0 {
            issues.push(format!(
                "baseline.score_threshold = {} (expected positive finite)",
                self.baseline.score_threshold
            ));
        }
        if self.baseline.learning_secs == 0 {
            issues.push("baseline.learning_secs = 0 (expected > 0)".into());
        }
        if self.baseline.save_interval_secs == 0 {
            issues.push("baseline.save_interval_secs = 0 (expected > 0)".into());
        }
        if self.baseline.pairs_max == 0 {
            issues.push("baseline.pairs_max = 0 (cap disabled - expected > 0)".into());
        }
        if self.ratelimit.keys_max == 0 {
            issues.push("ratelimit.keys_max = 0 (cap disabled - expected > 0)".into());
        }
        if self.ratelimit.window_secs == 0 {
            issues.push("ratelimit.window_secs = 0 (expected > 0)".into());
        }
        if self.ratelimit.burst_window_secs == 0 {
            issues.push("ratelimit.burst_window_secs = 0 (expected > 0)".into());
        }
        if self.webhook.enabled && self.webhook.timeout_secs == 0 {
            issues.push(
                "webhook.timeout_secs = 0 with enabled = true \
                 (would let a slow collector pin all inflight permits forever)"
                    .into(),
            );
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
    matches!(len.trim().parse::<u32>(), Ok(n) if n <= 32)
}

/// SSRF guard for webhook URLs. Returns `Some(reason)` when the URL
/// targets a destination that should not be allowed without an
/// explicit `allow_private_destinations = true` opt-in:
///
/// - cloud-metadata IPs (169.254.0.0/16, fd00:ec2::/32)
/// - loopback (127.0.0.0/8, ::1)
/// - RFC1918 private (10/8, 172.16/12, 192.168/16)
/// - link-local IPv6 (fe80::/10) and ULA (fc00::/7)
/// - hostnames `localhost`, `metadata.google.internal`,
///   `metadata`, `metadata.azure.com`, etc.
/// - schemes other than http/https
///
/// Pure syntactic check on the URL string; cannot resolve DNS at
/// config-validate time, so a hostname pointing at 127.0.0.1 will
/// pass validation and fail at runtime if the daemon is reachable.
/// Operators who care should pin the destination by IP.
pub fn webhook_url_security_issue(url: &str) -> Option<String> {
    use std::net::{Ipv4Addr, Ipv6Addr};

    let lower = url.to_ascii_lowercase();
    let scheme_end = lower.find("://")?;
    let scheme = &lower[..scheme_end];
    if scheme != "http" && scheme != "https" {
        return Some(format!("scheme {scheme:?} not allowed (only http / https)"));
    }
    if scheme == "http" {
        return Some("plain http (no TLS); use https".into());
    }

    let after_scheme = &lower[scheme_end + 3..];
    let host_part = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    // Strip user-info and port.
    let host = host_part.rsplit('@').next().unwrap_or(host_part);
    let host = if let Some(stripped) = host.strip_prefix('[') {
        // IPv6 in brackets.
        stripped.split(']').next().unwrap_or(stripped)
    } else {
        host.split(':').next().unwrap_or(host)
    };
    // Trim a trailing dot - DNS-resolvable absolute names like
    // "localhost." are common URL inputs and would otherwise sneak
    // past the BLOCKED_HOSTNAMES exact-string check.
    let host = host.trim_end_matches('.');

    // Refuse hosts that look like a Linux glibc inet_aton() shortcut
    // - integer-form (`2130706433` = 127.0.0.1), hex (`0x7f000001`),
    // octal (`017700000001`), or single zero (`0`). Ipv4Addr::from_str
    // accepts only dotted-decimal and would let these pass; the OS
    // resolver / hyper / reqwest accept them at runtime via inet_aton
    // and route to the embedded address.
    if host_is_inet_aton_shortcut(host) {
        return Some("integer / octal / hex IP form not allowed (inet_aton shortcut)".into());
    }
    // Refuse percent-encoded hosts. The url crate / reqwest will
    // percent-decode the host before resolution, so `%6c%6f%63%61%6c%68%6f%73%74`
    // resolves as `localhost`. Defer to operators who genuinely need
    // unicode hosts to use the punycode form (xn--...) which doesn't
    // contain `%`.
    if host.contains('%') {
        return Some("percent-encoded host not allowed".into());
    }

    const BLOCKED_HOSTNAMES: &[&str] = &[
        "localhost",
        "ip6-localhost",
        "metadata",
        "metadata.google.internal",
        "metadata.azure.com",
        "169.254.169.254",
    ];
    for blocked in BLOCKED_HOSTNAMES {
        if host == *blocked {
            return Some(format!("hostname {blocked:?} is blocked"));
        }
    }

    if let Ok(v4) = host.parse::<Ipv4Addr>() {
        if let Some(reason) = ipv4_security_issue(v4) {
            return Some(reason);
        }
    } else if let Ok(v6) = host.parse::<Ipv6Addr>() {
        // Resolve IPv4-mapped IPv6 (`::ffff:127.0.0.1` and friends)
        // into their IPv4 form so the IPv4 ranges still apply. Without
        // this an attacker could write `[::ffff:169.254.169.254]` and
        // bypass every IPv4 check.
        if let Some(mapped) = v6.to_ipv4_mapped() {
            if let Some(reason) = ipv4_security_issue(mapped) {
                return Some(format!("IPv4-mapped IPv6 with {reason}"));
            }
        }
        if v6.is_loopback() {
            return Some("loopback IPv6 (::1)".into());
        }
        if v6.is_unspecified() || v6.is_multicast() {
            return Some("non-routable IPv6".into());
        }
        let seg0 = v6.segments()[0];
        if seg0 & 0xffc0 == 0xfe80 {
            return Some("link-local IPv6 (fe80::/10)".into());
        }
        if seg0 & 0xfe00 == 0xfc00 {
            return Some("unique-local IPv6 (fc00::/7)".into());
        }
    }
    None
}

/// True if `host` is a plain inet_aton-style numeric form that
/// `Ipv4Addr::from_str` rejects but that glibc / hyper / reqwest
/// accept at runtime: a single decimal integer (`2130706433`), an
/// octal integer (`017700000001`, leading zero + only digits), or a
/// hex integer (`0x7f000001`).
///
/// Pure DNS hostnames contain a letter or a `-` and so never match.
/// Dotted-decimal (`127.0.0.1`) is left to `Ipv4Addr::from_str` and
/// then to `ipv4_security_issue` which has the actual range checks.
fn host_is_inet_aton_shortcut(host: &str) -> bool {
    if host.is_empty() {
        return false;
    }
    // Hex: `0x` / `0X` prefix.
    if let Some(rest) = host.strip_prefix("0x").or_else(|| host.strip_prefix("0X")) {
        return !rest.is_empty() && rest.chars().all(|c| c.is_ascii_hexdigit());
    }
    // Single integer or octal. No dots allowed - dotted forms parse
    // as Ipv4Addr and go through ipv4_security_issue instead.
    if host.contains('.') {
        return false;
    }
    host.chars().all(|c| c.is_ascii_digit())
}

fn ipv4_security_issue(v4: std::net::Ipv4Addr) -> Option<String> {
    let o = v4.octets();
    if v4.is_loopback() {
        return Some("loopback IPv4 (127.0.0.0/8)".into());
    }
    if v4.is_private() {
        return Some("RFC1918 private IPv4".into());
    }
    if v4.is_link_local() {
        return Some("link-local IPv4 (169.254.0.0/16, includes cloud metadata)".into());
    }
    // CGNAT / shared-address space - 100.64.0.0/10 (RFC 6598). Not in
    // Ipv4Addr::is_private. Some hyperscalers route internal links
    // through this range; an exfiltration attempt against an internal
    // collector would otherwise look "public" to the syntactic guard.
    if o[0] == 100 && (o[1] & 0xc0) == 0x40 {
        return Some("CGNAT shared-address IPv4 (100.64.0.0/10, RFC 6598)".into());
    }
    if o[0] == 0 || v4.is_broadcast() || v4.is_multicast() || v4.is_unspecified() {
        return Some("non-routable IPv4".into());
    }
    None
}

#[cfg(test)]
mod webhook_url_tests {
    use super::webhook_url_security_issue as check;

    #[test]
    fn blocks_loopback_ipv4() {
        assert!(check("https://127.0.0.1/hook").is_some());
        assert!(check("https://127.1.2.3/hook").is_some());
    }

    #[test]
    fn blocks_cloud_metadata() {
        assert!(check("https://169.254.169.254/").is_some());
        assert!(check("https://metadata.google.internal/").is_some());
    }

    #[test]
    fn blocks_rfc1918() {
        assert!(check("https://10.0.0.1/").is_some());
        assert!(check("https://192.168.1.1/").is_some());
        assert!(check("https://172.16.5.5/").is_some());
    }

    #[test]
    fn blocks_localhost_name() {
        assert!(check("https://localhost/h").is_some());
        assert!(check("https://localhost:9090/h").is_some());
    }

    #[test]
    fn blocks_plain_http() {
        assert!(check("http://example.com/").is_some());
    }

    #[test]
    fn blocks_loopback_ipv6() {
        assert!(check("https://[::1]/h").is_some());
    }

    #[test]
    fn blocks_link_local_ipv6() {
        assert!(check("https://[fe80::1]/h").is_some());
    }

    #[test]
    fn allows_public_https() {
        assert!(check("https://hooks.slack.com/services/X/Y/Z").is_none());
        assert!(check("https://api.telegram.org/botX/sendMessage").is_none());
        assert!(check("https://203.0.113.5/hook").is_none());
    }

    #[test]
    fn rejects_unknown_scheme() {
        assert!(check("ftp://example.com/").is_some());
        assert!(check("file:///etc/passwd").is_some());
    }

    #[test]
    fn handles_userinfo_and_port() {
        assert!(check("https://user:pass@127.0.0.1:8080/h").is_some());
        assert!(check("https://user@hooks.slack.com/x").is_none());
    }

    // KR-16 hardening: bypasses the first-pass guard missed.

    #[test]
    fn blocks_ipv4_mapped_ipv6_loopback() {
        assert!(check("https://[::ffff:127.0.0.1]/h").is_some());
        assert!(check("https://[::ffff:127.1.2.3]/h").is_some());
    }

    #[test]
    fn blocks_ipv4_mapped_ipv6_metadata() {
        assert!(check("https://[::ffff:169.254.169.254]/").is_some());
    }

    #[test]
    fn blocks_ipv4_mapped_ipv6_rfc1918() {
        assert!(check("https://[::ffff:10.0.0.1]/h").is_some());
        assert!(check("https://[::ffff:192.168.1.1]/h").is_some());
    }

    #[test]
    fn blocks_trailing_dot_localhost() {
        assert!(check("https://localhost./h").is_some());
        assert!(check("https://metadata.google.internal./").is_some());
    }

    #[test]
    fn blocks_cgnat() {
        assert!(check("https://100.64.0.1/h").is_some());
        assert!(check("https://100.127.255.255/h").is_some());
        // Just outside the range still allowed.
        assert!(check("https://100.63.255.255/h").is_none());
        assert!(check("https://100.128.0.0/h").is_none());
    }

    // KR-23: inet_aton shortcuts and percent-encoding.

    #[test]
    fn blocks_integer_form_ipv4() {
        // 2130706433 = 127.0.0.1
        assert!(check("https://2130706433/hook").is_some());
        // 0 - "any address" routes to localhost on Linux.
        assert!(check("https://0/").is_some());
    }

    #[test]
    fn blocks_hex_form_ipv4() {
        assert!(check("https://0x7f000001/").is_some());
        assert!(check("https://0X7F000001/").is_some());
    }

    #[test]
    fn blocks_octal_form_ipv4() {
        // Leading zero + only digits = octal in inet_aton's eyes.
        assert!(check("https://017700000001/").is_some());
    }

    #[test]
    fn blocks_percent_encoded_host() {
        // `%6c%6f%63%61%6c%68%6f%73%74` decodes to `localhost`.
        assert!(check("https://%6c%6f%63%61%6c%68%6f%73%74/").is_some());
    }

    #[test]
    fn allows_dns_names_with_digits_when_dotted() {
        // Public IPv4 dotted form must still pass.
        assert!(check("https://203.0.113.5/hook").is_none());
        // DNS names containing digits but at least one letter fall
        // through (no IPv4-shortcut match because of the letter).
        assert!(check("https://api2.example.com/x").is_none());
        assert!(check("https://h1.h2.example.org/x").is_none());
    }
}
