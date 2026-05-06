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
    pub global:    GlobalConfig,
    pub detectors: BTreeMap<String, DetectorConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GlobalConfig {
    pub log_level:     String,
    pub output_format: String,
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            log_level:     "info".to_string(),
            output_format: "auto".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DetectorConfig {
    pub enabled:   bool,
    pub allowlist: Vec<String>,
}

impl Default for DetectorConfig {
    fn default() -> Self {
        Self { enabled: true, allowlist: Vec::new() }
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
        let text = std::fs::read_to_string(p)
            .map_err(|e| ConfigError::Io(path.to_string(), e))?;
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
            "auto" | "plain" | "json" | "journald" => {}
            other => issues.push(format!("global.output_format = {other:?} \
                                          (expected auto|plain|json|journald)")),
        }

        match self.global.log_level.as_str() {
            "trace" | "debug" | "info" | "warn" | "error" | "off" => {}
            // Composite RUST_LOG strings are also fine — pass through
            s if s.contains('=') || s.contains(',') => {}
            other => issues.push(format!("global.log_level = {other:?} \
                                          (expected trace|debug|info|warn|error|off \
                                          or a RUST_LOG-style filter)")),
        }

        let known: &[&str] = &[
            "privesc", "bpf-loader", "container", "kmod",
            "fim", "network", "injection", "cred",
        ];
        for name in self.detectors.keys() {
            if !known.iter().any(|k| k == name) {
                issues.push(format!("unknown detector {name:?} \
                                     (known: {known:?})"));
            }
        }

        // Validate regex patterns
        for (det, cfg) in &self.detectors {
            for entry in &cfg.allowlist {
                if let Some(rx) = entry.strip_prefix('/').and_then(|s| s.strip_suffix('/')) {
                    if let Err(e) = regex::Regex::new(rx) {
                        issues.push(format!("detectors.{det}.allowlist: \
                                             bad regex {entry:?}: {e}"));
                    }
                }
            }
        }

        issues
    }
}
