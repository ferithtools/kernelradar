use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub global:    GlobalConfig,
    pub detectors: DetectorConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GlobalConfig {
    pub log_level:     String,
    pub alert_backend: AlertBackend,
    pub webhook_url:   Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertBackend {
    Journald,
    Stdout,
    Webhook,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DetectorConfig {
    pub privesc:    PrivEscConfig,
    pub bpf_loader: BpfLoaderConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivEscConfig {
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BpfLoaderConfig {
    pub enabled:   bool,
    /// Processes allowed to load BPF programs
    pub allowlist: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            global:    GlobalConfig::default(),
            detectors: DetectorConfig::default(),
        }
    }
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            log_level:     "info".to_string(),
            alert_backend: AlertBackend::Stdout,
            webhook_url:   None,
        }
    }
}

impl Default for DetectorConfig {
    fn default() -> Self {
        Self {
            privesc:    PrivEscConfig    { enabled: true },
            bpf_loader: BpfLoaderConfig {
                enabled:   true,
                allowlist: vec![
                    "/usr/sbin/falco".to_string(),
                    "/usr/bin/bpftrace".to_string(),
                ],
            },
        }
    }
}
