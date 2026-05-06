use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use crate::event::Severity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id:          u64,
    pub timestamp:   DateTime<Utc>,
    pub severity:    Severity,
    pub detector:    String,
    pub title:       String,
    pub description: String,
    pub pid:         u32,
    pub uid:         u32,
    pub comm:        String,
    /// JSON-serialised detector-specific context
    pub context:     serde_json::Value,
}

impl std::fmt::Display for Alert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] {} | {} | pid={} uid={} comm={} | {}",
            self.severity,
            self.timestamp.format("%Y-%m-%dT%H:%M:%S%.3fZ"),
            self.detector,
            self.pid,
            self.uid,
            self.comm,
            self.title,
        )
    }
}
