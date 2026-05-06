use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use crate::event::Severity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    /// Sequential local id (per-process)
    pub id:          u64,
    /// UUID v7 — timestamp-prefixed, sortable, unique across instances
    pub correlation_id: Uuid,
    pub timestamp:   DateTime<Utc>,
    pub severity:    Severity,
    pub detector:    String,
    /// Detector-specific event subtype (mirrors `KrEvent::event_type`).
    /// Used by the rate-limiter as part of the dedup key.
    pub event_type:  u16,
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
            "[{}] {} | {} | pid={} uid={} comm={} | {} | cid={}",
            self.severity,
            self.timestamp.format("%Y-%m-%dT%H:%M:%S%.3fZ"),
            self.detector,
            self.pid,
            self.uid,
            self.comm,
            self.title,
            self.correlation_id,
        )
    }
}
