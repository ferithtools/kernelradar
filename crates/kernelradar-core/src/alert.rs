// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Ferith Tools
//
// Part of the kernelradar project — Linux kernel anomaly detection via BPF.
// See LICENSE for terms.

use crate::event::Severity;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::borrow::Cow;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
pub struct Alert {
    /// Sequential local id (per-process)
    pub id: u64,
    /// UUID v7 — timestamp-prefixed, sortable, unique across instances
    pub correlation_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub severity: Severity,
    /// Detector identifier. Almost always a string literal from the
    /// detector crate (`Cow::Borrowed("privesc")`); synthetic variants
    /// like `"privesc.anomaly"` arrive as owned strings, so `Cow` lets
    /// the hot path stay allocation-free without losing flexibility.
    pub detector: Cow<'static, str>,
    /// Detector-specific event subtype (mirrors `KrEvent::event_type`).
    /// Used by the rate-limiter as part of the dedup key.
    pub event_type: u16,
    pub title: String,
    pub description: String,
    pub pid: u32,
    pub uid: u32,
    pub comm: String,
    /// JSON-serialised detector-specific context
    pub context: serde_json::Value,
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
