// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Ferith Tools
//
// Part of the kernelradar project — Linux kernel anomaly detection via BPF.
// See LICENSE for terms.

/// Global output format selection (T-1.4 + T-5.6).
///
/// • Plain    — colored human text on stdout (interactive use)
/// • Json     — one JSON object per line (kernelradar native schema)
/// • Journald — tracing events with structured fields
/// • Falco    — Falco-compatible JSON schema, one object per line
///              (see https://falco.org/docs/outputs/formatting/)
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Plain,
    Json,
    Journald,
    Falco,
}

static OUTPUT_FORMAT: OnceLock<OutputFormat> = OnceLock::new();

pub fn set_output_format(f: OutputFormat) {
    let _ = OUTPUT_FORMAT.set(f);
}

pub fn global_output_format() -> OutputFormat {
    *OUTPUT_FORMAT.get().unwrap_or(&OutputFormat::Plain)
}

pub fn detect_systemd_environment() -> bool {
    std::env::var_os("JOURNAL_STREAM").is_some() || std::env::var_os("INVOCATION_ID").is_some()
}

/// Translate a kernelradar Alert into a Falco-compatible JSON object.
///
/// Falco fields used:
///   time          — ISO-8601 timestamp
///   priority      — Falco severity (Emergency..Debug)
///   rule          — name of the rule that fired
///   output        — human-readable line
///   output_fields — map of additional context
///   source        — "syscall" (closest match for our event sources)
///   tags          — list of tags for the rule
///   hostname      — pulled from /etc/hostname
pub fn alert_to_falco_json(alert: &kernelradar_core::alert::Alert) -> String {
    let priority = match alert.severity {
        kernelradar_core::event::Severity::Critical => "Critical",
        kernelradar_core::event::Severity::Alert => "Error",
        kernelradar_core::event::Severity::Warning => "Warning",
        kernelradar_core::event::Severity::Info => "Informational",
    };

    let hostname = std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".into());

    // Build output_fields with Falco-conventional names + our custom ones
    let mut fields = serde_json::Map::new();
    fields.insert("proc.pid".into(), serde_json::json!(alert.pid));
    fields.insert("proc.name".into(), serde_json::json!(alert.comm));
    fields.insert("user.uid".into(), serde_json::json!(alert.uid));
    fields.insert(
        "kernelradar.detector".into(),
        serde_json::json!(alert.detector),
    );
    fields.insert(
        "kernelradar.event_type".into(),
        serde_json::json!(alert.event_type),
    );
    fields.insert(
        "kernelradar.correlation_id".into(),
        serde_json::json!(alert.correlation_id.to_string()),
    );
    fields.insert("kernelradar.context".into(), alert.context.clone());

    let obj = serde_json::json!({
        "time":          alert.timestamp.to_rfc3339(),
        "priority":      priority,
        "rule":          format!("kernelradar.{}", alert.detector),
        "output":        alert.title,
        "output_fields": fields,
        "source":        "syscall",
        "tags":          ["kernelradar", alert.detector.clone()],
        "hostname":      hostname,
    });

    obj.to_string()
}
