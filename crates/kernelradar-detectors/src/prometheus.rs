// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Ferith Tools
//
// Part of the kernelradar project — Linux kernel anomaly detection via BPF.
// See LICENSE for terms.

/// Prometheus /metrics endpoint.
///
/// Tiny HTTP server (tokio TcpListener — no external HTTP framework).
/// Serves the Prometheus text exposition format on
///   GET /metrics
///   GET /healthz
/// All other paths → 404.
///
/// Renders all counters from `metrics::*` plus daemon health gauges.
use std::sync::OnceLock;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::metrics::{cumulative_anomalies, cumulative_bursts, cumulative_totals};

#[derive(Debug, Clone)]
pub struct PromConfig {
    pub enabled: bool,
    pub listen_addr: String,
}

impl Default for PromConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_addr: "127.0.0.1:9100".into(),
        }
    }
}

static CONFIG: OnceLock<PromConfig> = OnceLock::new();

pub fn init(config: PromConfig) {
    let _ = CONFIG.set(config);
}

pub fn spawn_server() {
    let cfg = match CONFIG.get() {
        Some(c) => c,
        None => return,
    };
    if !cfg.enabled {
        return;
    }

    let addr = cfg.listen_addr.clone();
    tokio::spawn(async move {
        let listener = match TcpListener::bind(&addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(error = %e, addr = %addr,
                                 "prometheus: bind failed");
                return;
            }
        };
        tracing::info!(addr = %addr, "prometheus: serving /metrics");

        loop {
            let (mut stream, peer) = match listener.accept().await {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!("prometheus: accept failed: {e}");
                    continue;
                }
            };

            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let n = match stream.read(&mut buf).await {
                    Ok(n) if n > 0 => n,
                    _ => return,
                };
                let req = String::from_utf8_lossy(&buf[..n]);
                let path = req.split_whitespace().nth(1).unwrap_or("");

                let resp = match path {
                    "/metrics" => {
                        http_response(200, "text/plain; version=0.0.4", &render_metrics())
                    }
                    "/healthz" => http_response(200, "text/plain", "ok\n"),
                    _ => http_response(404, "text/plain", "not found\n"),
                };
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = peer; // suppress unused
            });
        }
    });
}

fn http_response(code: u16, ctype: &str, body: &str) -> String {
    let status = match code {
        200 => "200 OK",
        404 => "404 Not Found",
        _ => "500 Internal Server Error",
    };
    format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: {ctype}\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        len = body.len(),
    )
}

fn render_metrics() -> String {
    let mut out = String::new();

    // ── Alerts emitted ──
    out.push_str("# HELP kernelradar_alerts_total Number of alerts emitted\n");
    out.push_str("# TYPE kernelradar_alerts_total counter\n");
    for ((det, sev), n) in cumulative_totals() {
        out.push_str(&format!(
            "kernelradar_alerts_total{{detector=\"{det}\",severity=\"{sev}\"}} {n}\n"
        ));
    }

    // ── Bursts ──
    out.push_str("# HELP kernelradar_bursts_total Bursts of repeated alerts\n");
    out.push_str("# TYPE kernelradar_bursts_total counter\n");
    for (det, n) in cumulative_bursts() {
        out.push_str(&format!(
            "kernelradar_bursts_total{{detector=\"{det}\"}} {n}\n"
        ));
    }

    // ── Anomalies ──
    out.push_str("# HELP kernelradar_anomalies_total Statistical anomalies\n");
    out.push_str("# TYPE kernelradar_anomalies_total counter\n");
    for (det, n) in cumulative_anomalies() {
        out.push_str(&format!(
            "kernelradar_anomalies_total{{detector=\"{det}\"}} {n}\n"
        ));
    }

    // ── Build info ──
    out.push_str("# HELP kernelradar_build_info kernelradar build info (always 1)\n");
    out.push_str("# TYPE kernelradar_build_info gauge\n");
    out.push_str(&format!(
        "kernelradar_build_info{{version=\"{}\"}} 1\n",
        env!("CARGO_PKG_VERSION"),
    ));

    out
}
