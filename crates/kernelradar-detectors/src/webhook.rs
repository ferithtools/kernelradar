// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Ferith Tools
//
// Part of the kernelradar project - Linux kernel anomaly detection via BPF.
// See LICENSE for terms.

/// Webhook output - HTTP POST per alert.
///
/// Async fire-and-forget: each alert spawns a non-blocking POST.
/// On failure: log and drop. We never let an HTTP backend slow down
/// the kernel hot path.
use std::sync::OnceLock;
use std::time::Duration;

use kernelradar_core::alert::Alert;

#[derive(Debug, Clone)]
pub struct WebhookConfig {
    pub enabled: bool,
    pub url: String,
    pub timeout_secs: u64,
    /// Optional bearer token / shared secret in `Authorization: Bearer <X>`.
    pub auth_token: Option<String>,
    /// If true, only forward Severity ≥ Alert. Otherwise forward all.
    pub severity_filter_alert_or_higher: bool,
}

impl Default for WebhookConfig {
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

static CONFIG: OnceLock<WebhookConfig> = OnceLock::new();
static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

pub fn init(config: WebhookConfig) {
    if !config.enabled || config.url.is_empty() {
        return;
    }
    // Disable redirect-following entirely. Default reqwest policy
    // chases up to 10 redirects, which lets a compromised collector
    // (or a misconfigured DNS record) issue 302 -> 169.254.169.254
    // and exfiltrate alert payloads to cloud-metadata or any
    // private-network destination. The SSRF guard in
    // kernelradar_core::config::webhook_url_security_issue runs at
    // config-validate time and only checks the configured URL; it
    // cannot vet runtime redirect targets. Webhook output is a
    // direct POST to a known endpoint, so redirects have no
    // legitimate use here.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(config.timeout_secs))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("kernelradar-webhook/0.1")
        .build()
        .expect("reqwest client");
    let _ = CLIENT.set(client);
    let _ = CONFIG.set(config);
}

/// Submit an alert to the configured webhook (no-op if disabled).
pub fn submit(alert: &Alert) {
    let cfg = match CONFIG.get() {
        Some(c) => c,
        None => return,
    };
    let client = match CLIENT.get() {
        Some(c) => c,
        None => return,
    };

    if cfg.severity_filter_alert_or_higher
        && (alert.severity as u8) < (kernelradar_core::event::Severity::Alert as u8)
    {
        return;
    }

    let payload = match serde_json::to_string(alert) {
        Ok(s) => s,
        Err(_) => return,
    };
    let url = cfg.url.clone();
    let auth = cfg.auth_token.clone();
    let client = client.clone();

    tokio::spawn(async move {
        let mut req = client
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(payload);
        if let Some(t) = auth {
            req = req.header(reqwest::header::AUTHORIZATION, format!("Bearer {t}"));
        }
        let safe_url = sanitize_url(&url);
        match req.send().await {
            Ok(resp) if resp.status().is_success() => { /* ok */ }
            Ok(resp) => {
                tracing::warn!(status = %resp.status(),
                                url = %safe_url,
                                "webhook: non-2xx response");
            }
            Err(e) => {
                tracing::warn!(error = %e, url = %safe_url,
                                "webhook: send failed");
            }
        }
    });
}

/// Strip path/query/fragment from a webhook URL for logging.
/// Slack and Telegram embed bot tokens in the URL path; we must not
/// leak them through journald / log aggregation. Returns just the
/// scheme + host[:port], or "<malformed>" if the URL won't parse.
fn sanitize_url(url: &str) -> String {
    match reqwest::Url::parse(url) {
        Ok(u) => {
            let mut s = format!("{}://{}", u.scheme(), u.host_str().unwrap_or("?"));
            if let Some(port) = u.port() {
                s.push_str(&format!(":{port}"));
            }
            s
        }
        Err(_) => "<malformed>".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_url_strips_slack_token() {
        let s = sanitize_url("https://hooks.slack.com/services/T0001/B0001/SECRET_TOKEN_PAYLOAD");
        assert_eq!(s, "https://hooks.slack.com");
    }

    #[test]
    fn sanitize_url_strips_telegram_bot_token() {
        let s = sanitize_url("https://api.telegram.org/bot123456:ABCDEF_xyz/sendMessage");
        assert_eq!(s, "https://api.telegram.org");
    }

    #[test]
    fn sanitize_url_keeps_port() {
        let s = sanitize_url("https://internal-relay.example.com:8443/hook?token=abc");
        assert_eq!(s, "https://internal-relay.example.com:8443");
    }

    #[test]
    fn sanitize_url_handles_malformed_input() {
        assert_eq!(sanitize_url("not a url"), "<malformed>");
        assert_eq!(sanitize_url(""), "<malformed>");
    }
}
