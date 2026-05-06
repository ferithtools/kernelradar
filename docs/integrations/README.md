# kernelradar — Integrations

kernelradar is built around four output channels. Pick the one(s) that
fit your stack:

| Channel    | When to use                          | Setup                                 |
|------------|---------------------------------------|---------------------------------------|
| journald   | Anything systemd-based                | `--format=journald` (default w/ unit) |
| Webhook    | Slack, Telegram, custom SIEM          | `[webhook]` in config                 |
| Prometheus | Metrics dashboards, alertmanager      | `[prometheus]` in config              |
| Falco JSON | Falco-compatible pipelines (Sysdig)   | `--format=falco`                      |

Specific guides:

- [Wazuh](wazuh.md)              — ship JSON via Wazuh agent
- [Slack & Telegram](slack-telegram.md) — webhook recipes
- [Loki / Vector / Fluentbit](loki-vector-fluentbit.md) — log shipping
- [Prometheus + Alertmanager](prometheus.md) — metrics monitoring
- [Falco compatibility](falco.md) — output format & schema mapping
