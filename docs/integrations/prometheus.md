# Prometheus + Alertmanager

## Enable the endpoint

```toml
# /etc/kernelradar/config.toml
[prometheus]
enabled     = true
listen_addr = "127.0.0.1:9101"
```

> **Why 9101, not 9100?** Port 9100 is the de-facto standard for
> `node_exporter` on every Linux host running the prometheus stack.
> Binding kernelradar to 9100 silently collides with it and causes
> confusing scrape failures. 9101 is free by convention.

Then:

```bash
sudo systemctl restart kernelradar
curl http://127.0.0.1:9101/metrics
```

## Exposed series

```
# HELP kernelradar_alerts_total Number of alerts emitted
# TYPE kernelradar_alerts_total counter
kernelradar_alerts_total{detector="privesc",  severity="ALERT"} 23
kernelradar_alerts_total{detector="cred",     severity="CRITICAL"} 4
kernelradar_alerts_total{detector="container",severity="WARNING"} 117

# HELP kernelradar_bursts_total Bursts of repeated alerts
# TYPE kernelradar_bursts_total counter
kernelradar_bursts_total{detector="privesc"} 2

# HELP kernelradar_anomalies_total Statistical anomalies
# TYPE kernelradar_anomalies_total counter
kernelradar_anomalies_total{detector="privesc"} 5

# HELP kernelradar_build_info kernelradar build info (always 1)
# TYPE kernelradar_build_info gauge
kernelradar_build_info{version="0.1.3"} 1
```

## Prometheus scrape config

```yaml
# /etc/prometheus/prometheus.yml
scrape_configs:
  - job_name: kernelradar
    static_configs:
      - targets: ['10.0.0.1:9101']
    scrape_interval: 30s
```

## Alertmanager rules

```yaml
groups:
- name: kernelradar
  rules:
    - alert: KernelradarCriticalAlert
      expr: increase(kernelradar_alerts_total{severity="CRITICAL"}[5m]) > 0
      for: 0m
      labels: { severity: page }
      annotations:
        summary: "kernelradar reported a CRITICAL alert"
        description: "{{ $labels.detector }} fired CRITICAL on {{ $labels.instance }}"

    - alert: KernelradarBurstStorm
      expr: increase(kernelradar_bursts_total[10m]) > 3
      for: 5m
      labels: { severity: page }
      annotations:
        summary: "Multiple alert bursts in 10 minutes"

    - alert: KernelradarAnomalyTrend
      expr: increase(kernelradar_anomalies_total[1h]) > 10
      for: 15m
      labels: { severity: warn }
      annotations:
        summary: "kernelradar is detecting unusual baseline drift"
```

## Health check

```
GET /healthz   →   200 OK
                   ok
```

Use it in load balancers or external monitoring.
