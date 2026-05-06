# Loki / Vector / Fluentbit

kernelradar emits structured logs to journald (default) or stdout
JSON. Any modern log shipper can pick them up.

## Loki via Promtail

```yaml
# /etc/promtail/config.yml
scrape_configs:
  - job_name: kernelradar
    journal:
      max_age: 12h
      labels:
        job: kernelradar
        host: ${HOSTNAME}
      matches: SYSLOG_IDENTIFIER=kernelradar
    relabel_configs:
      - source_labels: ['__journal_f_detector']
        target_label:  detector
      - source_labels: ['__journal_f_severity']
        target_label:  severity
      - source_labels: ['__journal_f_correlation_id']
        target_label:  correlation_id
```

Promtail pulls journald entries with identifier `kernelradar` and
maps the structured fields (F_DETECTOR, F_SEVERITY, F_CORRELATION_ID)
into Loki labels.

Sample LogQL queries:

```logql
{job="kernelradar"}                              # all
{job="kernelradar", severity="Critical"}         # only critical
{detector="cred"} | json | line_format "{{.title}}"
sum by (detector) (count_over_time(
    {job="kernelradar", severity=~"Alert|Critical"}[1h]
))
```

## Vector

```toml
# /etc/vector/vector.toml
[sources.kernelradar]
type     = "journald"
include_units = []
include_matches.SYSLOG_IDENTIFIER = ["kernelradar"]

[transforms.kernelradar_parsed]
type   = "remap"
inputs = ["kernelradar"]
source = '''
.detector       = .F_DETECTOR
.severity       = .F_SEVERITY
.correlation_id = .F_CORRELATION_ID
.context        = parse_json!(.F_CONTEXT) ?? {}
'''

[sinks.loki_out]
type     = "loki"
inputs   = ["kernelradar_parsed"]
endpoint = "http://loki:3100"
labels.detector = "{{ detector }}"
labels.severity = "{{ severity }}"
encoding.codec  = "json"
```

## Fluentbit

```ini
[INPUT]
    Name            systemd
    Tag             kernelradar.*
    Systemd_Filter  SYSLOG_IDENTIFIER=kernelradar
    Read_From_Tail  On

[OUTPUT]
    Name            stdout
    Match           kernelradar.*
```

Replace `[OUTPUT]` with `loki`, `forward`, `es`, `splunk`, etc.
