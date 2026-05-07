# Falco compatibility

kernelradar can emit alerts in [Falco's JSON output schema](https://falco.org/docs/outputs/formatting/)
so existing Falco pipelines (Sysdig agents, Falco Sidekick, etc.) can
consume kernelradar without changes.

## Enable Falco mode

Either via CLI:

```bash
kernelradar --format=falco daemon
```

…or in `/etc/kernelradar/config.toml`:

```toml
[global]
output_format = "falco"
```

Tracing diagnostic logs are routed to **stderr** in this mode, so the
stdout stream contains only Falco-shaped JSON. You can pipe it into
Falco-aware tooling directly.

## Field mapping

| Falco field            | Source                                |
|------------------------|---------------------------------------|
| `time`                 | `alert.timestamp` (RFC 3339)          |
| `priority`             | mapping below                         |
| `rule`                 | `kernelradar.<detector>`              |
| `output`               | `alert.title`                         |
| `output_fields`        | `proc.pid`, `proc.name`, `user.uid` + `kernelradar.*` |
| `source`               | `"syscall"`                           |
| `tags`                 | `["kernelradar", "<detector>"]`       |
| `hostname`             | `/etc/hostname`                       |

## Severity → priority

```
kernelradar Severity   →   Falco priority
Critical               →   Critical
Alert                  →   Error
Warning                →   Warning
Info                   →   Informational
```

## Sample line

```json
{
  "time": "2026-05-06T10:01:00.542Z",
  "priority": "Critical",
  "rule": "kernelradar.fim",
  "output": "write open to /etc/sudoers.d/foo by bash",
  "output_fields": {
    "proc.pid":   4158704,
    "proc.name":  "bash",
    "user.uid":   0,
    "kernelradar.detector":       "fim",
    "kernelradar.event_type":     1,
    "kernelradar.correlation_id": "01900000-...",
    "kernelradar.context":        {"path": "/etc/sudoers.d/foo", "rule": "/etc/sudoers.d/"}
  },
  "source":   "syscall",
  "tags":     ["kernelradar", "fim"],
  "hostname": "host01"
}
```

## What kernelradar does NOT emit

- No mutex on `proc.aname[N]`, `proc.cmdline`, etc. - kernelradar tracks
  `comm` (16-byte truncated process name) and `exe` (resolved from
  `/proc/PID/exe`). The full ancestor chain is out of scope today.
- No file FD ancestry; FIM events have the path only.

For pipelines that need richer process metadata, run Falco alongside
kernelradar - they complement each other.
