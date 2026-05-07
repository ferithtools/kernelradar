# kernelradar — Logging guide

kernelradar emits two kinds of records:

| Kind | Source | Severity range |
|------|--------|----------------|
| **Alert** | A detector caught a suspicious event | INFO / WARN / ERROR |
| **Diagnostic** | Lifecycle, attach/detach, internal errors | INFO / WARN / ERROR |

Both flow through the same `tracing` pipeline. The output sink is
selected at startup via `--format`.

---

## Output formats

### `--format=auto` (default)

- Under systemd → `journald`
- Otherwise → `plain`

Detection: `JOURNAL_STREAM` or `INVOCATION_ID` env vars set.

### `--format=plain`

Human-readable text on stdout.

```
[ALERT] 2026-05-06T10:01:00.542Z | container | pid=4149716 uid=1000 \
    comm=unshare | unshare(NEWUSER) by unshare | cid=01900000-...
          └ exe=/usr/bin/unshare
          └ {"flags":"NEWUSER","syscall":"unshare"}
```

### `--format=json`

One JSON object per line, on stdout. Suitable for `| jq`, file logging,
or shipping to ELK / Loki / Vector.

```json
{"id":1,"correlation_id":"01900000-...","timestamp":"2026-05-06T10:01:00Z",
 "severity":"Warning","detector":"container","title":"unshare(NEWUSER)",
 "pid":4149716,"uid":1000,"comm":"unshare","context":{...}}
```

### `--format=journald`

Structured fields shipped directly to systemd journal. Each tracing
field becomes a journal entry field.

```
$ journalctl -t kernelradar -o json | jq 'select(.DETECTOR == "privesc")' | head
{
  "DETECTOR": "privesc",
  "SEVERITY": "ALERT",
  "PID": "4149674",
  "UID": "1000",
  "COMM": "python3",
  "CORRELATION_ID": "01900000-...",
  "MESSAGE": "setuid(0) — uid 1000 → 0 by python3",
  ...
}
```

This is the recommended format for production systemd installations.

---

## Querying alerts

### journalctl (default systemd setup)

```bash
# Live tail of all kernelradar output
journalctl -t kernelradar -f

# Only alerts, last hour
journalctl -t kernelradar --since '1 hour ago' \
    PRIORITY=4..3

# All privesc alerts as JSON
journalctl -t kernelradar -o json | jq 'select(.DETECTOR == "privesc")'

# Count alerts per detector for the past day
journalctl -t kernelradar --since '1 day ago' -o json |
    jq -r 'select(.DETECTOR != null) | .DETECTOR' | sort | uniq -c
```

### kernelradar status

```bash
# In-process cumulative counters (since daemon start)
kernelradar status
```

---

## Per-detector log levels

`RUST_LOG` is the standard mechanism. kernelradar honours it via the
`tracing-subscriber` `EnvFilter`.

```bash
# Default — only diagnostic INFO from kernelradar crates
RUST_LOG=kernelradar=info kernelradar daemon

# Increase privesc verbosity, silence kmod
RUST_LOG=kernelradar=info,kernelradar_detectors::privesc=debug,kernelradar_detectors::kmod=warn \
    kernelradar daemon

# Only alerts, suppress diagnostic chatter
RUST_LOG=warn,kernelradar.alert=info kernelradar daemon
```

In a systemd unit:

```ini
[Service]
Environment=RUST_LOG=kernelradar=info,kernelradar.alert=info
```

---

## Hourly summary

When running in daemon mode, kernelradar emits a summary every hour
into the `kernelradar.summary` target:

```
hourly summary: 23 alerts (privesc/Alert=2 fim/Critical=1 network/Warning=20)
```

Suppress with `RUST_LOG=...,kernelradar.summary=off`.

---

## Log rotation

### journald (recommended)

systemd journald rotates automatically. Configure persistence and
limits in `/etc/systemd/journald.conf`:

```ini
[Journal]
Storage=persistent
SystemMaxUse=2G
SystemKeepFree=500M
SystemMaxFileSize=64M
MaxRetentionSec=14day
```

### File logging (non-systemd)

If you redirect kernelradar to a file (`> /var/log/kernelradar.json`),
use `logrotate`. Drop this into `/etc/logrotate.d/kernelradar`:

```
/var/log/kernelradar.json {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
```

`copytruncate` is important: kernelradar holds the file descriptor
open, so renaming would orphan it. `copytruncate` truncates in place.

---

## Correlation IDs

Every alert carries a UUID v7 `correlation_id`:

- **Sortable**: lexicographic order matches chronological order
- **Unique**: across instances and reboots
- **Compact**: 36-char string

Use it to:

```bash
# Find a specific alert and its surrounding context
journalctl -t kernelradar | grep 01900000-12ab-...

# Group multi-step attack patterns:
# e.g., a single intrusion may produce
#   privesc cid=01900000-aaaa
#   bpf-loader cid=01900000-bbbb
#   network cid=01900000-cccc
# all within seconds — chain them via timestamps + correlation_id sort.
```

A future feature will tag related alerts with the same `attack_id`
when temporal/spatial clustering identifies them as one incident.
