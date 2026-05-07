# Changelog

All notable changes to this project are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

— Tracked items live in [`k-radar_backlog.md`](k-radar_backlog.md).
The next planned release is the **v0.1.x** patch series (Q2 2026)
covering `--dry-run`/`--audit-only` enforcement, `kr_stats`
counters in the Prometheus exporter, IPv6 destination CIDR
allowlist, per-detector documentation, the email-integration
recipe, and the first `.deb` package.

## [v0.1.0] — 2026-05-07

First public preview. The full feature surface is implemented and
production-tested on a Debian 12 / kernel 6.13.9 host; there is no
GitHub release artifact yet beyond what's pinned in
[`release-checksums/v0.1.0/`](release-checksums/v0.1.0/).

### Added — eight in-tree detectors

- **privesc** — `setuid(0)` / `setgid(0)` from non-root processes.
- **bpf-loader** — `BPF_PROG_LOAD` from non-allowlisted processes.
- **container** — `unshare()` / `setns()` namespace-escape patterns.
- **kmod** — `init_module` / `finit_module` (kernel-module rootkits).
- **fim** — write-mode `openat()` against sensitive paths
  (`/etc/passwd`, `/etc/shadow`, `~/.ssh/`, `/etc/cron.*/`,
  `/etc/systemd/`, `/etc/init.d/`, `/etc/pam.d/`).
- **network** — outbound `connect()` to public IPv4, with severity
  bumping for known reverse-shell ports and (F-1) a destination CIDR
  allowlist that suppresses connections to whitelisted ranges before
  process attribution.
- **injection** — `ptrace(PTRACE_ATTACH/SEIZE/POKE*)` and
  `process_vm_writev()`.
- **cred** — read-mode `openat()` against credential files (shadow,
  sudoers, ssh private keys, browser cookies).

### Added — observability + integrations

- Structured journald output with custom fields (`DETECTOR=`,
  `SEVERITY=`, `PID=`, `UID=`, `COMM=`, `CORRELATION_ID=`).
- Prometheus exporter on `127.0.0.1:9101` (off by default; chosen
  to avoid colliding with `node_exporter`).
- HTTP webhook with bearer-token auth, severity filter, and a
  sanitised URL field in failure logs (Slack / Telegram path-token
  leak prevented — H-4).
- Falco-compatible JSON output for SIEMs already ingesting Falco.
- Recipes in [`docs/integrations/`](docs/integrations/) for Wazuh,
  Prometheus, Loki / Vector / Fluent Bit, Slack & Telegram, and
  Falco-compatible aggregators.

### Added — engine

- Adaptive baseline with per-(detector, comm, hour-of-day) EWMA
  buckets and σ-based anomaly scoring (T-4).
- Rate limiting + burst detection + exponential back-off (T-3).
- BPF integrity check via build-time SHA-256 with `[integrity]
  strict_mode` to harden refusal-to-load (H-1).
- Per-detector `kr_stats` counters (observed / dropped) pinned at
  `/sys/fs/bpf/kr_stats_<det>` for external metric collectors (H-3).
- LSM enforcement modes (off by default): `selfprotect` (block kill
  of the daemon's own PID, T-6.4), `enforce_bpf` (block
  `BPF_PROG_LOAD` from non-allowlisted comms), `enforce_kmod` (block
  `kmod` loads from non-allowlisted comms — process allowlist, not a
  signature check). All three integrity-checked at load (H-2).

### Added — operability

- TOML configuration with hot-reload via `SIGHUP` (T-2.6).
- `kernelradar config-cmd validate|show|example` for config
  troubleshooting.
- `kernelradar baseline show|status|reset` for the adaptive model.
- `kernelradar status` for cumulative alert / burst / anomaly
  counters.
- systemd unit with capability minimisation (`CAP_BPF +
  CAP_PERFMON + CAP_SYS_RESOURCE + CAP_SYS_ADMIN`), filesystem
  hardening, and `MemoryMax=256M`.
- `kernelradar --version` carries the git SHA + build date so
  operators can pin a version reproducibly.
- `make release-tarball` produces a self-contained installable
  bundle plus inner-file SHA-256s.
- `release-checksums/<ver>/` in-repo SHA-256 pin so any consumer
  can verify the GitHub-served archive against a value committed
  at release time (T-15.1, T-15.2).

### Security — pre-publication audit

A full code-review pass surfaced and fixed:

- **H-1** — integrity-check `strict_mode` config to refuse loading
  on hash mismatch.
- **H-2** — LSM enforcement objects now hash-verified at load (was
  accepting any bytes silently).
- **H-3** — `kr_stats` counters were only populated by the
  `privesc` detector; the other seven were silently zero.
- **H-4** — webhook URL fully logged on failure leaked Slack /
  Telegram path-tokens via journald; now sanitised to
  scheme+host+port only.
- **M-1** — `/proc/<pid>/exe` lookup post-event raced PID reuse
  and `execve`; now verified against `/proc/<pid>/comm` matching
  the BPF-captured value.
- **M-2** — allowlist prefix-match (`comm.starts_with(entry)`) let
  an `sshd` allowlist cover an `sshooly-rev-shell`. Removed; use
  regex `/^prefix.*/` for prefix semantics.
- **M-3** — `Baseline::pairs` HashMap had no eviction, growing
  unbounded with per-(detector, comm) pairs from short-lived
  containers or hostile flooding. Capped at `pairs_max` (default
  10 000); pairs older than `evict_age_hours` (default 7 days)
  are dropped on overflow.
- **M-4** — network-detector multicast filter checked `b0 == 224`
  (one /8) instead of `b0 >= 224` (multicast /4 + reserved /4),
  letting addresses 225/8–255/8 through as public IPv4.
- **M-5** — "wait for any handle" shutdown actually awaited only
  `handles[0]` and dropped the rest, silently cancelling
  surviving detectors. Now waits for every detector cleanly.
- **M-6** — `/proc/mounts` longest-prefix match used first-match
  semantics; `/` always won. Now sorts by mountpoint length
  descending.
- **M-7** — `baseline.json` wrote with default `umask` (often
  `0644`); the file's content is a system fingerprint. Now
  `chmod 0640` after the atomic rename.
- **M-8** — global mutexes used `.expect("…")`; a panic on one
  thread cascaded daemon-wide on every subsequent lock. Replaced
  with `.unwrap_or_else(|e| e.into_inner())` recovery.

### Performance (measured)

On the lowest-spec officially-supported hardware (Celeron J4125 @
2.0 GHz, 8 GB DDR4, kernel 6.13.9):

- Sustained event rate: **321 000 events/sec** (BPF tracepoint,
  kernel-side).
- Idle resident memory: **65–80 MB**.
- Peak RSS under a 100 000-event burst: **136 MB**, returning to
  the 80 MB baseline (no leak).
- CPU at idle: **< 0.1 %** of one core.
- CPU under sustained burst: **~28 %** of one core.
- Graceful shutdown (`SIGTERM` → all 12 BPF programs detached):
  **641 ms**.

Methodology and per-stage breakdown live in
[`docs/performance.md`](docs/performance.md).

### Known limitations

- The network detector is IPv4-only; the kernel-side BPF probe
  drops anything that isn't `AF_INET`, so IPv6 connections are
  not observed in v0.1. Tracked as T-12.4 (Q2 2026).
- LSM enforcement requires `lsm=...,bpf` in the kernel `cmdline`;
  on stock distributions the daemon falls back to observe-only
  with a warning.
- `kr_stats` counters are read-only via `bpftool map dump pinned`;
  the Prometheus exporter does not yet surface them. Tracked as
  T-12.3 / F-3 (Q2 2026).
- Process attribution (`/proc/<pid>/exe` + `comm` re-check) closes
  most of the TOCTOU window but not all of it for processes that
  `execve` to a binary sharing the first 15 comm bytes
  (TASK_COMM_LEN). Tracked as a known accuracy bound, not a
  scheduled fix — kernel-side path capture would close this.

### Compatibility

- Linux kernel 6.1+ (older may work but is not tested).
- libbpf 0.8+ via Aya 0.13 (Rust BPF userspace).
- Rust toolchain stable.
- Tested distributions: Debian 12.

## Authoring conventions

- Sections per release: **Added**, **Changed**, **Deprecated**,
  **Removed**, **Fixed**, **Security**.
- Date format: `YYYY-MM-DD`.
- Reference task ids from
  [`k-radar_backlog.md`](k-radar_backlog.md) (`T-N`, `H-N`, `M-N`,
  `F-N`) where applicable.
- Link to commits / PRs / issues from the bullet text, not from
  prose, so changelog entries remain readable in plain text.
