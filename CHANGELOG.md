# Changelog

All notable changes to this project are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

Post-publication polish on top of v0.1.0; no new features, no API
changes a downstream user can observe.

### Changed - performance

- Detector ring buffers are now driven by `tokio::io::unix::AsyncFd`
  registered against the BPF ring's file descriptor. Tasks wake on
  epoll-ready instead of polling every 100 ms, dropping the
  end-to-end alert latency floor from "up to 100 ms" to a few
  microseconds and removing the idle wake-up cost on otherwise-quiet
  daemons.
- Detector identifiers now flow through the alert pipeline as
  `Cow<'static, str>` (always `Cow::Borrowed` for regular alerts,
  `Cow::Owned` only for the synthetic `*.anomaly` / `*.burst`
  markers). Saves three `String` allocations per emitted alert in
  `make_alert`, the rate limiter key, and the metrics key.

### Changed - internals

- Detector load + attach + ring-buffer drive collapsed into a shared
  `runtime::TracepointDetector` builder. Each individual detector
  module shrank by ~30 lines; the per-detector dance of `fs::read +
  verify_bpf + Ebpf::load + pin kr_stats + try_into TracePoint +
  attach + RingBuf::try_from + polling loop` now lives in exactly
  one place.
- CLI bootstrap (webhook init, Prometheus init, rate limiter,
  baseline, integrity strict mode, hourly summary spawn, preflight
  checks, LSM install) extracted from `main.rs` into a dedicated
  `bootstrap` module. `main.rs` reads as the CLI control flow now,
  not as a long sequence of subsystem initialisers.

### Fixed

- Two detectors (`fim`, `cred`) reconstructed the path payload from
  `[u64; 4]` via `mem::transmute` to `[u8; 32]`. Replaced with a
  word-by-word `to_ne_bytes()` reassembly - same native-endianness
  semantics, no `unsafe` needed.
- `build.rs` no longer panics on a backdated build host: the
  `SystemTime::now().duration_since(UNIX_EPOCH).unwrap()` is now
  `unwrap_or(0)`, and the SHA-256 word load avoids
  `try_into().unwrap()` by indexing the 64-byte chunk directly.
- Rust 1.95 turned several clippy warnings into hard errors under
  `-D warnings` (`match_like_matches_macro`, `unnecessary_map_or`,
  `io_other_error`, `needless_borrow`, `needless_return`,
  `dead_code`, `items_after_test_module`, `unused_imports`). All
  are now behaviour-preserving rewrites.

### Documentation

- README: dropped the bilingual EN+RU layout in favour of an
  English-only canonical version.
- README + `docs/architecture.md`: unified the build instructions
  on `make` (matches CONTRIBUTING.md). Removed the long-standing
  false claim that BPF objects were committed as pre-compiled `.o`
  files.
- `docs/architecture.md` rewritten under v0.1.0 reality: eight
  detectors instead of four, accurate kernel hooks, integrity
  check, LSM enforcement, rate limiter, baseline, AsyncFd-driven
  ring buffer, real TOML config schema.
- All em-dashes (U+2014) replaced with ASCII hyphens.

### Infrastructure

- Removed `rc/*.png` (1.3 MB of branding assets) from the source
  tree; logos are distributed via GitHub social-preview /
  release-asset settings instead.

The next planned **release** is the **v0.1.x** patch series (Q2
2026) covering `--dry-run` / `--audit-only` enforcement, `kr_stats`
counters in the Prometheus exporter, IPv6 destination CIDR
allowlist, per-detector documentation, the email-integration
recipe, and the first `.deb` package.

## [v0.1.0] - 2026-05-07

First public preview. The full feature surface is implemented and
production-tested on a Debian 12 / kernel 6.13.9 host; the GitHub
release tarball is pinned by SHA-256 in
[`release-checksums/v0.1.0/`](release-checksums/v0.1.0/).

### Added - eight in-tree detectors

- **privesc** - `setuid(0)` / `setgid(0)` from non-root processes.
- **bpf-loader** - `BPF_PROG_LOAD` from non-allowlisted processes.
- **container** - `unshare()` / `setns()` namespace-escape patterns.
- **kmod** - `init_module` / `finit_module` (kernel-module rootkits).
- **fim** - write-mode `openat()` against sensitive paths
  (`/etc/passwd`, `/etc/shadow`, `~/.ssh/`, `/etc/cron.*/`,
  `/etc/systemd/`, `/etc/init.d/`, `/etc/pam.d/`).
- **network** - outbound `connect()` to public IPv4, with severity
  bumping for known reverse-shell ports and a destination CIDR
  allowlist that suppresses connections to whitelisted ranges before
  process attribution.
- **injection** - `ptrace(PTRACE_ATTACH/SEIZE/POKE*)` and
  `process_vm_writev()`.
- **cred** - read-mode `openat()` against credential files (shadow,
  sudoers, ssh private keys, browser cookies).

### Added - observability and integrations

- Structured journald output with custom fields (`DETECTOR=`,
  `SEVERITY=`, `PID=`, `UID=`, `COMM=`, `CORRELATION_ID=`).
- Prometheus exporter on `127.0.0.1:9101` (off by default; chosen
  to avoid colliding with `node_exporter`).
- HTTP webhook with bearer-token auth, severity filter, and a
  sanitised URL field in failure logs (Slack / Telegram path-token
  leak prevented).
- Falco-compatible JSON output for SIEMs already ingesting Falco.
- Recipes in [`docs/integrations/`](docs/integrations/) for Wazuh,
  Prometheus, Loki / Vector / Fluent Bit, Slack and Telegram, and
  Falco-compatible aggregators.

### Added - engine

- Adaptive baseline with per-(detector, comm, hour-of-day) EWMA
  buckets and σ-based anomaly scoring.
- Rate limiting, burst detection, and exponential back-off.
- BPF integrity check via build-time SHA-256 with `[integrity]
  strict_mode` to harden refusal-to-load.
- Per-detector `kr_stats` counters (observed / dropped) pinned at
  `/sys/fs/bpf/kr_stats_<det>` for external metric collectors.
- LSM enforcement modes (off by default): `selfprotect` (block kill
  of the daemon's own PID), `enforce_bpf` (block `BPF_PROG_LOAD`
  from non-allowlisted comms), `enforce_kmod` (block `kmod` loads
  from non-allowlisted comms - a process allowlist, not a signature
  check). All three integrity-checked at load.

### Added - operability

- TOML configuration with hot-reload via `SIGHUP`.
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
- In-repo `release-checksums/<ver>/` SHA-256 pin so any consumer
  can verify the GitHub-served archive against a value committed
  at release time.

### Security - pre-publication audit

A full code-review pass before publication surfaced and fixed:

- Integrity-check `strict_mode` configuration option that refuses
  to load any BPF object on hash mismatch.
- LSM enforcement objects are hash-verified at load (previously
  accepted any bytes silently).
- `kr_stats` observed / dropped counters are now populated by every
  detector (previously only the privesc detector wrote them; the
  other seven were silently zero).
- Webhook URLs in failure logs are sanitised to `scheme://host:port`,
  preventing Slack / Telegram path-token leaks via journald.
- `/proc/<pid>/exe` lookup after a BPF event now re-verifies
  `/proc/<pid>/comm` against the BPF-captured value, closing a PID
  reuse + `execve` race.
- Allowlist matching uses exact-equality, not `comm.starts_with`,
  so an `sshd` allowlist no longer covers a hypothetical
  `sshooly-rev-shell`. For prefix semantics, use a regex.
- Adaptive baseline pair store is now bounded: `pairs_max` (default
  10 000) caps total entries, and pairs older than
  `evict_age_hours` (default 7 days) are dropped on overflow.
  Hostile flooding or short-lived container churn no longer grows
  the table without bound.
- Network detector's multicast filter now correctly excludes the
  full multicast /4 + reserved /4 (`b0 >= 224`) instead of only
  the `b0 == 224` octet.
- Shutdown waits for every detector cleanly instead of dropping
  all but the first handle.
- `/proc/mounts` longest-prefix match now sorts mountpoints by
  length descending (previously first-match always picked `/`).
- `baseline.json` is `chmod 0640` after the atomic rename, since
  its content is a system fingerprint.
- Global mutexes recover from poisoning via
  `.unwrap_or_else(|e| e.into_inner())`; a panic on one thread no
  longer cascades daemon-wide on every subsequent lock.

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
  not observed in v0.1. Targeted for the v0.1.x patch series.
- LSM enforcement requires `lsm=...,bpf` in the kernel `cmdline`;
  on stock distributions the daemon falls back to observe-only
  with a warning.
- `kr_stats` counters are read-only via `bpftool map dump pinned`;
  the Prometheus exporter does not yet surface them. Targeted for
  the v0.1.x patch series.
- Process attribution (`/proc/<pid>/exe` + `comm` re-check) closes
  most of the TOCTOU window but not all of it for processes that
  `execve` to a binary sharing the first 15 comm bytes
  (`TASK_COMM_LEN`). Treated as a known accuracy bound, not a
  scheduled fix - kernel-side path capture would close this.

### Compatibility

- Linux kernel 6.1+ (older may work but is not tested).
- libbpf 0.8+ via Aya 0.13 (Rust BPF userspace).
- Rust toolchain stable.
- Tested distributions: Debian 12.

## Authoring conventions

- Sections per release: **Added**, **Changed**, **Deprecated**,
  **Removed**, **Fixed**, **Security**.
- Date format: `YYYY-MM-DD`.
- Link to commits / PRs / issues from the bullet text, not from
  prose, so changelog entries remain readable in plain text.
