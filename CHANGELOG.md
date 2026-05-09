# Changelog

All notable changes to this project are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.3] - 2026-05-09

False-positive reduction release. A first-time admin walkthrough on
a busy production host (Debian 12, kernel 6.13.9, with `runc` /
`containerd` running) flagged three runtime sources of noise that
v0.1.2 still produced. No API or configuration changes.

### Fixed - false positives

- **`bpf-loader` no longer flags the daemon's own startup loads.**
  At boot the daemon issues several `BPF_PROG_LOAD` syscalls from
  its tokio worker threads (`comm = "tokio-rt-worker"`). Those
  worker comms do not match the per-detector allowlist, which only
  knows the daemon's binary name, so each load surfaced as
  "unauthorised loader" and the baseline scored the burst as an
  ascending z-score. The detector now reads the daemon's host TGID
  (via `/proc/self/status` `NSpid:`, the same code path
  `selfprotect` already used) and drops events where the calling
  TGID is the daemon itself. Self-events on third-party `BPF_PROG_LOAD`
  callers are unaffected.
- **Path-traversal heuristic in `cred` and `fim` exempts kernel
  virtual filesystems and runtime / scratch areas.** Paths under
  `/sys/`, `/proc/`, `/var/`, `/tmp/`, and `/run/` no longer fire
  the `KR_*_PATH_TRAVERSAL` event type just because they contain a
  literal `/../`. `runc` mounts cgroups with paths like
  `/sys/fs/cgroup/../<container>` and was producing a CRITICAL
  alert per container start. The kernel canonicalises `..` before
  `openat` returns, so a real attacker cannot escape these
  filesystems into a credential path via a literal traversal token
  anyway. Direct opens of `/etc/shadow`, `/etc/sudoers`, `/root/`,
  and `/home/*/.ssh/` still trigger as before.

### Changed - baseline scoring

- **Under-sampled hour buckets observe silently instead of emitting
  a linear-ramp z-score.** Before this release, the
  `min_samples_for_scoring` gate (added in KR-05) routed events for
  buckets with fewer than `min_samples_for_scoring` observations
  into a "no prior data" branch that scored `observed / 0.5`. That
  is not a real z-score - it is `2 * observed`, so two events
  scored "z=4σ", three scored "z=6σ", four scored "z=8σ", which on
  a daemon restart looked like an escalating attack but was just
  the bucket warming up. The branch now returns `None`. The drift-
  train concern that motivated the gate is partially covered by
  the rate-limiter and burst detectors, which do not depend on the
  per-hour bucket; full coverage is on the v0.2 list.

### Documentation - install.sh next-steps

- The bundled `install.sh` finishes with a three-step prompt
  (enable + start, follow alerts, validate config after edits)
  instead of just "Enable + start". Saves a round-trip to the
  README for an admin running `install.sh` from a screenshot of a
  walkthrough.

## [0.1.2] - 2026-05-09

Packaging-only patch on top of v0.1.1. **No source changes** to the
Rust crates or the BPF programs; the binary is byte-for-byte
re-built from the same tree, so the alert pipeline, configuration
schema, and on-wire output are identical to v0.1.1. v0.1.1
supersedes -> v0.1.2 because three packaging issues surfaced during
a fresh-admin walkthrough:

### Fixed - release tarball

- **Outer `.sha256` no longer carries the maintainer's `dist/`
  path.** `sha256sum -c kernelradar-0.1.2-linux-x86_64.tar.gz.sha256`
  now works out of the box. The old form (`<hash>  dist/<name>`)
  forced the verifier to either edit the file or compute the hash
  by hand.
- **File modes inside the tarball are now `0644` for data and
  `0755` only for the binary and `install.sh`.** v0.1.1 was packed
  on a Windows-mounted filesystem in WSL; everything inherited
  `0755`, including `LICENSE`, `README.md`, the `.bpf.o` files, the
  `.service` unit, and `config.toml.example`. The Makefile now
  `chmod`s explicitly before `tar`, so the modes are correct
  regardless of the build host's filesystem.
- **`CHANGELOG.md` is shipped inside the tarball.** Operators no
  longer have to clone the repo or open the GitHub release page to
  see what changed between versions.

### Changed - release binary

- `Cargo.toml`'s `[profile.release]` now uses `strip = "symbols"`
  instead of `strip = "debuginfo"`. The release binary drops from
  ~12 MB to ~5 MB. Trade-off: native crash backtraces lose
  function names. The `--version` output still carries the build
  git SHA, so a debug-friendly binary can be reproduced from
  source for an exact build.

## [0.1.1] - 2026-05-08

Security hardening release on top of v0.1.0. No new features, no
API surface a downstream user can observe; the binary, the
configuration schema, the systemd unit, and the BPF program names
are all source-compatible with v0.1.0.

### Security - second hardening pass (KR-01..26)

A three-round red-team review of the v0.1.0 source closed 26
findings. None of these were ever exploited in the wild; the
project had no production users at v0.1.0 release. The fixes
fall into four buckets:

- **BPF integrity defaults (KR-01, KR-11, KR-12).** Integrity
  strict-mode is on by default; an empty build-time hash is
  treated as a refuse-to-load condition (it previously degraded
  silently). The preflight checker warns when the BPF
  installation directory is not owned by root or is group-/world-
  writable. `config-cmd validate` documents that it does not
  load BPF, only parse the TOML.
- **Webhook SSRF surface (KR-09, KR-15, KR-16, KR-18, KR-23).**
  The webhook URL validator now rejects loopback, RFC1918,
  link-local, IPv4-mapped IPv6 loopback / RFC1918 / metadata,
  inet_aton shortcuts (`https://0x7f000001`, `https://2130706433`),
  and percent-encoded hosts (`https://%6c%6f%63%61%6c%68%6f%73%74`).
  Redirect-following is disabled (`reqwest::redirect::Policy::none`)
  so a malicious 302 response cannot bypass the syntactic check.
  Inflight POSTs are capped by a `tokio::sync::Semaphore` so a
  slow webhook endpoint cannot back up unbounded futures.
- **State-store bounds and eviction (KR-05, KR-07, KR-13, KR-14,
  KR-17, KR-21).** The rate-limiter and dedup tables are bounded
  with sample-of-K approximate LRU eviction (no O(N) min scan
  per insert). The adaptive baseline enforces `pairs_max` with a
  10 % oldest-pair fall-through drop when normal `retain` evicts
  nothing. Anomaly scoring requires a minimum bucket sample count
  before the bucket's mean / sigma is used (defends against
  drift-train attacks during warm-up). LSM allowlist entries
  >15 bytes are refused (`TASK_COMM_LEN` is 16 incl. NUL, so a
  longer entry would never match a real comm). The hostname is
  cached on first use; the correlation-id generator switched to
  UUID v4 so the bytes do not leak host time.
- **Output, parsing, and self-protection hygiene (KR-02, KR-03,
  KR-04, KR-06, KR-08, KR-10, KR-19, KR-20, KR-22, KR-24, KR-25,
  KR-26).** systemd unit splits read-only `bpf/` from writable
  `state/` via separate `BindReadOnlyPaths` / `BindPaths` entries.
  `selfprotect` emits a CRITICAL alert per denied kill so the
  block leaves an audit trail. Path traversal heuristic in `fim`
  / `cred` requires a real parent-directory token (`/../` or
  `/..\0`) so legitimate filenames like `/var/cache/...metadata`
  do not false-positive. Plain-text output escapes ANSI control
  sequences and the full Unicode bidi / format / line-separator
  range so a hostile `comm` cannot rewrite a terminal session.
  The Prometheus exporter has a request timeout and an inflight
  cap. The allowlist pre-compiles its regex set into a single
  DFA (no per-event `Regex::new`). `Config::validate` rejects
  `NaN` / `Inf` / out-of-range values for `alpha`,
  `score_threshold`, `learning_secs`, `save_interval_secs`,
  `pairs_max`, `keys_max`, `window_secs`, `burst_window_secs`,
  and `webhook.timeout_secs`. `selfprotect` resolves the daemon's
  host TGID from `/proc/self/status` `NSpid:` so the LSM block
  stays correct when the daemon is launched in a PID namespace.
  `baseline.json` writes use `O_NOFOLLOW + O_EXCL + O_CREAT` to
  defeat a symlink swap before the atomic rename.

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
- Generated `crates/kernelradar-bpf/include/vmlinux.h` is in
  `.gitignore`; it is dumped from `/sys/kernel/btf/vmlinux` at
  build time and is kernel-version-specific (~3.3 MB).
- CI bumped `actions/checkout` to v5 (Node.js 20 deprecation;
  Node 24 is the supported runtime).

The next planned release is the **v0.1.x** patch series covering
`--dry-run` / `--audit-only` enforcement, `kr_stats` counters in
the Prometheus exporter, IPv6 destination CIDR allowlist,
per-detector documentation, the email-integration recipe, and the
first `.deb` package.

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
- Idle resident memory: **65 to 80 MB**.
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
