# kernelradar: architecture

This document describes how kernelradar v0.1.0 actually works on a
running host. Pair it with [`docs/threat-model.md`](threat-model.md)
(what we defend against) and [`docs/hardening.md`](hardening.md)
(how to harden a real deployment).

## Overview

kernelradar runs a continuous **observe -> attribute -> score -> emit**
loop. BPF is the kernel-side observation layer; a single Rust
userspace process owns everything else.

```
Kernel space                               Userspace (kernelradar daemon)
-------------------------------------     -----------------------------------
  BPF tracepoints + LSM hooks               +-----------------------------+
  +--------------------------+              |  Loader (Aya)               |
  | privesc, bpf-loader,     |              |  - integrity check (SHA-256)|
  | container, kmod, fim,    |  events ---> |  - attach tracepoints/LSM   |
  | network, injection, cred |              |  - pin kr_stats             |
  | + selfprotect/enforce_*  |              +--------------+--------------+
  +--------------------------+                             |
                                          per-detector BPF ring buffer
                                                           |
                                            +--------------v--------------+
                                            |  Per-detector reader        |
                                            |  (tokio + AsyncFd)          |
                                            +--------------+--------------+
                                                           |
                                            +--------------v--------------+
                                            |  Userspace pipeline         |
                                            |  - process attribution      |
                                            |    (/proc/pid/exe + comm    |
                                            |     re-check, TOCTOU mit.)  |
                                            |  - allowlist match          |
                                            |  - adaptive baseline (EWMA, |
                                            |    sigma scoring)           |
                                            |  - rate limit / burst /     |
                                            |    exponential backoff      |
                                            +--------------+--------------+
                                                           |
                                            +--------------v--------------+
                                            |  Output channels            |
                                            |  - journald (default)       |
                                            |  - JSON / Plain / Falco     |
                                            |  - HTTP webhook             |
                                            |  - Prometheus /metrics      |
                                            +-----------------------------+
```

## Crate layout

```
kernelradar/
|-- crates/
|   |-- kernelradar-bpf/        # BPF C sources + libbpf build glue.
|   |                           # Produces .bpf.o under .output/ (gitignored).
|   |
|   |-- kernelradar-core/       # Pure data types: KrEvent, Alert, Severity,
|   |                           # Config. No OS or BPF dependencies; this
|   |                           # crate compiles on any platform.
|   |
|   |-- kernelradar-detectors/  # One module per detector, plus shared
|   |                           # infrastructure (rate limiter, baseline,
|   |                           # integrity check, LSM enforcement,
|   |                           # tracepoint runtime helper).
|   |
|   `-- kernelradar-cli/        # Binary: clap CLI, daemon orchestration,
|                               # SIGHUP-driven config reload, bootstrap.
|
|-- contrib/systemd/            # Hardened systemd unit (CAP minimisation,
|                               # filesystem isolation, MemoryMax=256M).
|
|-- release-checksums/<ver>/    # In-tree SHA-256 pin for the published
|                               # release tarball. Lets a consumer verify
|                               # the GitHub-served archive against a value
|                               # committed at release time.
|
`-- docs/                       # Architecture, threat model, hardening,
                                # logging, performance, integrations.
```

## Detectors and BPF hooks

Eight observation detectors (always loaded in daemon mode unless
disabled in config) plus three opt-in LSM enforcement programs:

| Detector | Type | Kernel hook(s) | Catches |
|---|---|---|---|
| **privesc** | tracepoint | `syscalls/sys_enter_setuid`, `sys_enter_setgid` | `setuid(0)` / `setgid(0)` from non-root |
| **bpf-loader** | tracepoint | `syscalls/sys_enter_bpf` | `BPF_PROG_LOAD` by non-allowlisted comms |
| **container** | tracepoint | `syscalls/sys_enter_unshare`, `sys_enter_setns` | namespace-escape patterns |
| **kmod** | tracepoint | `syscalls/sys_enter_init_module`, `sys_enter_finit_module` | kernel-module rootkits |
| **fim** | tracepoint | `syscalls/sys_enter_openat` | write-mode opens of sensitive paths |
| **network** | tracepoint | `syscalls/sys_enter_connect` | outbound `connect()` to public IPv4 |
| **injection** | tracepoint | `syscalls/sys_enter_ptrace`, `sys_enter_process_vm_writev` | cross-process memory manipulation |
| **cred** | tracepoint | `syscalls/sys_enter_openat` (read-mode) | reads of credential files (shadow, ssh keys, ...) |

LSM enforcement (off by default; see `[enforcement]` in config and
`docs/hardening.md`):

| Program | LSM hook | Effect |
|---|---|---|
| **selfprotect** | `task_kill` | returns `-EPERM` for any signal aimed at the daemon's own TGID, except from PID 1 or kernelradar itself |
| **enforce_bpf** | `bpf` | denies `BPF_PROG_LOAD` for comms not in `bpf_allowlist` |
| **enforce_kmod** | `kernel_read_file` | denies `READING_MODULE` for comms not in `kmod_allowlist` |

All eleven `.bpf.o` files are SHA-256 hashed at build time into a
table embedded in the binary; the userspace loader re-hashes the
file on disk before passing it to the verifier. See "Integrity"
below.

## Event model

Every detector emits the same fixed-size struct into its own per-CPU
BPF ring buffer:

```c
// crates/kernelradar-bpf/include/events.h
struct kr_event {
    __u64  timestamp_ns;
    __u32  pid;
    __u32  tid;
    __u32  uid;
    __u32  gid;
    __u8   comm[16];           // TASK_COMM_LEN
    __u8   detector_id;        // 1=privesc, 2=bpf-loader, ... 8=cred
    __u8   severity;           // 0=info, 1=warning, 2=alert, 3=critical
    __u16  event_type;         // detector-specific subtype
    __u64  data[4];            // detector-specific payload (32 bytes)
};
```

Userspace mirrors this byte-for-byte with `kernelradar_core::event::KrEvent`.
A `#[repr(C)]` layout test plus a fuzz test for the ring-buffer
parser guard the ABI ([`crates/kernelradar-core/src/event.rs`](../crates/kernelradar-core/src/event.rs)).

## Userspace pipeline

For each event coming out of a ring buffer, the userspace pipeline
runs the same sequence:

1. **Process attribution.** `comm` arrives in the event itself
   (16 bytes from BPF). For the executable path the daemon reads
   `/proc/<pid>/exe` and re-reads `/proc/<pid>/comm`; if they
   disagree, the lookup is dropped (PID-reuse / `execve` race
   mitigation - see `read_exe_path_verified` in
   [`util.rs`](../crates/kernelradar-detectors/src/util.rs)).

2. **Allowlist match.** Per-detector list with four match modes:
   regex (`/^pat/`), exact `comm`, exact `exe`, exact `exe`
   basename. No prefix match - earlier versions had it and a
   regression in `sshd` allowlisting was found that way.

3. **Adaptive baseline.** Per `(detector, comm, hour-of-day)` EWMA
   buckets track events-per-minute. New events score `z = (observed -
   mean) / sigma`; rate that diverges past `score_threshold` (3 sigma
   by default) emits a synthetic ANOMALY alert in addition to (or
   instead of) the regular one. Storage is bounded: `pairs_max`
   capped at 10 000 entries by default with age-based eviction.

4. **Rate limiter.** Sliding window per `(detector, comm,
   event_type)`: at most `window_max` allowed emissions per
   `window`. Burst detection emits a secondary BURST alert when
   `burst_threshold` is exceeded inside `burst_window`. Persistent
   over-limit triggers exponential backoff capped at `backoff_max`.

5. **Output.** One of:
   - **journald** (default in systemd environments) - structured
     fields `DETECTOR=`, `SEVERITY=`, `PID=`, `UID=`, `COMM=`,
     `CORRELATION_ID=`.
   - **JSON** - one JSON object per line on stdout.
   - **Plain** - colored human-readable text on stdout.
   - **Falco** - JSON shape compatible with Falco-consuming SIEMs.
   - **Webhook** (additive, off by default) - HTTP POST per alert
     with bearer-token auth and severity filter.
   - **Prometheus** (additive, off by default) - HTTP `/metrics`
     endpoint with `kernelradar_alerts_total`,
     `kernelradar_bursts_total`, `kernelradar_anomalies_total`.

## Integrity verification

`build.rs` in `kernelradar-detectors` computes SHA-256 of every
`.bpf.o` file under `crates/kernelradar-bpf/.output/` and emits a
generated `bpf_hashes.rs` mapping `name -> hex`. The runtime loader
re-hashes the file on disk before `Ebpf::load` and compares.

Two modes:

- **Strict** (default, `[integrity] strict_mode = true`): a hash
  mismatch OR a missing build-time hash (e.g. the `.bpf.o` was
  absent during `cargo build`) refuses to load that detector. This
  is the only safe setting for binaries an operator did not just
  build themselves.
- **Permissive** (`strict_mode = false`): mismatch logs a loud
  `error!` and the daemon continues. Useful while iterating on
  `.bpf.o` files after install. Flip strict back on before shipping.

## Threading model

- The CLI uses `#[tokio::main]` with the multi-threaded runtime.
- One detector = one `tokio::spawn`'d task = one BPF ring buffer
  reader, driven by `tokio::io::unix::AsyncFd` registered against
  the ring's file descriptor. Tasks wake on epoll-ready, not on a
  100 ms polling tick.
- Shared state (rate limiter, baseline, metrics) is single-mutex
  protected. Locks are held for microseconds; on `PoisonError` the
  inner state is recovered with a warn-and-continue policy rather
  than panicking the whole process.
- Allowlists and the destination CIDR list are `Arc<RwLock<...>>`
  with a SIGHUP handler that swaps them atomically on config
  reload.

## Configuration

Single TOML file at `/etc/kernelradar/config.toml`. Generate a
canonical example with `kernelradar config-cmd example`. Validate a
file with `kernelradar config-cmd validate`. Live-reload by sending
`SIGHUP` to the daemon; the reload validates first and refuses to
swap state if the new config has issues.

```toml
[global]
log_level     = "info"
output_format = "auto"   # auto | plain | json | journald | falco

[ratelimit]
window_secs       = 60
window_max        = 10
burst_threshold   = 100
burst_window_secs = 1
backoff_initial_secs = 60
backoff_max_secs     = 3600

[baseline]
enabled              = true
learning_secs        = 86400        # 24h warm-up before scoring
score_threshold      = 3.0          # sigma
alpha                = 0.10         # EWMA smoothing
save_path            = "/var/lib/kernelradar/state/baseline.json"
save_interval_secs   = 300
pairs_max            = 10000
evict_age_hours      = 168          # 7 days

[webhook]
enabled                          = false
url                              = ""
timeout_secs                     = 3
severity_filter_alert_or_higher  = false

[prometheus]
enabled     = false
listen_addr = "127.0.0.1:9101"      # 9101 to avoid node_exporter (9100)

[enforcement]                       # all OFF by default
selfprotect_enabled  = false
bpf_enforce_enabled  = false
kmod_enforce_enabled = false
bpf_allowlist        = ["bpftrace", "falco", "kernelradar"]
kmod_allowlist       = ["modprobe", "kmod", "insmod", "systemd-udevd"]

[integrity]
strict_mode = true                  # default; false only while iterating on .bpf.o locally

[network]
destination_cidr_allowlist = []     # IPv4 CIDRs to suppress before alerting

[detectors.privesc]
enabled    = true
allowlist  = ["sshd", "su", "sudo", "polkitd", "/^systemd.*/"]
# ... one [detectors.<name>] block per detector
```

## Build requirements

Both halves of the build require Linux (or WSL2) - the BPF objects
need a clang capable of `target=bpf` and the kernel's BTF type info,
and the userspace `build.rs` hashes the freshly built `.bpf.o` files
for integrity verification. Build artifacts (`.bpf.o`, `target/`)
are not committed; the in-repo `release-checksums/` directory is the
only thing that pins binary state across releases.

Toolchain:
- `clang` >= 14 with the BPF backend
- `libbpf-dev` >= 1.0
- `bpftool` (used to generate `vmlinux.h`)
- Linux kernel built with `CONFIG_DEBUG_INFO_BTF=y` (mainstream
  distro kernels already are)
- Rust toolchain stable

```
make    # builds BPF objects, then the userspace daemon
```

The top-level Makefile orders BPF before Rust deliberately so the
integrity table picks up real hashes - running `cargo build`
directly logs "no build-time hash recorded" at every startup.
