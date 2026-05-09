# kernelradar

> Linux host security daemon: eight eBPF-based detectors, one Rust
> binary, journald output by default.

[![License: GPL-2.0-only](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](LICENSE)
[![CI](https://github.com/ferithtools/kernelradar/actions/workflows/ci.yml/badge.svg)](https://github.com/ferithtools/kernelradar/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-v0.1.4-orange.svg)](#)
[![Linux only](https://img.shields.io/badge/platform-linux--6.1%2B-lightgrey.svg)](#)

---

> **Status: pre-1.0 preview, single maintainer.** The eight detectors
> work and are production-tested on one Debian 12 / kernel 6.13.9
> host. There is no CNCF backing, no fleet of users, no multi-year
> track record. Pilot on a non-critical box first. Contributions of
> any size welcome - file an issue, send a PR, package for a distro,
> or star the repo so others can find it.

---

## What it is

`kernelradar` is a single Linux daemon that loads eleven eBPF programs
(eight observers + three optional LSM enforcement hooks) and emits
structured alerts to journald, JSON, a webhook, or a Prometheus
endpoint. Detectors cover `setuid(0)`, `BPF_PROG_LOAD` outside an
allowlist, `unshare` / `setns`, kernel-module loads, write-mode opens
of sensitive files (`/etc/shadow`, ssh keys, ...), outbound IPv4
`connect()` to public addresses, `ptrace` / `process_vm_writev`, and
read-mode opens of credential files.

It is in the same broad space as **Falco**, **Tetragon**, and
**Tracee**. Those projects are mature, CNCF-class, with thousands of
rules and active communities; kernelradar is none of those things.
What it does try to do is be **one small Rust daemon you can drop
onto an on-prem or edge host without a Kubernetes cluster around it**,
with a 65-80 MB resident set instead of 200-500 MB. See the
[Comparison](#comparison) table for the honest read of where it
fits and where it doesn't.

In addition to the static detectors, kernelradar tracks an EWMA of
events-per-minute per `(detector, comm, hour-of-day)` and emits a
secondary alert when the rate diverges past a sigma threshold. This
is a running statistical heuristic, not machine learning - useful as
a second signal alongside whatever rule engine you already run, not
as a replacement.

What's not in v0.1: web UI, fleet manager, threat-intel feed, IPv6
in the network detector, automatic remediation. The default install
is observe-only.

---

## Comparison

| | kernelradar | Falco | Tetragon | Tracee | Commercial EDR |
|---|---|---|---|---|---|
| License | **GPL-2.0-only** (copyleft) | Apache-2.0 | Apache-2.0 | Apache-2.0 | proprietary |
| Idle RSS (footprint) | **65-80 MB** | ~200 MB | ~500 MB | ~300 MB | varies |
| Single self-contained binary | ✅ | ✅ | partial (k8s-first) | ✅ | n/a |
| Kubernetes required | ❌ | ❌ | typically yes | ❌ | n/a |
| Detection model | Rules + EWMA/sigma | Rules | Policies | Signatures | ML + cloud rules |
| LSM enforcement (block mode) | opt-in | ❌ | ✅ | ❌ | ✅ |
| SaaS / data leaves host | ❌ | ❌ | ❌ | ❌ | ✅ |
| Per-host monthly cost | free | free | free | free | typically tens of dollars |
| Web UI / dashboard | ❌ | ❌ (third-party) | partial (Hubble) | ❌ | ✅ |
| Pre-built rule library | small | **large** | medium | medium | large |
| Production track record | **pre-1.0 preview** | mature | mature (CNCF) | mature | mature |
| Community size | tiny | **large (CNCF)** | large (Cilium) | medium | n/a |

Numbers for the free peers are approximations from each project's published
documentation; `kernelradar`'s figures are measured directly on the lowest-spec
hardware officially supported (see [Performance](#performance)).

The honest read of this table: Falco / Tetragon / Tracee are mature,
production-trusted tools with active CNCF-class communities. **They
do more, they do it better-tested, they cover more scenarios out of
the box.** If you run Kubernetes at scale, run Falco. If you need
policy enforcement woven into a service mesh, run Tetragon.

The two rows in **bold** are where kernelradar is structurally
different, not just smaller:

- **GPL-2.0-only.** Apache-2.0 forks can be closed and re-sold as
  proprietary; GPL-2.0 obligates derivatives to publish source. For
  security tooling that is the structural argument against a future
  "kernelradar Enterprise" subscription tier appearing - the source
  has to come along no matter who picks it up.
- **65-80 MB resident set.** This is not "fewer features so smaller
  RAM"; it is "one Rust daemon, no Lua-policy interpreter, no k8s
  integration overhead, no plugin host". Falco's Lua engine and
  Tetragon's Cilium-shaped runtime are powerful and mostly the
  reason their resident set is what it is. On Celeron-class edge
  boxes, 4 GB SOHO routers, or per-VPS deployments where 500 MB
  resident is unacceptable, the difference is the whole reason to
  pick kernelradar.

The other rows in the table are facts but not selling points:
"adaptive baseline" is an EWMA with a sigma threshold (useful, not
revolutionary); "no cloud" is a peer feature, not a kernelradar
exclusive; LSM enforcement is hardening defence-in-depth, not a
guarantee against root.

## Where kernelradar actually fits

Pick `kernelradar` when:

- You run **5-50 on-prem servers** or **edge / IoT / SOHO** boxes
  and `make && sudo make install` beats deploying a Helm chart for
  a single host.
- You want **resident set under 100 MB** and CPU floor under 1 %.
- You want a **second behavioural signal** (rate deviations from a
  per-host baseline) on top of whatever rule engine you already
  run - kernelradar happily coexists with Falco / auditd /
  Wazuh / SELinux on the same host.
- The **GPL-2.0 copyleft** matters to you for licensing or
  governance reasons.

Pick something else when:

- You run **Kubernetes at scale**: Falco's CNCF community and
  Tetragon's k8s-shaped policies are years ahead.
- You need a **rule library curated by an active community**: Falco
  ships thousands of rules, kernelradar eight detectors.
- You need a **production-grade web UI** out of the box: pair with
  Wazuh, Elastic, Grafana, or buy commercial EDR.
- You need **IPv6 outbound monitoring today**: kernelradar's
  network detector is IPv4-only in v0.1; targeted for v0.1.x.
- You need a **mature, multi-year track record**: kernelradar is
  v0.1.4. Pilot it before paging anyone.

---

## Performance

The numbers below were collected on the lowest-spec hardware
`kernelradar` is officially supported on - the worst-case floor.
Throughput on bigger hardware will be higher, but the project does
not yet have measurements on Xeon/Threadripper/Ampere class boxes
to publish.

**Hardware:** Intel Celeron J4125 @ 2.0 GHz · 4 cores · no SMT · 8 GB DDR4 ·
Linux kernel 6.13.9 · Debian 12.

| Metric | Value |
|---|---|
| Sustained event rate (BPF tracepoint, kernel-side) | **321 000 events/sec** |
| Idle resident memory (RSS) | **65 to 80 MB** |
| RSS peak under a 100 000-event burst | 136 MB |
| Memory growth after burst returns to idle | **0 bytes** |
| CPU at idle | <0.1 % of one core |
| CPU under sustained burst | ~28 % of one core |
| Graceful shutdown (SIGTERM → all 12 BPF programs detached) | **641 ms** |

Full methodology and a per-stage breakdown live in
[`docs/performance.md`](docs/performance.md).

---

## Quickstart

### Option A - install the prebuilt release (Linux x86_64)

```bash
# 1. Pull the release tarball + its SHA-256.
curl -fsSLO https://github.com/ferithtools/kernelradar/releases/download/v0.1.4/kernelradar-0.1.4-linux-x86_64.tar.gz
curl -fsSLO https://github.com/ferithtools/kernelradar/releases/download/v0.1.4/kernelradar-0.1.4-linux-x86_64.tar.gz.sha256

# 2. Verify against the published checksum, then cross-check
#    against the in-repo pin (committed at release time, so a
#    compromised release endpoint cannot serve a tampered SHA).
sha256sum -c kernelradar-0.1.4-linux-x86_64.tar.gz.sha256 \
    || { echo "TAMPERED - do not install"; exit 1; }

PIN=$(curl -fsSL https://raw.githubusercontent.com/ferithtools/kernelradar/master/release-checksums/v0.1.4/kernelradar-0.1.4-linux-x86_64.tar.gz.sha256 | awk '{print $1}')
PUB=$(awk '{print $1}' kernelradar-0.1.4-linux-x86_64.tar.gz.sha256)
[ "$PIN" = "$PUB" ] || { echo "release-attached SHA does not match in-repo pin"; exit 1; }

# 3. Extract + run the bundled installer.
tar -xzf kernelradar-0.1.4-linux-x86_64.tar.gz
cd kernelradar-0.1.4-linux-x86_64
sha256sum -c SHA256SUMS                  # verify each shipped file
./install.sh                              # binary, BPF objects, systemd unit, default config
sudo systemctl enable --now kernelradar
journalctl -u kernelradar -f -o cat
```

> The release is checksummed (SHA-256 pinned in the source tree),
> not cryptographically signed. Identity-based signing via cosign /
> Sigstore is targeted for v0.2.

### Option B - build from source

Install dependencies (Debian/Ubuntu):

```bash
sudo apt install -y build-essential clang llvm libbpf-dev libelf-dev \
    pkg-config bpftool linux-tools-common
```

Install Rust (if not already):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Build and run:

```bash
git clone https://github.com/ferithtools/kernelradar.git
cd kernelradar

# 1. Build BPF objects + userspace daemon. The top-level Makefile
#    ensures BPF is built first so build.rs can hash the .bpf.o
#    files into the integrity-verification table; running
#    `cargo build` directly logs "no build-time hash recorded" at
#    every startup.
make

# 2. Validate, then run
sudo ./target/release/kernelradar config-cmd validate
sudo ./target/release/kernelradar daemon \
    --bpf-dir crates/kernelradar-bpf/.output \
    --format=plain
```

Watch live alerts (in a second terminal - pick whichever you prefer):

```bash
# When running with --format=plain (above), alerts go to the daemon's stdout.
# For systemd installs the daemon defaults to journald:
journalctl -t kernelradar -f
```

For a permanent install:

```bash
sudo make install            # binary, BPF objects, systemd unit, default config
sudo systemctl enable --now kernelradar
journalctl -u kernelradar -f
```

The default install ships in **observe-only** mode - no LSM enforcement, no
process killing, no outbound webhook. Read [`docs/hardening.md`](docs/hardening.md)
before flipping any of those on.

---

## Detectors (v0.1)

| # | Detector | Catches |
|---|---|---|
| 1 | **privesc** | `setuid(0)` / `setgid(0)` from non-root processes |
| 2 | **bpf-loader** | `BPF_PROG_LOAD` from processes outside the allowlist (BPF rootkits) |
| 3 | **container** | `unshare()` / `setns()` patterns suggesting cgroup or namespace escape |
| 4 | **kmod** | `init_module` / `finit_module` (kernel module rootkits) |
| 5 | **fim** | `openat()` with write/append/create on sensitive paths (`/etc/passwd`, `/etc/shadow`, ssh keys, …) |
| 6 | **network** | Outbound `connect()` to public IPv4 addresses with severity-bumping for known reverse-shell ports |
| 7 | **injection** | `ptrace(PTRACE_ATTACH/SEIZE/POKE*)` and `process_vm_writev()` |
| 8 | **cred** | Read-opens of credential files (shadow, sudoers, ssh private keys, browser cookies, …) |

Each detector emits a structured `Alert` with a stable schema
(`correlation_id`, `severity`, `detector`, `title`, `pid`, `uid`, `comm`,
`context`, plus a per-detector payload). See
[`crates/kernelradar-core/src/alert.rs`](crates/kernelradar-core/src/alert.rs)
for the canonical type and [`docs/logging.md`](docs/logging.md) for output
formats.

---

## Outputs and integrations

`kernelradar` does not run its own dashboard; it speaks the protocols you
already speak. Pick the channel(s) that fit your stack:

- **journald** (default) - structured fields (`DETECTOR=`, `SEVERITY=`,
  `PID=`, `CORRELATION_ID=`, …) for `journalctl -o json | jq`
- **Prometheus** - `/metrics` endpoint on `127.0.0.1:9101` (off by default;
  `9101` not `9100` to avoid collision with `node_exporter`)
- **HTTP webhook** - POSTs the alert JSON to any URL you configure;
  ready-made adapter recipes for Slack and Telegram bots (small Python
  scripts that bridge the webhook to the respective bot API) live in
  [`docs/integrations/slack-telegram.md`](docs/integrations/slack-telegram.md),
  and the same pattern extends to any custom receiver
- **Falco-compatible JSON** - drop-in for SIEM/aggregators that already
  ingest Falco
- **Plain text / JSON-lines on stdout** - for ad-hoc piping

Working configs live in [`docs/integrations/`](docs/integrations/) for:
[Wazuh](docs/integrations/wazuh.md),
[Prometheus](docs/integrations/prometheus.md),
[Loki / Vector / Fluent Bit](docs/integrations/loki-vector-fluentbit.md),
[Slack & Telegram](docs/integrations/slack-telegram.md),
and [Falco-compatible SIEMs](docs/integrations/falco.md).

---

## Architecture (high-level)

```
┌──────────────────────┐    ┌──────────────────────┐
│   Kernel space       │    │   User space (Rust)  │
│                      │    │                      │
│ tracepoints + LSM ───┼───▶│ ring-buffer reader   │
│ hooks (12 programs)  │    │        │             │
│        ▲             │    │        ▼             │
│        │             │    │ allowlist + CIDR     │
│        │             │    │        │             │
│        │             │    │        ▼             │
│        │             │    │ rate-limit + burst   │
│        │             │    │ + adaptive baseline  │
│        │             │    │        │             │
│        │             │    │        ▼             │
│        └─ kr_stats ◀─┼────┤ outputs:             │
│           (counters) │    │  journald / Prom /   │
│                      │    │  webhook / Falco     │
└──────────────────────┘    └──────────────────────┘
```

For the full event flow, crate layout, and threat model see
[`docs/architecture.md`](docs/architecture.md) and
[`docs/threat-model.md`](docs/threat-model.md).

---

## What's not (yet) included

Setting expectations honestly:

- **No web dashboard.** Bring your own (Grafana on top of Prometheus, Wazuh,
  or any SIEM that eats journald / Falco JSON).
- **No multi-host fleet management.** `kernelradar` runs per-host. Aggregate
  the journals with Loki / Vector / Fluent Bit (recipes provided).
- **No threat-intelligence feed integration.** Detection is local-only:
  heuristics + adaptive baseline. No live IOC subscription.
- **No automated remediation in the default install.** The LSM enforcement
  mode (block `BPF_PROG_LOAD` from non-allowlisted processes, block
  `kmod` loads from non-allowlisted processes, block kill of the
  kernelradar process itself) is opt-in and off by default. Default =
  observe + alert. Note: the `kmod` hook is a process allowlist, not a
  signature check - kernel module signing remains the kernel's job.
- **No managed cloud version.** Self-hosted only.
- **Linux only.** macOS / Windows are out of scope by design - eBPF is a
  Linux feature.
- **The network detector is IPv4-only.** Its kernel-side BPF probe filters
  out anything that isn't `AF_INET`, so IPv6 connections are not observed
  at all in v0.1 (they don't alert, but they also don't show up). The
  destination CIDR allowlist is therefore IPv4-only too. Kernel-side IPv6
  hooks land in v0.2 (see roadmap).
- **Distribution is source + tarball.** v0.1.x ships a SHA-256-pinned
  Linux x86_64 tarball; Debian / RPM / OCI images land in v0.2 (see roadmap).

If any of those are deal-breakers, you probably want a commercial EDR or one
of the larger CNCF tools. If they're acceptable trade-offs, read on.

---

## Roadmap

A direction, not a commitment. Single-maintainer projects miss
quarters; treat the dates below as "no earlier than" rather than
"by then". The list moves with what real users ask for - if a
scheduled item has no demand and an unscheduled one does, that
gets reordered.

### Q2 2026 - v0.1.x patch series

Closing the v0.1 punch list and shipping installable packages.

- `--dry-run` / `--audit-only` mode for LSM enforcement (logs "would-block"
  decisions without enforcing them - lets operators canary the policy)
- BPF-side `kr_stats` counters surfaced through the Prometheus exporter
  (currently observable only via `bpftool map dump`)
- IPv6 destination CIDR allowlist for the network detector
- Per-detector documentation (one page each: what it catches, what it
  misses, how to tune it)
- `docs/integrations/email.md` (msmtp / exim recipe)
- Debian / Ubuntu `.deb` package - first installable release artifact

### Q3 2026 - v0.2

New detectors, persistence/execution coverage, platform expansion.

- **DNS anomaly detector** - DGA / suspicious resolver patterns
- **Reverse-shell heuristics detector** - process-tree shape + symbolic
  port matching (independent of the existing port-blocklist in the
  network detector)
- **Persistence detector** - additions to `~/.bashrc`, `~/.profile`,
  cron / at jobs, systemd unit files, init.d scripts, and SUID-bit
  flips. Covers MITRE TA0003.
- **Exec-anomaly detector** - `execve` from `/tmp`, `/dev/shm`,
  `/var/tmp`; suspicious parent-child mismatches (web server → shell);
  LOLBin-style patterns (curl piping into shell). Covers MITRE TA0002.
- Pluggable threat-intel adapter for the network detector (one default
  feed shipped - likely a public CIDR blocklist)
- ARM64 cross-compile + qemu-based CI matrix
- OCI distroless container image
- RPM package for Fedora / RHEL
- Reproducible builds + SBOM generation
- GPG-signed releases

### Q4 2026 - v0.3

Detection breadth and (lightly) UX.

- **Memory anomaly detector** - heap-spray patterns, suspicious slab
  allocations via perf counters
- **Ransomware-behavior detector** - mass-rename heuristic: N+ files
  renamed within T seconds by one process, especially with a uniform
  new extension (the typical encryption signature). Covers MITRE TA0040.
- Embedded read-only HTTP UI (single binary, no separate frontend stack):
  recent alerts, baseline state, detector status, `/metrics` proxy
- Optional Kubernetes operator + Helm chart in a separate
  `kernelradar-k8s` repository (so the core binary stays k8s-free)
- Production-hardening pass: 24-hour KASAN soak in CI, anti-tamper
  improvements

### Q1 2027 - v1.0 (LTS)

Feature-stable cut after community feedback. 12-month support window with
backported security fixes.

**Candidates for v1.1+ on community demand:** audit-tamper detector
(catches attempts to disable auditd / journald), proc-hide detector
(rootkit PID-hiding via `/proc` enumeration mismatch), mount-anomaly
detector (privileged container mounts).

Day-to-day prioritisation lives on the GitHub
[issues page](https://github.com/ferithtools/kernelradar/issues) -
file one if a missing detector is blocking your use case.

---

## Security model

What `kernelradar` actually does to your system, in one paragraph:

It loads 12 BPF programs into the kernel via the standard `bpf()` syscall
under `CAP_BPF` + `CAP_PERFMON` (no need for full root on kernels ≥5.8).
Eight of those are read-only tracepoint observers. Three are LSM hooks for
optional enforcement and self-protection - **off by default**. One is a
shared statistics map. When the daemon exits - including on `SIGKILL`,
panic, or `OOM` - every BPF program detaches automatically (Aya's `Drop`
impl). There are no kernel modules, no `/proc/sys` modifications, no
`sysctl` tweaks, no persistent on-disk state outside `/var/lib/kernelradar/`.
Network egress is opt-in (webhook / Prometheus only when explicitly
enabled). Default behaviour is "watch and report" - `kernelradar` does
not kill processes or block syscalls unless you explicitly enable the
LSM enforcement mode.

For the threat model, in-scope vs out-of-scope attackers, and what an
attacker with root can and cannot do to this tool, see
[`docs/threat-model.md`](docs/threat-model.md) and
[`docs/hardening.md`](docs/hardening.md).

**Reporting vulnerabilities:** see [`SECURITY.md`](SECURITY.md).

---

## License

GPL-2.0-only - see [`LICENSE`](LICENSE) for the verbatim text.

The BPF programs require GPL because they call kernel BPF helpers that are
GPL-only; the userspace Rust code is GPL-2.0-only by symmetry. Practical
consequence: you can use `kernelradar` for any purpose, including
commercial deployments, but if you fork it and ship a derivative work, the
derivative must also be GPL-2.0-only and its source must be available. No
closed-source proprietary forks.

---

## Contributing

Issue and pull-request templates are in
[`.github/`](.github/); see
[`CONTRIBUTING.md`](CONTRIBUTING.md) for the workflow.

Until then: open an issue describing what you'd like to change, and we'll
figure it out from there.
