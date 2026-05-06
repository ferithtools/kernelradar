# kernelradar

> Behavioral anomaly detection for the Linux kernel. Defensive security through BPF observability.

**Status**: Early development. Phase 1 (privilege escalation tracker) — in progress.

## What it is

`kernelradar` watches the Linux kernel from the inside via BPF iterators and tracepoints, learns the baseline of "normal" behavior on a given system, and flags deviations in real time. Optionally enforces policies via BPF LSM.

Inspired by Falco, Tetragon, Tracee — but with two distinguishing properties:

1. **Adaptive baseline.** Most existing tools require pre-written rules. `kernelradar` learns what "normal" looks like for a given system and detects deviations from that.
2. **Single-binary, low-friction.** No Kubernetes, no Helm chart, no SaaS dashboard. One Rust binary + BPF programs. Drop on a server, watch.

## Detectors (planned, sequential delivery)

| # | Detector | Status | What it catches |
|---|----------|--------|-----------------|
| 1 | **Privilege Escalation Tracker** | 🚧 In progress | setuid/setgid abuse, suspicious credential transitions |
| 2 | **BPF Rootkit Detector** | Planned | Unauthorized BPF program loads, BPF-based persistence |
| 3 | **Container Escape Detector** | Planned | Cgroup boundary violations, suspicious namespace operations |
| 4 | **Kernel Module Rootkit Detector** | Planned | Unauthorized module loads, integration with ML-DSA module signing |
| 5 | **Memory Anomaly Detector** | Future | Heap spray patterns, suspicious slab allocations |
| 6 | **Side-Channel Detector** | Future | Spectre/Meltdown-like access patterns via perf counters |

## Architecture (high level)

```
                  ┌──────────────────────────────┐
                  │  kernelradar (userspace)     │
                  │                              │
  ┌──────────┐    │  ┌────────────────────────┐  │
  │  BPF     │───▶│  │  Event collector        │  │
  │  programs│    │  └────────────────────────┘  │
  │          │    │             │                │
  │ tracepts │    │             ▼                │
  │ iterators│    │  ┌────────────────────────┐  │
  │ LSM hook │    │  │  Detection engine       │  │
  │          │◀───│  │  (rules + ML baseline)  │  │
  └──────────┘    │  └────────────────────────┘  │
                  │             │                │
                  │             ▼                │
                  │  ┌────────────────────────┐  │
                  │  │  Alert pipeline         │  │
                  │  │  (syslog, http, telegr) │  │
                  │  └────────────────────────┘  │
                  └──────────────────────────────┘
```

## Stack

- **BPF programs**: C, compiled with libbpf BPF target
- **Userspace daemon**: Rust + [Aya](https://aya-rs.dev/)
- **Build system**: Cargo workspace
- **Target kernel**: Linux 6.13+ (older kernels supported best-effort)
- **Test environment**: Debian 12 with custom-built kernel 7.0.3

## Quick start (when ready)

```bash
# Build
cargo build --release

# Run privilege escalation detector
sudo ./target/release/kernelradar detect privesc

# Run all available detectors with default policy
sudo ./target/release/kernelradar daemon

# Watch live alerts
journalctl -t kernelradar -f
```

## License

GPL-2.0-only. BPF programs must be GPL-compatible to use kernel BPF helpers, so the whole project is GPL.

## Project structure

```
kernelradar/
├── crates/
│   ├── kernelradar-cli/       # Main binary
│   ├── kernelradar-core/      # Common types, telemetry
│   ├── kernelradar-detectors/ # Detection logic per category
│   └── kernelradar-bpf/       # BPF C source + build tooling
├── docs/
│   ├── architecture.md
│   ├── threat-model.md
│   ├── detectors/             # One doc per detector
│   └── benchmarks/
├── tests/
└── tools/
```

## Author

Ferith Tools, 2026.

## See also

- [Falco](https://falco.org/) — k8s-focused, rule-based
- [Tetragon](https://tetragon.io/) — Cilium's kernel security observability
- [Tracee](https://www.aquasec.com/products/tracee/) — Aqua Security's runtime detection
