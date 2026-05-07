# kernelradar: Architecture

## Overview

kernelradar runs a continuous **observe → analyse → alert** loop inside Linux, using BPF as the observation layer and Rust as the userspace engine.

```
Kernel space                    Userspace
────────────────────────────    ─────────────────────────────────────────
                                kernelradar daemon
  BPF programs                    ┌─────────────────────────────────────┐
  ┌──────────────────────┐        │  Loader                             │
  │  tracepoints         │──────► │  (Aya: load & manage BPF programs)  │
  │  LSM hooks           │        └──────────────┬──────────────────────┘
  │  BPF iterators       │◄──────────────────────┤
  └──────────────────────┘  maps  │  Event collector                    │
                                  │  (perf ring buffer / BPF ring buf)  │
                                  └──────────────┬──────────────────────┘
                                                 │
                                  ┌──────────────▼──────────────────────┐
                                  │  Detection engine                   │
                                  │  • Rule-based (fast path)           │
                                  │  • Baseline ML (adaptive)           │
                                  └──────────────┬──────────────────────┘
                                                 │
                                  ┌──────────────▼──────────────────────┐
                                  │  Alert pipeline                     │
                                  │  • syslog / journald                │
                                  │  • HTTP webhook                     │
                                  │  • stdout (debug mode)              │
                                  └─────────────────────────────────────┘
```

## Crate layout

```
kernelradar/
└── crates/
    ├── kernelradar-bpf/       # BPF C sources + libbpf build glue
    │                          # Compiled objects embedded in Rust via include_bytes!
    │
    ├── kernelradar-core/      # Shared types: Event, Alert, Severity, Config
    │                          # No BPF or OS dependencies - pure data types
    │
    ├── kernelradar-detectors/ # One module per detector
    │   ├── privesc.rs         # Detector 1: privilege transitions
    │   ├── bpf_rootkit.rs     # Detector 2: suspicious BPF loads
    │   ├── container.rs       # Detector 3: namespace/cgroup escapes
    │   └── kmod.rs            # Detector 4: kernel module integrity
    │
    └── kernelradar-cli/       # Binary: CLI flags, daemon loop, output
```

## BPF programs per detector

Each detector owns its own BPF program(s):

| Detector | BPF type | Kernel hooks |
|----------|----------|--------------|
| privesc | tracepoint | `syscalls/sys_enter_setuid`, `syscalls/sys_enter_setgid`, `task/task_rename` |
| bpf_rootkit | tracepoint + LSM | `syscalls/sys_enter_bpf`, `bpf/bpf_prog_load` |
| container | LSM | `lsm/cgroup_attach_task`, `lsm/sb_mount` |
| kmod | LSM | `lsm/kernel_module_request`, `lsm/kernel_read_file` |

## Event model

Every BPF program emits a fixed-size `Event` struct into a BPF ring buffer:

```c
// kernelradar-bpf/include/events.h
struct kr_event {
    __u64  timestamp_ns;
    __u32  pid;
    __u32  tid;
    __u32  uid;
    __u32  gid;
    __u8   comm[16];
    __u8   detector_id;   // enum DetectorId
    __u8   severity;      // 0=info 1=warning 2=alert 3=critical
    __u16  event_type;    // detector-specific sub-type
    __u64  data[4];       // detector-specific payload (32 bytes)
};
```

Userspace maps to a Rust mirror type in `kernelradar-core`.

## Detection engine

Two modes - both run simultaneously:

**Rule-based (deterministic, fast path)**
- Hand-written conditions checked per-event
- Examples: `uid 0 → uid != 0 → uid 0 within 100ms` = alert
- Zero false negatives for known patterns

**Baseline ML (adaptive)**
- Builds a behavioural model over the first N hours
- Uses kernel density estimation over event frequency per cgroup
- Scores new events: > 3σ from baseline = candidate alert
- Deduplication: same pattern within 30s = suppress
- Phase 1 ships rule-based only; ML added in Phase 3

## Configuration

Single TOML file (`/etc/kernelradar/config.toml`):

```toml
[global]
log_level = "info"
alert_backend = "journald"   # journald | syslog | webhook | stdout

[detectors.privesc]
enabled = true
severity_threshold = "warning"

[detectors.bpf_rootkit]
enabled = true
allowlist = ["/usr/sbin/falco", "/usr/bin/bpftrace"]

[baseline]
enabled = false        # Phase 3
learn_duration_hours = 48
```

## Build requirements

Both halves of the build require Linux (or WSL2) - the BPF objects
need a clang capable of `target=bpf` and the kernel's BTF type info,
and the userspace `build.rs` hashes the freshly built `.bpf.o` files
for integrity verification. Build artifacts (`.bpf.o`, `target/`)
are not committed; the in-repo `release-checksums/` directory is the
only thing that pins binary state across releases.

Toolchain:
- `clang` ≥ 14 with the BPF backend
- `libbpf-dev` ≥ 1.0
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
