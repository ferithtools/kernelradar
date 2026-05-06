# kernelradar: Roadmap

## Phase 1 — Observation + Rule-based detection (current)

Goal: working daemon with first two detectors, installable on Debian 12.

**Detectors**:
- [x] Project skeleton
- [ ] Detector 1: Privilege escalation tracker
- [ ] Detector 2: BPF program loader auditor

**Infrastructure**:
- [ ] Cargo workspace (kernelradar-core, kernelradar-cli, kernelradar-bpf)
- [ ] BPF ring buffer → Rust event pipeline
- [ ] journald alert output
- [ ] `systemd` unit file
- [ ] `make install` on Debian 12

**Definition of done**: `sudo kernelradar daemon` runs on 127.0.0.1,
detects a demo privilege escalation in under 100ms, logs to journald.

---

## Phase 2 — More detectors + configuration

- [ ] Detector 3: Container escape detector
- [ ] Detector 4: Kernel module integrity checker
- [ ] Config file (`/etc/kernelradar/config.toml`)
- [ ] Per-detector allowlists
- [ ] HTTP webhook output
- [ ] CLI: `kernelradar status`, `kernelradar test`

---

## Phase 3 — Adaptive baseline (ML)

- [ ] Event time-series collection into SQLite
- [ ] Baseline model: kernel density estimation per cgroup
- [ ] Anomaly scoring (σ-based)
- [ ] Alert deduplication
- [ ] Baseline reset command

---

## Phase 4 — Hardening + active enforcement

- [ ] BPF LSM enforcement (not just observe)
- [ ] Policy: block / kill / isolate on detection
- [ ] BPF program signing integration (ML-DSA when available)
- [ ] Integration tests with KASAN-enabled kernel

---

## Phase 5 — Ecosystem

- [ ] Wazuh integration (SIEM)
- [ ] Prometheus metrics endpoint
- [ ] Package for Debian/RHEL/Alpine
- [ ] ФСТЭК-совместимая документация (для рос. рынка)
