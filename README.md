# kernelradar

> Behavioral anomaly detection for the Linux kernel via eBPF —
> a single Rust binary, no Kubernetes, no SaaS, no telemetry leaving the host.

[![License: GPL-2.0-only](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](LICENSE)
[![CI](https://github.com/ferithtools/kernelradar/actions/workflows/ci.yml/badge.svg)](https://github.com/ferithtools/kernelradar/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-v0.1.0--preview-orange.svg)](#)
[![Linux only](https://img.shields.io/badge/platform-linux--6.1%2B-lightgrey.svg)](#)

🇬🇧 **English** · [🇷🇺 Русский](#kernelradar--русская-версия)

---

> 🤝 **A note to enthusiasts.** kernelradar is being built in the open
> by one person and a small circle of contributors. If you run
> small-fleet infrastructure, do Linux security for a living, write
> Rust or BPF C — or simply believe that Linux observability shouldn't
> require a SaaS subscription — your help is welcome. File a bug, send
> a `pull request`, write documentation, port a detector, package the
> tool for your distro, or just star the repository so others can find
> it. The roadmap below is a direction, not a fence: if you have a
> real-world scenario that needs a different detector, open an `issue`
> and let's talk.

---

## What is this — and why does it exist?

`kernelradar` watches a Linux box from inside the kernel via eBPF and flags
suspicious behaviour in real time: privilege escalation, BPF-based rootkit
loads, container escapes, unauthorized kernel-module installs, file-integrity
violations, outbound connections to public addresses on reverse-shell ports,
process injection, and credential-file reads.

It lives in the same category as the open-source tools **Falco**, **Tetragon**,
**Tracee**, and the commercial endpoint-detection products like **SentinelOne**,
**CrowdStrike Falcon**, **Sysdig Secure**.

What makes it different:

- **Adaptive baseline + sigma-based anomaly scoring.** It learns what
  "normal" looks like on each individual host (an EWMA model — per
  detector, per process, per hour of the day) and flags statistical
  deviations, not just static rule matches.
- **One binary, ~80 MB resident memory.**
  Drop it on the server, point it at journald, walk away.
- **About what's not (yet) here.** No web UI. No centralized
  management. No threat-intelligence integration. No automated
  remediation in the default install. Pair it with the observability
  stack you already run (journald, Prometheus, Loki, Vector, Wazuh,
  Slack, Telegram, any Falco-compatible SIEM) — recipes are in
  [`docs/integrations/`](docs/integrations/).

**Built for the DevOps engineer or sysadmin running 5–50 servers** whose
budget can't stretch to enterprise EDR subscriptions but who still wants
to know in real time when something on a production box runs `setuid(0)`,
loads an unsigned kernel module, opens `/etc/shadow`, or makes outbound
connections from an unfamiliar process.

> ⚠️ **Status: v0.1.0-preview.** All eight detectors are implemented and tested
> on a real host (Debian 12, kernel 6.13). Performance and reliability numbers
> below are measured, not promised. But this is a young project — please pilot
> on a non-critical box first and read the [security model](#security-model)
> before wiring it into anything that pages on call.

---

## Comparison

| | kernelradar | Falco | Tetragon | Tracee | Commercial EDR |
|---|---|---|---|---|---|
| License | GPL-2.0-only | Apache-2.0 | Apache-2.0 | Apache-2.0 | proprietary |
| Detection model | Rules + **adaptive baseline** | Rules | Policies | Signatures | ML + cloud rules |
| Idle RSS (footprint) | **65–80 MB** | ~200 MB | ~500 MB | ~300 MB | varies |
| Single self-contained binary | ✅ | ✅ | partial (k8s-first) | ✅ | n/a |
| Kubernetes required | ❌ | ❌ | typically yes | ❌ | n/a |
| Web UI / dashboard | ❌ | ❌ (third-party) | ❌ (Hubble) | ❌ | ✅ |
| LSM enforcement (block mode) | ✅ opt-in | ❌ | ✅ | ❌ | ✅ |
| SaaS / data leaves host | ❌ | ❌ | ❌ | ❌ | ✅ |
| Per-host monthly cost | free | free | free | free | typically tens of dollars |

Numbers for the free peers are approximations from each project's published
documentation; `kernelradar`'s figures are measured directly on the lowest-spec
hardware we officially support (see [Performance](#performance)).

---

## Performance

All numbers were collected on the lowest-spec hardware `kernelradar` is
officially supported on, to give a worst-case floor. On real server hardware
(Xeon, Threadripper, Ampere) you can expect 5×–20× better.

**Hardware:** Intel Celeron J4125 @ 2.0 GHz · 4 cores · no SMT · 8 GB DDR4 ·
Linux kernel 6.13.9 · Debian 12.

| Metric | Value |
|---|---|
| Sustained event rate (BPF tracepoint, kernel-side) | **321 000 events/sec** |
| Idle resident memory (RSS) | **65–80 MB** |
| RSS peak under a 100 000-event burst | 136 MB |
| Memory growth after burst returns to idle | **0 bytes** |
| CPU at idle | <0.1 % of one core |
| CPU under sustained burst | ~28 % of one core |
| Graceful shutdown (SIGTERM → all 12 BPF programs detached) | **641 ms** |

Full methodology and a per-stage breakdown live in
[`docs/performance.md`](docs/performance.md).

---

## Quickstart

### Option A — install the prebuilt release (Linux x86_64)

```bash
# 1. Pull the release tarball.
curl -fsSLO https://github.com/ferithtools/kernelradar/releases/download/v0.1.0/kernelradar-0.1.0-linux-x86_64.tar.gz

# 2. Verify against the in-repo SHA-256 pin (so a compromised CDN
#    can't slip you a tampered binary).
EXPECTED=$(curl -fsSL https://raw.githubusercontent.com/ferithtools/kernelradar/v0.1.0/release-checksums/v0.1.0/kernelradar-0.1.0-linux-x86_64.tar.gz.sha256 | awk '{print $1}')
ACTUAL=$(sha256sum kernelradar-0.1.0-linux-x86_64.tar.gz | awk '{print $1}')
[ "$EXPECTED" = "$ACTUAL" ] || { echo "TAMPERED — do not install"; exit 1; }

# 3. Extract + run the bundled installer.
tar -xzf kernelradar-0.1.0-linux-x86_64.tar.gz
cd kernelradar-0.1.0-linux-x86_64
sha256sum -c SHA256SUMS                  # verify each shipped file
./install.sh                              # binary, BPF objects, systemd unit, default config
sudo systemctl enable --now kernelradar
journalctl -u kernelradar -f -o cat
```

> 🔒 The release is signed only by SHA-256 pinned in the source tree.
> GPG release signing lands in v0.2 (T-15.6).

### Option B — build from source

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

# 1. Compile the BPF objects
( cd crates/kernelradar-bpf && make )

# 2. Build the userspace daemon
cargo build --release

# 3. Validate, then run
sudo ./target/release/kernelradar config-cmd validate
sudo ./target/release/kernelradar daemon \
    --bpf-dir crates/kernelradar-bpf/.output \
    --format=plain
```

Watch live alerts (in a second terminal — pick whichever you prefer):

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

The default install ships in **observe-only** mode — no LSM enforcement, no
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

- **journald** (default) — structured fields (`DETECTOR=`, `SEVERITY=`,
  `PID=`, `CORRELATION_ID=`, …) for `journalctl -o json | jq`
- **Prometheus** — `/metrics` endpoint on `127.0.0.1:9101` (off by default;
  `9101` not `9100` to avoid collision with `node_exporter`)
- **HTTP webhook** — POSTs the alert JSON to any URL you configure;
  ready-made adapter recipes for Slack and Telegram bots (small Python
  scripts that bridge the webhook to the respective bot API) live in
  [`docs/integrations/slack-telegram.md`](docs/integrations/slack-telegram.md),
  and the same pattern extends to any custom receiver
- **Falco-compatible JSON** — drop-in for SIEM/aggregators that already
  ingest Falco
- **Plain text / JSON-lines on stdout** — for ad-hoc piping

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
  signature check — kernel module signing remains the kernel's job.
- **No managed cloud version.** Self-hosted only.
- **Linux only.** macOS / Windows are out of scope by design — eBPF is a
  Linux feature.
- **The network detector is IPv4-only.** Its kernel-side BPF probe filters
  out anything that isn't `AF_INET`, so IPv6 connections are not observed
  at all in v0.1 (they don't alert, but they also don't show up). The
  destination CIDR allowlist is therefore IPv4-only too. Kernel-side IPv6
  hooks land in v0.2 (see roadmap).
- **No release artifacts yet.** v0.1.0-preview is built from source. Debian /
  RPM / OCI images land in v0.2 (see roadmap).

If any of those are deal-breakers, you probably want a commercial EDR or one
of the larger CNCF tools. If they're acceptable trade-offs, read on.

---

## Roadmap 2026

This is a single-maintainer project at a conservative cadence. One
quarter — one or two minor versions.

### Q2 2026 — v0.1.x patch series

Closing the v0.1 punch list and shipping installable packages.

- `--dry-run` / `--audit-only` mode for LSM enforcement (logs "would-block"
  decisions without enforcing them — lets operators canary the policy)
- BPF-side `kr_stats` counters surfaced through the Prometheus exporter
  (currently observable only via `bpftool map dump`)
- IPv6 destination CIDR allowlist for the network detector
- Per-detector documentation (one page each: what it catches, what it
  misses, how to tune it)
- `docs/integrations/email.md` (msmtp / exim recipe)
- Debian / Ubuntu `.deb` package — first installable release artifact

### Q3 2026 — v0.2

New detectors, persistence/execution coverage, platform expansion.

- **DNS anomaly detector** — DGA / suspicious resolver patterns
- **Reverse-shell heuristics detector** — process-tree shape + symbolic
  port matching (independent of the existing port-blocklist in the
  network detector)
- **Persistence detector** — additions to `~/.bashrc`, `~/.profile`,
  cron / at jobs, systemd unit files, init.d scripts, and SUID-bit
  flips. Covers MITRE TA0003.
- **Exec-anomaly detector** — `execve` from `/tmp`, `/dev/shm`,
  `/var/tmp`; suspicious parent-child mismatches (web server → shell);
  LOLBin-style patterns (curl piping into shell). Covers MITRE TA0002.
- Pluggable threat-intel adapter for the network detector (one default
  feed shipped — likely a public CIDR blocklist)
- ARM64 cross-compile + qemu-based CI matrix
- OCI distroless container image
- RPM package for Fedora / RHEL
- Reproducible builds + SBOM generation
- GPG-signed releases

### Q4 2026 — v0.3

Detection breadth and (lightly) UX.

- **Memory anomaly detector** — heap-spray patterns, suspicious slab
  allocations via perf counters
- **Ransomware-behavior detector** — mass-rename heuristic: N+ files
  renamed within T seconds by one process, especially with a uniform
  new extension (the typical encryption signature). Covers MITRE TA0040.
- Embedded read-only HTTP UI (single binary, no separate frontend stack):
  recent alerts, baseline state, detector status, `/metrics` proxy
- Optional Kubernetes operator + Helm chart in a separate
  `kernelradar-k8s` repository (so the core binary stays k8s-free)
- Production-hardening pass: 24-hour KASAN soak in CI, anti-tamper
  improvements

### Q1 2027 — v1.0 (LTS)

Feature-stable cut after community feedback. 12-month support window with
backported security fixes.

**Candidates for v1.1+ on community demand:** audit-tamper detector
(catches attempts to disable auditd / journald), proc-hide detector
(rootkit PID-hiding via `/proc` enumeration mismatch), mount-anomaly
detector (privileged container mounts).

Roadmap moves with reality. The
[backlog file](k-radar_backlog.md) is the authoritative live tracker;
this section is a snapshot.

---

## Security model

What `kernelradar` actually does to your system, in one paragraph:

It loads 12 BPF programs into the kernel via the standard `bpf()` syscall
under `CAP_BPF` + `CAP_PERFMON` (no need for full root on kernels ≥5.8).
Eight of those are read-only tracepoint observers. Three are LSM hooks for
optional enforcement and self-protection — **off by default**. One is a
shared statistics map. When the daemon exits — including on `SIGKILL`,
panic, or `OOM` — every BPF program detaches automatically (Aya's `Drop`
impl). There are no kernel modules, no `/proc/sys` modifications, no
`sysctl` tweaks, no persistent on-disk state outside `/var/lib/kernelradar/`.
Network egress is opt-in (webhook / Prometheus only when explicitly
enabled). Default behaviour is "watch and report" — `kernelradar` does
not kill processes or block syscalls unless you explicitly enable the
LSM enforcement mode.

For the threat model, in-scope vs out-of-scope attackers, and what an
attacker with root can and cannot do to this tool, see
[`docs/threat-model.md`](docs/threat-model.md) and
[`docs/hardening.md`](docs/hardening.md).

**Reporting vulnerabilities:** see [`SECURITY.md`](SECURITY.md) (coming with v0.1.0).

---

## License

GPL-2.0-only — see [`LICENSE`](LICENSE) for the verbatim text.

The BPF programs require GPL because they call kernel BPF helpers that are
GPL-only; the userspace Rust code is GPL-2.0-only by symmetry. Practical
consequence: you can use `kernelradar` for any purpose, including
commercial deployments, but if you fork it and ship a derivative work, the
derivative must also be GPL-2.0-only and its source must be available. No
closed-source proprietary forks.

---

## Contributing

Issue and pull-request templates ship with v0.1.0; see
[`CONTRIBUTING.md`](CONTRIBUTING.md) (coming).

Until then: open an issue describing what you'd like to change, and we'll
figure it out from there.

---

# kernelradar — русская версия

> Поведенческое обнаружение аномалий в ядре Linux через eBPF —
> один Rust-бинарник, без Kubernetes, без SaaS, без телеметрии наружу.

🇬🇧 [English](#kernelradar) · 🇷🇺 **Русский**

---

> 🤝 **Энтузиастам.** kernelradar разрабатывается открыто — одним
> человеком и небольшим кругом участников. Если ты держишь
> инфраструктуру небольшого парка серверов, профессионально занимаешься
> безопасностью Linux, пишешь на Rust или BPF C — или просто убеждён,
> что наблюдаемость Linux не должна требовать SaaS-подписки — твоя
> помощь нужна. Заведи баг, пришли `pull request`, напиши
> документацию, портируй детектор, собери пакет под свой дистрибутив
> или просто поставь репозиторию звезду, чтобы другие его нашли.
> Дорожная карта ниже — это направление, а не забор: если у тебя есть
> реальный сценарий, требующий другого детектора, — открой `issue`,
> обсудим.

---

## Что это и зачем

`kernelradar` наблюдает за Linux-машиной изнутри ядра через eBPF и в
реальном времени отмечает подозрительную активность: повышение привилегий,
загрузку BPF-руткитов, побеги из контейнеров, установку неподписанных
модулей ядра, нарушение целостности файлов, исходящие соединения на порты
типичных reverse shell, инъекции в процессы, чтение файлов с учётными
данными.

В одной нише с open-source инструментами **Falco**, **Tetragon**,
**Tracee** и коммерческими EDR — **SentinelOne**, **CrowdStrike Falcon**,
**Sysdig Secure**.

Чем отличается:

- **Адаптивный учёт нормы и оценка отклонений по сигме.** Учится тому,
  как выглядит «норма» на каждой конкретной машине (модель EWMA — по
  детектору, по процессу, по часу суток) и помечает статистические
  отклонения, а не только срабатывания статичных правил.
- **Один бинарник, ~80 МБ резидентной памяти.**
  Положил на сервер, направил на journald — и забыл.
- **Про то, чего пока нет.** Нет веб-интерфейса. Нет централизованного
  управления. Нет интеграции с источниками разведки угроз. Нет
  автоматического реагирования в установке по умолчанию. Подключай тот
  стек наблюдаемости, который у тебя уже есть (journald, Prometheus,
  Loki, Vector, Wazuh, Slack, Telegram, любой SIEM с поддержкой Falco)
  — рецепты в [`docs/integrations/`](docs/integrations/).

**Сделан для инженера DevOps или сисадмина с 5–50 серверами**, у которого
бюджет не тянет корпоративные EDR-подписки, но кто всё равно хочет знать
в реальном времени, когда на проде кто-то делает `setuid(0)`, загружает
неподписанный модуль ядра, открывает `/etc/shadow` или связывается с
внешней сетью из незнакомого процесса.

> ⚠️ **Статус: v0.1.0-preview.** Все восемь детекторов реализованы и
> протестированы на реальной машине (Debian 12, ядро 6.13). Цифры
> производительности и надёжности ниже — измеренные, не обещанные.
> Но это молодой проект: сначала обкатайте на некритичной машине,
> прочитайте [модель безопасности](#модель-безопасности) — и только
> потом подключайте к контурам, дёргающим дежурного.

---

## Сравнение

| | kernelradar | Falco | Tetragon | Tracee | Коммерческий EDR |
|---|---|---|---|---|---|
| Лицензия | GPL-2.0-only | Apache-2.0 | Apache-2.0 | Apache-2.0 | проприетарная |
| Модель обнаружения | Правила + **адаптивная норма** | Правила | Политики | Сигнатуры | ML + облачные правила |
| Память в простое (RSS) | **65–80 МБ** | ~200 МБ | ~500 МБ | ~300 МБ | варьируется |
| Один самодостаточный бинарник | ✅ | ✅ | частично (сначала под k8s) | ✅ | — |
| Требует Kubernetes | ❌ | ❌ | обычно да | ❌ | — |
| Веб-интерфейс / панель управления | ❌ | ❌ (сторонние) | ❌ (Hubble) | ❌ | ✅ |
| Блокировка через LSM (режим запрета) | ✅ по подписке | ❌ | ✅ | ❌ | ✅ |
| SaaS / данные уходят с хоста | ❌ | ❌ | ❌ | ❌ | ✅ |
| Месячная стоимость на хост | бесплатно | бесплатно | бесплатно | бесплатно | обычно десятки долларов |

Цифры по бесплатным аналогам — приближения из их документации; цифры
`kernelradar` — собственные измерения на самой слабой официально
поддерживаемой машине (см. [Производительность](#производительность)).

---

## Производительность

Цифры собраны на самой слабой машине, на которой `kernelradar` официально
поддерживается, чтобы показать худший случай. На реальном серверном
железе (Xeon, Threadripper, Ampere) ожидайте в 5–20 раз лучше.

**Железо:** Intel Celeron J4125 @ 2.0 ГГц · 4 ядра · без SMT · 8 ГБ DDR4 ·
Linux 6.13.9 · Debian 12.

| Метрика | Значение |
|---|---|
| Устойчивая скорость обработки событий (на стороне ядра, через `tracepoint`) | **321 000 событий/сек** |
| Память в простое (RSS) | **65–80 МБ** |
| Пик RSS под нагрузкой в 100 000 событий | 136 МБ |
| Прирост памяти после возврата в простой | **0 байт** |
| CPU в простое | <0.1 % одного ядра |
| CPU под постоянной нагрузкой | ~28 % одного ядра |
| Корректное завершение (`SIGTERM` → выгрузка всех 12 BPF-программ) | **641 мс** |

Полная методология и поэтапная разбивка — в
[`docs/performance.md`](docs/performance.md).

---

## Быстрый старт

### Вариант A — поставить готовый релиз (Linux x86_64)

```bash
# 1. Скачать архив релиза.
curl -fsSLO https://github.com/ferithtools/kernelradar/releases/download/v0.1.0/kernelradar-0.1.0-linux-x86_64.tar.gz

# 2. Проверить против SHA-256, запиннованного в исходниках
#    (защита от подмены: даже если CDN скомпрометирован, не пройдёт).
EXPECTED=$(curl -fsSL https://raw.githubusercontent.com/ferithtools/kernelradar/v0.1.0/release-checksums/v0.1.0/kernelradar-0.1.0-linux-x86_64.tar.gz.sha256 | awk '{print $1}')
ACTUAL=$(sha256sum kernelradar-0.1.0-linux-x86_64.tar.gz | awk '{print $1}')
[ "$EXPECTED" = "$ACTUAL" ] || { echo "TAMPERED — не ставить"; exit 1; }

# 3. Распаковать и запустить установщик из комплекта.
tar -xzf kernelradar-0.1.0-linux-x86_64.tar.gz
cd kernelradar-0.1.0-linux-x86_64
sha256sum -c SHA256SUMS                  # проверить каждый файл архива
./install.sh                              # бинарь, BPF, systemd unit, конфиг по умолчанию
sudo systemctl enable --now kernelradar
journalctl -u kernelradar -f -o cat
```

> 🔒 Релиз подписан только SHA-256, который зафиксирован в дереве
> исходников. GPG-подпись релизов появится в v0.2 (T-15.6).

### Вариант B — собрать из исходников

Установить зависимости (Debian/Ubuntu):

```bash
sudo apt install -y build-essential clang llvm libbpf-dev libelf-dev \
    pkg-config bpftool linux-tools-common
```

Установить Rust (если ещё нет):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Собрать и запустить:

```bash
git clone https://github.com/ferithtools/kernelradar.git
cd kernelradar

# 1. Собрать BPF-объекты
( cd crates/kernelradar-bpf && make )

# 2. Собрать демон в пространстве пользователя
cargo build --release

# 3. Проверить конфиг и запустить
sudo ./target/release/kernelradar config-cmd validate
sudo ./target/release/kernelradar daemon \
    --bpf-dir crates/kernelradar-bpf/.output \
    --format=plain
```

Смотреть алерты в реальном времени (отдельный терминал):

```bash
# С --format=plain (выше) алерты идут в `stdout` демона.
# Для systemd-установки демон по умолчанию пишет в journald:
journalctl -t kernelradar -f
```

Постоянная установка:

```bash
sudo make install            # бинарник, BPF, systemd unit, конфиг по умолчанию
sudo systemctl enable --now kernelradar
journalctl -u kernelradar -f
```

Установка по умолчанию — режим **только наблюдения**: без блокировки
через LSM, без остановки процессов, без исходящих `webhook`-вызовов.
Перед включением чего-либо из этого прочитайте
[`docs/hardening.md`](docs/hardening.md).

---

## Детекторы (v0.1)

| # | Детектор | Что ловит |
|---|---|---|
| 1 | **privesc** | `setuid(0)` / `setgid(0)` от непривилегированных процессов |
| 2 | **bpf-loader** | `BPF_PROG_LOAD` от процессов, не входящих в `allowlist` (BPF-руткиты) |
| 3 | **container** | `unshare()` / `setns()` — признаки побега из cgroup/namespace |
| 4 | **kmod** | `init_module` / `finit_module` (руткиты через модули ядра) |
| 5 | **fim** | `openat()` с записью/дозаписью/созданием на чувствительных путях (`/etc/passwd`, `/etc/shadow`, SSH-ключи, …) |
| 6 | **network** | Исходящий `connect()` на публичные IPv4 с повышением уровня тревоги для известных портов reverse-shell |
| 7 | **injection** | `ptrace(PTRACE_ATTACH/SEIZE/POKE*)` и `process_vm_writev()` |
| 8 | **cred** | Чтение файлов с учётными данными (shadow, sudoers, приватные ключи SSH, браузерные cookies, …) |

Каждый детектор формирует структурированный `Alert` со стабильной схемой
(`correlation_id`, `severity`, `detector`, `title`, `pid`, `uid`, `comm`,
`context` + полезная нагрузка детектора). Каноническая структура —
[`crates/kernelradar-core/src/alert.rs`](crates/kernelradar-core/src/alert.rs);
форматы вывода — [`docs/logging.md`](docs/logging.md).

---

## Каналы вывода и интеграции

`kernelradar` не запускает свою панель управления — он говорит на тех
протоколах, которые ты уже используешь. Выбирай канал(ы) под свой стек:

- **journald** (по умолчанию) — структурированные поля (`DETECTOR=`,
  `SEVERITY=`, `PID=`, `CORRELATION_ID=`, …) для
  `journalctl -o json | jq`.
- **Prometheus** — точка `/metrics` на `127.0.0.1:9101` (по умолчанию
  выключена; `9101`, а не `9100`, чтобы не конфликтовать с
  `node_exporter`).
- **HTTP `webhook`** — отправляет POST с JSON алерта на любой URL,
  указанный в конфиге; готовые рецепты адаптеров для Slack и
  Telegram-ботов (небольшие Python-скрипты, мостящие `webhook` к API
  бота) — в
  [`docs/integrations/slack-telegram.md`](docs/integrations/slack-telegram.md);
  тот же подход расширяется на любой другой приёмник.
- **Совместимый с Falco JSON** — готовый формат для SIEM-систем и
  агрегаторов, которые уже умеют принимать Falco.
- **Обычный текст / JSON-строки в `stdout`** — для разовых пайпов и
  отладки.

Готовые конфиги — в [`docs/integrations/`](docs/integrations/) для:
[Wazuh](docs/integrations/wazuh.md),
[Prometheus](docs/integrations/prometheus.md),
[Loki / Vector / Fluent Bit](docs/integrations/loki-vector-fluentbit.md),
[Slack & Telegram](docs/integrations/slack-telegram.md),
[SIEM с поддержкой Falco](docs/integrations/falco.md).

---

## Архитектура (high-level)

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

Полный поток событий, расположение модулей и модель угроз — в
[`docs/architecture.md`](docs/architecture.md) и
[`docs/threat-model.md`](docs/threat-model.md).

---

## Чего пока (или вообще) нет

- **Нет веб-панели.** Подключай свою — Grafana поверх Prometheus,
  Wazuh, любой SIEM, который читает journald или JSON в формате Falco.
- **Нет управления флотом из нескольких хостов.** `kernelradar`
  работает на отдельно взятом хосте. Агрегируйте журналы через Loki,
  Vector или Fluent Bit (рецепты есть).
- **Нет интеграции с источниками разведки угроз.** Обнаружение чисто
  локальное: эвристики и адаптивная норма. Без подписок на индикаторы
  компрометации (IOC).
- **Нет автоматического реагирования в установке по умолчанию.** Режим
  блокировки через LSM (запрет `BPF_PROG_LOAD` от процессов, не входящих
  в `allowlist`; запрет загрузки `kmod` от процессов, не входящих в
  `allowlist`; защита самого `kernelradar` от попыток убийства процесса)
  включается явно и по умолчанию выключен. По умолчанию работаем по
  принципу «наблюдай и сообщай». Уточнение: перехватчик `kmod` — это
  список разрешённых процессов по `comm`, а не проверка подписи
  модуля; подписи модулей по-прежнему проверяет ядро через
  `CONFIG_MODULE_SIG_FORCE`.
- **Нет облачной (managed) версии.** Только локальная установка на
  своём железе.
- **Только Linux.** macOS / Windows вне области применения изначально —
  eBPF это механизм ядра Linux.
- **Сетевой детектор работает только с IPv4.** BPF-фильтр на стороне
  ядра отбрасывает всё, что не `AF_INET`, поэтому IPv6-соединения в
  v0.1 вообще не наблюдаются (они не дают тревог, но и не попадают в
  журнал). Список разрешённых CIDR соответственно тоже только под IPv4.
  Перехватчики IPv6 на стороне ядра появятся в v0.2 (см. roadmap).
- **Готовых пакетов для установки пока нет.** v0.1.0-preview собирается
  из исходников. Пакеты Debian / RPM и OCI-образы — в v0.2 (см. roadmap).

Если что-то из этого критично — скорее всего нужен коммерческий EDR
или один из крупных инструментов CNCF. Если компромиссы приемлемы —
читай дальше.

---

## Дорожная карта 2026

Проект ведёт один человек, темп консервативный. Один квартал — 1–2
минорные версии.

### Q2 2026 — серия патчей v0.1.x

Доделываем хвосты v0.1 и выпускаем готовые к установке пакеты.

- Режим `--dry-run` / `--audit-only` для блокировки через LSM: вместо
  фактического запрета пишет в журнал, что было бы заблокировано — можно
  обкатать политику без риска для прода.
- Счётчики `kr_stats` (наблюдённые и потерянные события на стороне
  BPF) — отдаются через Prometheus; сейчас их видно только через
  `bpftool map dump`.
- Список разрешённых CIDR под IPv6 для сетевого детектора (сейчас
  фильтр работает только по IPv4).
- Отдельная страница документации на каждый детектор: что ловит, что
  пропускает, как тюнить.
- `docs/integrations/email.md` — рецепт отправки тревог через
  msmtp / exim.
- Пакет `.deb` для Debian / Ubuntu — первый готовый к установке релиз
  (до этого только сборка из исходников).

### Q3 2026 — v0.2

Новые детекторы, покрытие персистентности и подозрительного запуска,
расширение платформы.

- **Детектор подозрительных DNS-запросов** — алгоритмически
  сгенерированные домены (DGA), нетипичные паттерны обращений к
  резолверу.
- **Детектор эвристик reverse-shell** — анализ формы дерева процессов
  + совпадение «говорящих» портов с подозрительным родителем (отдельно
  от существующего списка опасных портов в сетевом детекторе).
- **Детектор персистентности** — отслеживает создание и правку
  `~/.bashrc`, `~/.profile`, задач cron / at, юнитов systemd,
  скриптов init.d, выставление SUID-битов. Закрывает тактику
  MITRE TA0003.
- **Детектор аномального запуска** — `execve` из `/tmp`, `/dev/shm`,
  `/var/tmp`; несовпадение родителя и дочернего процесса (веб-сервер
  → shell); шаблоны LOLBin (curl, перенаправленный в shell). Закрывает
  тактику MITRE TA0002.
- Подключаемый адаптер разведки угроз для сетевого детектора — с одним
  готовым источником в комплекте (скорее всего публичный список
  CIDR-блоков).
- Кросс-компиляция под ARM64 + матрица CI на qemu.
- OCI-образ контейнера на основе distroless.
- Пакет RPM для Fedora / RHEL.
- Воспроизводимая сборка + генерация SBOM.
- Релизы с подписью GPG.

### Q4 2026 — v0.3

Расширение охвата и лёгкое улучшение пользовательского опыта.

- **Детектор аномалий памяти** — шаблоны heap-spray (рассеивание
  шеллкода по куче), подозрительные slab-аллокации через счётчики
  perf.
- **Детектор поведения шифровальщиков** — эвристика массового
  переименования: N+ файлов переименовано за T секунд одним процессом
  (особенно с одинаковым новым расширением — типичный признак
  шифровальщика). Закрывает тактику MITRE TA0040.
- Встроенный HTTP-интерфейс только для чтения (всё в одном бинарнике,
  без отдельной фронтенд-сборки): свежие тревоги, состояние нормы,
  статус детекторов, проксирование `/metrics`.
- Необязательный оператор Kubernetes + чарт Helm в отдельном
  репозитории `kernelradar-k8s` (чтобы основной бинарник оставался
  независимым от k8s).
- Доводка до промышленного уровня: 24-часовой прогон с KASAN в CI,
  улучшения защиты от подмены.

### Q1 2027 — v1.0 (LTS)

Стабильный релиз: новые детекторы и крупные функции замораживаются,
дальше — только исправления ошибок и патчи безопасности. Цель — версия,
на которую можно закладываться в проде на год вперёд. Поддержка линии
v1.0 — 12 месяцев с обратным переносом исправлений безопасности.

**Кандидаты на v1.1+ по запросу сообщества:** детектор подделки журналов
аудита (попытки отключения auditd / journald), детектор скрытых
процессов (поиск PID, спрятанных руткитом, через несовпадение
`/proc` и реального состояния ядра), детектор аномальных монтирований
(привилегированные mount-ы внутри контейнера).

Дорожная карта живая и корректируется по обстановке. Актуальное
состояние — всегда в [файле backlog](k-radar_backlog.md); этот раздел
— снимок на момент публикации.

---

## Модель безопасности

Что `kernelradar` реально делает с системой, в одном абзаце:

Он загружает 12 BPF-программ в ядро через стандартный системный
вызов `bpf()` под `CAP_BPF` + `CAP_PERFMON` (полный root на ядрах
≥5.8 не нужен). Восемь из них — пассивные наблюдатели на точках
трассировки: только читают, ничего не меняют. Три — перехватчики
LSM для необязательной блокировки и самозащиты, **по умолчанию
выключены**. Один — общая карта счётчиков. При завершении демона
— включая `SIGKILL`, панику, OOM — каждая BPF-программа
автоматически отсоединяется (через реализацию `Drop` в Aya).
Никаких модулей ядра, никаких правок `/proc/sys`, никаких
изменений `sysctl`, никакого сохраняемого состояния на диске
кроме `/var/lib/kernelradar/`. Исходящий сетевой трафик
включается явно (webhook и Prometheus оба выключены по
умолчанию). По умолчанию `kernelradar` только наблюдает и
сообщает — не убивает процессы и не блокирует системные вызовы
пока не включён режим блокировки через LSM.

Модель угроз, какие атакующие в зоне ответственности и какие — нет,
что может и не может сделать с этим инструментом атакующий с правами
root — см. [`docs/threat-model.md`](docs/threat-model.md) и
[`docs/hardening.md`](docs/hardening.md).

**Сообщение об уязвимостях:** см. [`SECURITY.md`](SECURITY.md)
(с v0.1.0).

---

## Лицензия

GPL-2.0-only — дословный текст в [`LICENSE`](LICENSE).

BPF-программы обязаны быть совместимы с GPL, потому что вызывают
вспомогательные функции BPF в ядре, доступные только под GPL; код
на Rust в пространстве пользователя — тоже под GPL-2.0-only по
симметрии. Практическое следствие: `kernelradar` можно использовать
для любых задач, включая коммерческие установки. Но если ты сделаешь
форк и выпустишь производное — оно тоже должно быть под GPL-2.0-only с
открытыми исходниками. Закрытых проприетарных форков быть не может.

---

## Как поучаствовать

Шаблоны для `issue` и `pull request` появятся с v0.1.0; см.
[`CONTRIBUTING.md`](CONTRIBUTING.md) (будет).

А пока — открой `issue` с описанием того, что хочешь поменять, дальше
разберёмся.
