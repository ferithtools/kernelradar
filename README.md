# kernelradar

> Behavioral anomaly detection for the Linux kernel via eBPF —
> a single Rust binary, no Kubernetes, no SaaS, no telemetry leaving the host.

[![License: GPL-2.0-only](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](LICENSE)
[![CI](https://github.com/ferith-tools/kernelradar/actions/workflows/ci.yml/badge.svg)](https://github.com/ferith-tools/kernelradar/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-v0.1.0--preview-orange.svg)](#)
[![Linux only](https://img.shields.io/badge/platform-linux--6.1%2B-lightgrey.svg)](#)

🇬🇧 **English** · [🇷🇺 Русский](#kernelradar--русская-версия)

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

What makes `kernelradar` different:

- **Adaptive baseline + sigma-based anomaly scoring.** It learns what "normal"
  looks like for each individual host (per-detector, per-process, per-hour-of-day
  EWMA model) and flags statistical deviations — not just static rule matches.
  The free peers are rule-based; this is closer to commercial EDR baselining.
- **One Rust binary, ~80 MB resident, no Kubernetes.** Drop it on the server,
  point it at journald, walk away. No SaaS dashboard. No cloud account. No
  per-host subscription.
- **Honest about what it doesn't do.** No web UI. No fleet manager. No threat-
  intel feed. No automated remediation in the default install. Pair it with the
  observability stack you already run (journald, Prometheus, Loki, Vector,
  Wazuh, Slack, Telegram, anything Falco-compatible) — recipes are in
  [`docs/integrations/`](docs/integrations/).

**Built for the DevOps engineer or sysadmin running 5–50 servers** whose budget
skips enterprise EDR subscriptions but who still wants to know — in real time
— when something on a production box runs `setuid(0)`, loads an unsigned
kernel module, opens `/etc/shadow`, or phones home from a process you don't
recognize.

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
git clone https://github.com/ferith-tools/kernelradar.git
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
- **HTTP webhook** — POSTs the alert JSON; bridges to Slack, Telegram bots,
  PagerDuty, custom receivers
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
  unsigned `kmod` loads, block kill of the kernelradar process itself) is
  opt-in and off by default. Default = observe + alert.
- **No managed cloud version.** Self-hosted only.
- **Linux only.** macOS / Windows are out of scope by design — eBPF is a
  Linux feature.
- **IPv6 destination filtering not yet supported.** The network detector's
  CIDR allowlist is IPv4-only for v0.1; IPv6 destinations always alert.
- **No release artifacts yet.** v0.1.0-preview is built from source. Debian /
  RPM / OCI images land in v0.2 (see roadmap).

If any of those are deal-breakers, you probably want a commercial EDR or one
of the larger CNCF tools. If they're acceptable trade-offs, read on.

---

## Roadmap 2026

This is a single-maintainer project working at a conservative cadence. Each
quarter takes 1–2 minor versions; targets are realistic, not aspirational.

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

New detectors and platform expansion.

- **DNS anomaly detector** — DGA / suspicious resolver patterns
- **Reverse-shell heuristics detector** — process-tree shape + symbolic
  port matching (independent of the existing port-blocklist in the
  network detector)
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
- Embedded read-only HTTP UI (single binary, no separate frontend stack):
  recent alerts, baseline state, detector status, `/metrics` proxy
- Optional Kubernetes operator + Helm chart in a separate
  `kernelradar-k8s` repository (so the core binary stays k8s-free)
- Production-hardening pass: 24-hour KASAN soak in CI, anti-tamper
  improvements

### Q1 2027 — v1.0 (LTS)

Feature-stable cut after community feedback. 12-month support window with
backported security fixes.

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

## Что это и зачем

`kernelradar` наблюдает за Linux-машиной изнутри ядра через eBPF и в
реальном времени отмечает подозрительную активность: повышение привилегий,
загрузку BPF-руткитов, побеги из контейнеров, установку неподписанных
модулей ядра, нарушение целостности файлов, исходящие соединения на порты
типичных reverse shell, инъекции в процессы, чтение файлов с учётными
данными.

Живёт в той же категории, что open-source инструменты **Falco**,
**Tetragon**, **Tracee** и коммерческие EDR — **SentinelOne**,
**CrowdStrike Falcon**, **Sysdig Secure**.

Чем отличается:

- **Адаптивный baseline и sigma-based anomaly scoring.** Учится тому, как
  выглядит "норма" на каждой конкретной машине (per-detector, per-process,
  per-hour-of-day EWMA-модель) и помечает статистические отклонения, а не
  только срабатывания статичных правил. Free-аналоги — чисто rule-based;
  это ближе к baseline-логике коммерческих EDR.
- **Один Rust-бинарник, ~80 МБ резидентной памяти, без Kubernetes.**
  Положил на сервер, направил на journald, забыл. Без SaaS-панели, без
  облачного аккаунта, без подписки на хост.
- **Честно про то, чего нет.** Нет web-UI. Нет fleet-менеджера. Нет
  подписок на threat-intel. Нет автоматического реагирования в дефолтной
  установке. Подключай тот стек наблюдаемости, что у тебя уже есть
  (journald, Prometheus, Loki, Vector, Wazuh, Slack, Telegram, любой
  Falco-совместимый SIEM) — рецепты в [`docs/integrations/`](docs/integrations/).

**Сделан для DevOps-инженера или сисадмина с 5–50 серверами**, у которого
бюджет не покрывает enterprise EDR-подписки, но кто всё равно хочет
знать в реальном времени, когда на проде кто-то делает `setuid(0)`,
загружает неподписанный модуль ядра, открывает `/etc/shadow` или ходит
наружу из неизвестного процесса.

> ⚠️ **Статус: v0.1.0-preview.** Все восемь детекторов реализованы и
> протестированы на реальной машине (Debian 12, ядро 6.13). Цифры
> производительности и надёжности ниже — измеренные, не обещанные. Но это
> молодой проект: сначала пилотируйте на некритичной машине, прочитайте
> [модель безопасности](#модель-безопасности), и только после этого
> подключайте к контурам, дёргающим on-call.

---

## Сравнение

| | kernelradar | Falco | Tetragon | Tracee | Commercial EDR |
|---|---|---|---|---|---|
| Лицензия | GPL-2.0-only | Apache-2.0 | Apache-2.0 | Apache-2.0 | proprietary |
| Модель детектирования | Правила + **adaptive baseline** | Правила | Policies | Сигнатуры | ML + cloud rules |
| Idle RSS (footprint) | **65–80 МБ** | ~200 МБ | ~500 МБ | ~300 МБ | varies |
| Один self-contained binary | ✅ | ✅ | частично (k8s-first) | ✅ | n/a |
| Требует Kubernetes | ❌ | ❌ | обычно да | ❌ | n/a |
| Web-UI / dashboard | ❌ | ❌ (third-party) | ❌ (Hubble) | ❌ | ✅ |
| LSM enforcement (block-режим) | ✅ opt-in | ❌ | ✅ | ❌ | ✅ |
| SaaS / данные уходят с хоста | ❌ | ❌ | ❌ | ❌ | ✅ |
| Месячная стоимость на хост | бесплатно | бесплатно | бесплатно | бесплатно | обычно десятки долларов |

Цифры по free-аналогам — приближения из их документации; цифры
`kernelradar` — наши прямые измерения на самой слабой официально
поддерживаемой машине (см. [Производительность](#производительность)).

---

## Производительность

Цифры собраны на самой слабой машине, на которой `kernelradar` официально
поддерживается, чтобы дать worst-case floor. На реальном серверном железе
(Xeon, Threadripper, Ampere) ожидайте в 5–20 раз лучше.

**Железо:** Intel Celeron J4125 @ 2.0 ГГц · 4 ядра · без SMT · 8 ГБ DDR4 ·
Linux kernel 6.13.9 · Debian 12.

| Метрика | Значение |
|---|---|
| Устойчивая пропускная способность (BPF tracepoint, kernel-side) | **321 000 событий/сек** |
| Idle resident memory (RSS) | **65–80 МБ** |
| Пик RSS под флудом 100 000 событий | 136 МБ |
| Прирост памяти после возвращения в idle | **0 байт** |
| CPU в idle | <0.1 % одного ядра |
| CPU под устойчивым флудом | ~28 % одного ядра |
| Graceful shutdown (SIGTERM → выгрузка всех 12 BPF-программ) | **641 мс** |

Полная методология и поэтапная разбивка — в
[`docs/performance.md`](docs/performance.md).

---

## Быстрый старт

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
git clone https://github.com/ferith-tools/kernelradar.git
cd kernelradar

# 1. Собрать BPF-объекты
( cd crates/kernelradar-bpf && make )

# 2. Собрать userspace-демон
cargo build --release

# 3. Проверить конфиг и запустить
sudo ./target/release/kernelradar config-cmd validate
sudo ./target/release/kernelradar daemon \
    --bpf-dir crates/kernelradar-bpf/.output \
    --format=plain
```

Смотреть алерты в реальном времени (отдельный терминал):

```bash
# С --format=plain (выше) алерты идут в stdout демона.
# Для systemd-установки демон по умолчанию пишет в journald:
journalctl -t kernelradar -f
```

Постоянная установка:

```bash
sudo make install            # бинарник, BPF, systemd unit, дефолтный конфиг
sudo systemctl enable --now kernelradar
journalctl -u kernelradar -f
```

Дефолтная установка — режим **observe-only**: без LSM enforcement, без
блокировки процессов, без исходящих webhook'ов. Перед включением чего-либо
из этого прочитайте [`docs/hardening.md`](docs/hardening.md).

---

## Детекторы (v0.1)

| # | Детектор | Что ловит |
|---|---|---|
| 1 | **privesc** | `setuid(0)` / `setgid(0)` от непривилегированных процессов |
| 2 | **bpf-loader** | `BPF_PROG_LOAD` от процессов вне allowlist'а (BPF-руткиты) |
| 3 | **container** | `unshare()` / `setns()` — паттерны побега из cgroup/namespace |
| 4 | **kmod** | `init_module` / `finit_module` (руткиты через модули ядра) |
| 5 | **fim** | `openat()` с write/append/create на чувствительных путях (`/etc/passwd`, `/etc/shadow`, ssh-ключи, …) |
| 6 | **network** | Исходящий `connect()` на публичные IPv4 с повышением severity для известных reverse-shell портов |
| 7 | **injection** | `ptrace(PTRACE_ATTACH/SEIZE/POKE*)` и `process_vm_writev()` |
| 8 | **cred** | Чтение файлов с учётными данными (shadow, sudoers, ssh-приватники, browser cookies, …) |

Каждый детектор эмитит структурированный `Alert` со стабильной схемой
(`correlation_id`, `severity`, `detector`, `title`, `pid`, `uid`, `comm`,
`context` + per-detector payload). Каноническая структура —
[`crates/kernelradar-core/src/alert.rs`](crates/kernelradar-core/src/alert.rs);
форматы вывода — [`docs/logging.md`](docs/logging.md).

---

## Каналы вывода и интеграции

`kernelradar` не запускает свою dashboard'у — он говорит на тех протоколах,
которые ты уже используешь. Выбирай канал(ы) под свой стек:

- **journald** (по умолчанию) — структурированные поля (`DETECTOR=`,
  `SEVERITY=`, `PID=`, `CORRELATION_ID=`, …) для `journalctl -o json | jq`
- **Prometheus** — `/metrics` endpoint на `127.0.0.1:9101` (выкл. по
  умолчанию; `9101` а не `9100` — чтобы не конфликтовать с `node_exporter`)
- **HTTP webhook** — POST'ит JSON алерта; адаптеры на Slack, Telegram-боты,
  PagerDuty, кастомные приёмники
- **Falco-совместимый JSON** — drop-in для SIEM/агрегаторов, уже
  переваривающих Falco
- **Plain text / JSON-lines в stdout** — для ad-hoc piping

Готовые конфиги — в [`docs/integrations/`](docs/integrations/) для:
[Wazuh](docs/integrations/wazuh.md),
[Prometheus](docs/integrations/prometheus.md),
[Loki / Vector / Fluent Bit](docs/integrations/loki-vector-fluentbit.md),
[Slack & Telegram](docs/integrations/slack-telegram.md),
[Falco-совместимых SIEM](docs/integrations/falco.md).

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

Полный поток событий, layout крейтов и threat model — в
[`docs/architecture.md`](docs/architecture.md) и
[`docs/threat-model.md`](docs/threat-model.md).

---

## Чего пока (или вообще) нет

Честно про границы:

- **Нет web-dashboard'а.** Подключай свой (Grafana поверх Prometheus,
  Wazuh, любой SIEM который ест journald / Falco JSON).
- **Нет multi-host fleet management.** `kernelradar` работает per-host.
  Агрегируйте журналы через Loki / Vector / Fluent Bit (рецепты есть).
- **Нет интеграции с threat-intel feeds.** Детектирование чисто локальное:
  эвристики + адаптивный baseline. Без подписок на IOC.
- **Нет автоматического реагирования в дефолтной установке.** Режим LSM
  enforcement (блокировка `BPF_PROG_LOAD` от не-allowlisted процессов,
  блокировка неподписанных kmod-загрузок, защита самого kernelradar от
  kill'а) — opt-in и выкл. по умолчанию. Дефолт = "наблюдай и сообщай".
- **Нет managed cloud версии.** Только self-hosted.
- **Только Linux.** macOS / Windows вне scope by design — eBPF это
  Linux-фича.
- **IPv6 destination фильтр пока не поддерживается.** CIDR allowlist
  network-детектора — IPv4-only для v0.1; IPv6-цели всегда алертят.
- **Релизные артефакты пока отсутствуют.** v0.1.0-preview собирается из
  исходников. Debian / RPM / OCI образы — в v0.2 (см. roadmap).

Если что-то из этого критично — скорее всего нужен коммерческий EDR или
один из крупных CNCF-инструментов. Если приемлемые компромиссы — читай
дальше.

---

## Roadmap 2026

Single-maintainer проект, консервативный темп. Один квартал — 1–2 minor
версии; цели реалистичные, не аспирационные.

### Q2 2026 — серия патчей v0.1.x

Закрытие v0.1 punch-list'а и выпуск устанавливаемых пакетов.

- Режим `--dry-run` / `--audit-only` для LSM enforcement (логирует
  "would-block" решения без блокировки — оператор может канарить политику)
- BPF-side счётчики `kr_stats` через Prometheus exporter (сейчас
  доступны только через `bpftool map dump`)
- IPv6 destination CIDR allowlist для network-детектора
- Per-detector documentation (по странице на каждый: что ловит, что
  пропускает, как тюнить)
- `docs/integrations/email.md` (рецепт через msmtp / exim)
- Debian / Ubuntu `.deb` пакет — первый устанавливаемый release-артефакт

### Q3 2026 — v0.2

Новые детекторы и расширение платформы.

- **Детектор DNS-аномалий** — DGA / подозрительные resolver-паттерны
- **Детектор reverse-shell эвристик** — форма process-tree + символьное
  сопоставление портов (независимо от существующего port-blocklist'а в
  network-детекторе)
- Pluggable threat-intel адаптер для network-детектора (один дефолтный
  feed в комплекте — скорее всего публичный CIDR-blocklist)
- ARM64 cross-compile + qemu-based CI matrix
- OCI distroless container image
- RPM пакет для Fedora / RHEL
- Воспроизводимая сборка + генерация SBOM
- GPG-подписанные релизы

### Q4 2026 — v0.3

Расширение детектирования и (лёгкий) UX.

- **Детектор аномалий памяти** — heap-spray паттерны, подозрительные slab
  allocation'ы через perf counters
- Embedded read-only HTTP UI (один бинарник, без отдельного фронтенд-стека):
  свежие алерты, состояние baseline, статус детекторов, прокси к `/metrics`
- Опциональный Kubernetes operator + Helm chart в отдельной репе
  `kernelradar-k8s` (чтобы ядро оставалось k8s-free)
- Production hardening: 24-часовой KASAN soak в CI, anti-tamper улучшения

### Q1 2027 — v1.0 (LTS)

Feature-stable выпуск после фидбэка от сообщества. Окно поддержки 12
месяцев с бэкпортом security-фиксов.

Roadmap движется по реальной обстановке. Авторитетный live-tracker — это
[backlog файл](k-radar_backlog.md); этот раздел — снимок состояния.

---

## Модель безопасности

Что `kernelradar` реально делает с системой, в одном абзаце:

Он загружает 12 BPF-программ в ядро через стандартный `bpf()` syscall под
`CAP_BPF` + `CAP_PERFMON` (полный root не нужен на ядрах ≥5.8). Восемь из
них — read-only tracepoint-наблюдатели. Три — LSM-хуки для опционального
enforcement и самозащиты, **выкл. по умолчанию**. Один — общая stats-карта.
При выходе демона — включая `SIGKILL`, panic, OOM — каждая BPF-программа
автоматически отцепляется (Aya `Drop` impl). Никаких модулей ядра, никаких
правок `/proc/sys`, никаких `sysctl`-твиков, никакого персистентного
on-disk state кроме `/var/lib/kernelradar/`. Сетевой исходящий трафик —
opt-in (webhook / Prometheus только при явном включении). Дефолтное
поведение — "watch and report"; `kernelradar` не убивает процессы и не
блокирует syscall'ы пока не включён LSM enforcement-режим.

Threat model, in-scope vs out-of-scope атакующие, что может и не может
сделать с этим инструментом атакующий с root'ом — см.
[`docs/threat-model.md`](docs/threat-model.md) и
[`docs/hardening.md`](docs/hardening.md).

**Репорт уязвимостей:** см. [`SECURITY.md`](SECURITY.md) (с v0.1.0).

---

## Лицензия

GPL-2.0-only — verbatim текст в [`LICENSE`](LICENSE).

BPF-программы требуют GPL потому что используют kernel BPF helpers,
которые GPL-only; userspace Rust код — GPL-2.0-only по симметрии.
Практическое следствие: ты можешь использовать `kernelradar` для любых
целей, включая коммерческие развёртывания, но если форкнешь и выпустишь
производное — оно тоже должно быть GPL-2.0-only с открытыми исходниками.
Закрытых проприетарных форков быть не может.

---

## Контрибьютинг

Issue/PR-шаблоны — с v0.1.0; см. [`CONTRIBUTING.md`](CONTRIBUTING.md)
(будет).

До тех пор: открой issue с описанием того, что хочется поменять — дальше
разберёмся.
