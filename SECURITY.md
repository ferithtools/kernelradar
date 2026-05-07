# Security policy

🇬🇧 **English** · [🇷🇺 Русский](#security-policy--русская-версия)

---

## Reporting a vulnerability

**Do not open a public GitHub issue for security findings.**

Use either of these private channels:

- **GitHub Security Advisories** —
  [open a draft advisory](https://github.com/ferithtools/kernelradar/security/advisories/new)
  on this repository. This is the preferred path: GitHub gates the
  conversation, lets us collaborate on a CVE, and produces a public
  advisory we can ship together with the fix.
- **Email** — `ferithtools@users.noreply.github.com` (this is a
  GitHub-routed address; nothing fancy, no PGP key advertised yet —
  T-15.6 in the backlog tracks adding one).

Please include, at minimum:

- the affected version (`kernelradar --version` output is ideal —
  it carries the git SHA);
- the kernel + distribution you reproduced on;
- a minimal repro or, if a full PoC is risky, a description of the
  trigger;
- the impact you see (information disclosure, denial of service,
  privilege escalation, integrity bypass, etc.).

We acknowledge reports within **3 working days** for triage, and aim
to ship a fix within **30 days** for high-severity issues. Disclosure
is coordinated: by default we publish the advisory + fix together.

## Supported versions

Until v1.0 this project is pre-1.0; only the latest minor line
receives security fixes. After v1.0 (planned Q1 2027 — see
[`README.md`](README.md#roadmap-2026)) the LTS branch will be
maintained for 12 months.

| Version | Supported |
|---|---|
| `master` (HEAD) | ✅ |
| `v0.1.x` | ✅ until `v0.2.0` ships |
| pre-`v0.1.0` (development snapshots) | ❌ |

## What's in scope

Findings we treat as security:

- BPF program logic that gives a wrong answer in a way an attacker
  can leverage (false negative on actual privilege escalation,
  rootkit hide, suspicious connect, etc.).
- Userspace handling of BPF events that produces a wrong attribution
  an attacker can game (e.g. PID-reuse race, exe-path TOCTOU,
  allowlist bypass).
- Integrity-verification holes (`integrity::verify` accepting a
  tampered BPF object in `strict_mode = true`).
- LSM enforcement holes (`enforce_bpf` / `enforce_kmod` /
  `selfprotect` letting through what they advertise blocking).
- Information-disclosure surfaces — webhook URL leak (already
  patched in H-4), config file world-read, baseline file world-read
  (M-7 patched), pinned BPF map readability.
- Supply-chain attacks against the release artifacts (mismatch
  between in-repo SHA pin and shipped tarball is a security event;
  see [`release-checksums/`](release-checksums/)).

## What's out of scope

- Kernel CVEs that kernelradar happens to surface in events.
  Report those upstream.
- Using kernelradar as an offensive tool. The detector library is
  designed to be deployed by a defender on a host they control.
- `panic`s in detector hot paths from genuinely malformed kernel
  events (these are bugs, but treated as ordinary bugs unless the
  panic gives an attacker a useful primitive — usually it just
  crashes the daemon, which then auto-restarts under systemd).
- Findings that require pre-existing root on the target host. Once
  an attacker has root, kernelradar's threat model assumes they can
  unload BPF. The LSM `selfprotect` mode is a hardening hint, not a
  guarantee against root.

For the full threat model see [`docs/threat-model.md`](docs/threat-model.md).

## Coordinated disclosure

We follow [responsible disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure)
principles:

1. Report → ack within 3 days.
2. Joint analysis + patch (private GitHub Advisory).
3. Public release of fix + advisory + credit (if you want it).
4. CVE assignment via GitHub when appropriate.

If a public exploit lands or third-party publishes the issue before
we coordinate a fix, we'll publish the advisory at that moment with
whatever mitigation we have.

---

# Security policy — русская версия

🇬🇧 [English](#security-policy) · 🇷🇺 **Русский**

---

## Сообщение об уязвимости

**Не открывай публичный `issue` на GitHub для security-находок.**

Используй один из приватных каналов:

- **GitHub Security Advisories** —
  [создать черновик advisory](https://github.com/ferithtools/kernelradar/security/advisories/new)
  в этом репозитории. Предпочтительный путь: GitHub изолирует
  обсуждение, позволяет совместно работать над CVE и публикует
  открытое уведомление синхронно с фиксом.
- **Электронная почта** — `ferithtools@users.noreply.github.com`
  (адрес перенаправляется через GitHub; PGP-ключ пока не публикуем —
  его добавление отслеживается в T-15.6 в backlog'е).

Минимально нужно приложить:

- версию (`kernelradar --version` идеально — там есть git-SHA);
- ядро + дистрибутив, на котором воспроизводится;
- минимальный repro либо, если полноценный PoC рискован, описание
  триггера;
- наблюдаемое воздействие (раскрытие информации, отказ в
  обслуживании, повышение привилегий, обход проверки целостности
  и т.д.).

Подтверждение приходит в течение **3 рабочих дней** для триажа,
исправление high-severity целимся выпустить за **30 дней**.
Раскрытие — скоординированное: по умолчанию публикуем advisory +
фикс одновременно.

## Поддерживаемые версии

До v1.0 проект ещё pre-1.0; security-фиксы получает только текущая
минорная линия. После v1.0 (план — Q1 2027, см.
[`README.md`](README.md#roadmap-2026)) LTS-ветка будет
поддерживаться 12 месяцев.

| Версия | Поддерживается |
|---|---|
| `master` (HEAD) | ✅ |
| `v0.1.x` | ✅ до выхода `v0.2.0` |
| pre-`v0.1.0` (разработочные снимки) | ❌ |

## Что в зоне рассмотрения

Находки, которые расцениваем как security:

- Логика BPF-программ, выдающая неверный ответ так, что атакующий
  может это использовать (ложноотрицательный на реальном повышении
  привилегий, сокрытие руткита, подозрительный connect и т.д.).
- Userspace-обработка BPF-событий, дающая ошибочную атрибуцию,
  которой может манипулировать атакующий (например, PID-reuse race,
  TOCTOU на exe-пути, обход allowlist'а).
- Дыры в проверке целостности (`integrity::verify` принимает
  подменённый BPF-объект при `strict_mode = true`).
- Дыры в LSM-блокировках (`enforce_bpf` / `enforce_kmod` /
  `selfprotect` пропускают то, что должны блокировать).
- Поверхность раскрытия информации — утечка `webhook` URL (уже
  закрыта в H-4), world-read у config-файла, world-read у baseline
  (M-7 закрыта), читаемость пиннованных BPF-карт.
- Атаки на цепочку поставок против release-артефактов (рассогласование
  между SHA-пином в репо и опубликованным `.tar.gz` — security-событие;
  см. [`release-checksums/`](release-checksums/)).

## Что вне зоны

- CVE ядра, которые kernelradar просто отображает в событиях.
  Репортить нужно вверх по стеку.
- Использование kernelradar как наступательного инструмента.
  Библиотека детекторов рассчитана на использование защитником на
  хосте, которым он владеет.
- `panic`'и в hot-пути детекторов от действительно ломаных событий
  ядра (это баги, но рассматриваются как обычные, пока паника не
  даёт атакующему полезный примитив — обычно она просто роняет
  демон, который перезапускается под systemd).
- Находки, требующие предварительный root на целевом хосте.
  Когда у атакующего есть root, threat model kernelradar предполагает,
  что он может выгрузить BPF. LSM-режим `selfprotect` — это
  hardening-подсказка, а не гарантия защиты от root.

Полная модель угроз — в
[`docs/threat-model.md`](docs/threat-model.md).

## Скоординированное раскрытие

Следуем принципам [responsible disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure):

1. Репорт → подтверждение за 3 дня.
2. Совместный анализ + патч (приватный GitHub Advisory).
3. Публичный выпуск фикса + advisory + credit (если хочешь
   упоминания).
4. Назначение CVE через GitHub, когда уместно.

Если публичный эксплойт всплывает или сторонняя публикация выходит
раньше, чем мы скоординировали фикс — публикуем advisory в этот же
момент с тем митигейшеном, что есть.
