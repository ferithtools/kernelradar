# Contributing to kernelradar

🇬🇧 **English** · [🇷🇺 Русский](#contributing-to-kernelradar--русская-версия)

---

Thanks for the interest. kernelradar is a small open-source project
maintained out of working hours, so the workflow is deliberately
lightweight. Read the bits below that apply to what you want to do
and skip the rest.

## Quick map

| I want to … | Read |
|---|---|
| Report a bug | open a GitHub issue (use the **Bug report** template) |
| Suggest a feature | open a GitHub issue (use the **Feature request** template) |
| Send a code change | this whole document |
| Report a security issue | [`SECURITY.md`](SECURITY.md) — **not** a public issue |

## Development setup

You need a Linux host (BPF programs are Linux-only) plus:

```bash
# Debian / Ubuntu
sudo apt install -y build-essential clang llvm libbpf-dev libelf-dev \
    pkg-config bpftool linux-tools-common

# Rust toolchain (stable)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Build everything from the repo root using the Makefile, **not** by
running `cargo build` directly — `make rust` first builds the BPF
objects, otherwise the integrity-verification table records empty
hashes:

```bash
git clone https://github.com/ferithtools/kernelradar.git
cd kernelradar
make            # builds BPF + userspace
make check      # cargo check + clippy
```

## Running tests

```bash
cargo test --workspace --all-targets    # unit tests (~30 tests)
cargo fmt --all --check                  # formatting gate (CI hard-fails on diff)
cargo clippy --workspace --all-targets -- -D warnings
```

## Testing a detector locally

`make` produces `target/release/kernelradar`. Run a single detector
against the running system without touching any system files:

```bash
sudo ./target/release/kernelradar detect privesc \
    --bpf-dir crates/kernelradar-bpf/.output \
    --format=plain
```

In another terminal, fire something the detector should catch:

```bash
sudo -u nobody python3 -c 'import os; os.setuid(0)'
```

You should see an `[ALERT]` line with `setuid(0)` in the daemon's
output.

## Coding conventions

**Style.** We accept whatever `cargo fmt` produces with default
settings. CI fails the PR on any diff. No `rustfmt.toml` overrides.

**Lints.** `cargo clippy --workspace --all-targets -- -D warnings`
must pass. New warnings either get fixed or, very rarely, suppressed
with a `#[allow(...)]` and a one-line `// reason: ...` comment.

**Comments.** Default to no comments. Add one only when the WHY is
non-obvious — a hidden constraint, a workaround for a specific bug,
behaviour that would surprise a reader. Don't explain WHAT the code
does — well-named identifiers do that.

**`unsafe`.** Acceptable in the BPF ring-buffer reader (`read_unaligned`
on raw bytes, the load-bearing pattern in every detector handler).
New `unsafe` outside that pattern needs a SAFETY comment naming the
invariant the caller relies on.

**No personal data.** Source files carry the `Ferith Tools Project`
copyright line and never personal names, emails, or hostnames. CI
will not enforce this — it's on every contributor to keep clean.

## Commit messages

Format used across the repo:

```
<type>[ <task-id>]: <one-line summary, imperative, ≤ 72 chars>

<body — explain WHY, not WHAT. Wrap at 72.>

<optional sign-off / co-author trailers>
```

Types we use:

- `feat` — new feature
- `fix` — bug fix
- `docs` — documentation only
- `chore` — tooling, dependencies, project-meta
- `build` — packaging / Makefile / CI
- `release` — version bump, tag preparation
- `refactor` — non-behavioural code changes

Task ids reference the [`backlog`](k-radar_backlog.md) (`T-N` for
tracked work, `H-N` / `M-N` for security audit findings, `F-N` for
forward features). They're optional but useful for traceability.

Examples:

```
feat T-13.1: persistence detector — bashrc/cron/systemd watch
fix M-2: drop allowlist prefix-match — sshd no longer covers sshooly
docs(readme): clarify IPv6 limitation in the comparison table
```

## Pull request workflow

1. Fork. Branch off `master`. Branch name doesn't matter, but
   `<type>/<short-slug>` is nice (e.g. `feat/dns-detector`).
2. Make your change. Add or update tests.
3. Run `make`, `cargo test --workspace`, `cargo fmt --all --check`,
   `cargo clippy --workspace --all-targets -- -D warnings`. All four
   must pass before push.
4. Open a PR against `master`. The PR template asks for the
   linked issue, summary, test plan, and a few checkboxes — fill
   them honestly.
5. Reviewer responds within ~3 working days. If you don't hear
   back, ping the PR thread — it's a one-maintainer project, things
   slip.

## License + provenance

By submitting a contribution you agree it's released under
**GPL-2.0-only**, the same licence as the rest of the project.

Add a sign-off line to every commit ([Developer Certificate of
Origin](https://developercertificate.org/), `git commit -s`):

```
Signed-off-by: Your Name <your.email@example.org>
```

You can use a pseudonym + a noreply email if you'd rather not show
your real identity — we don't verify, and we won't ask.

## What we won't accept

- Code under any non-GPL-compatible licence.
- Detectors that exfiltrate data to third-party services without an
  explicit user-controlled config flag.
- Vendor-specific code (proprietary kernels, closed-source helpers).
- Big-bang rewrites of unrelated subsystems alongside your feature.
- Commits authored as personal humans rather than `Ferith Tools
  Project` … sorry, that's a joke. Use whatever name you want.

---

# Contributing to kernelradar — русская версия

🇬🇧 [English](#contributing-to-kernelradar) · 🇷🇺 **Русский**

---

Спасибо за интерес. kernelradar — небольшой open-source-проект, который
ведут в свободное время, поэтому процесс намеренно лёгкий. Читай те
разделы, что относятся к тому, что хочется сделать; остальное можно
пропустить.

## Карта быстрого доступа

| Хочу… | Что читать |
|---|---|
| Сообщить о баге | открой `issue` на GitHub (шаблон **Bug report**) |
| Предложить фичу | открой `issue` на GitHub (шаблон **Feature request**) |
| Прислать изменение в код | весь этот документ |
| Сообщить об уязвимости | [`SECURITY.md`](SECURITY.md) — **не** публичное `issue` |

## Подготовка окружения

Нужен Linux-хост (BPF-программы только под Linux) плюс:

```bash
# Debian / Ubuntu
sudo apt install -y build-essential clang llvm libbpf-dev libelf-dev \
    pkg-config bpftool linux-tools-common

# Rust toolchain (stable)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Собирай через корневой Makefile, **не** через `cargo build` напрямую —
`make rust` сначала собирает BPF-объекты, иначе таблица проверки
целостности запишет пустые хеши:

```bash
git clone https://github.com/ferithtools/kernelradar.git
cd kernelradar
make            # собирает BPF + userspace
make check      # cargo check + clippy
```

## Запуск тестов

```bash
cargo test --workspace --all-targets    # юнит-тесты (~30 штук)
cargo fmt --all --check                  # форматирование (CI hard-fail при отклонении)
cargo clippy --workspace --all-targets -- -D warnings
```

## Локальная проверка детектора

`make` собирает `target/release/kernelradar`. Запусти один детектор
против работающей системы, не трогая системные файлы:

```bash
sudo ./target/release/kernelradar detect privesc \
    --bpf-dir crates/kernelradar-bpf/.output \
    --format=plain
```

В другом терминале выстрели чем-то, что должен поймать детектор:

```bash
sudo -u nobody python3 -c 'import os; os.setuid(0)'
```

В выводе демона должна появиться строка `[ALERT]` с `setuid(0)`.

## Соглашения по коду

**Стиль.** Принимаем то, что выдаёт `cargo fmt` со стандартными
настройками. CI валит PR при любом отклонении. Никаких локальных
`rustfmt.toml`-переопределений.

**Линт.** `cargo clippy --workspace --all-targets -- -D warnings`
должен проходить чисто. Новые предупреждения либо чинятся, либо
(очень редко) глушатся через `#[allow(...)]` с однострочным
`// reason: ...`.

**Комментарии.** По умолчанию — никаких. Добавляй только когда
непонятно ПОЧЕМУ — скрытое ограничение, обход известного бага,
поведение, которое удивит читателя. Не объясняй ЧТО делает код —
это должны делать имена.

**`unsafe`.** Допустим в чтении BPF ring-buffer'а (`read_unaligned`
по сырым байтам — типовой паттерн в каждом детекторе). Новые
`unsafe`-блоки вне этого паттерна требуют SAFETY-комментария с
указанием инварианта, на который опирается вызывающий.

**Никаких персональных данных.** В исходниках только строка
`Ferith Tools Project` в copyright; никаких имён, адресов почты,
имён хостов. CI это не проверяет — следить за чистотой обязан
каждый контрибьютор.

## Сообщения коммитов

Формат, используемый в репозитории:

```
<тип>[ <task-id>]: <одна строка, повелительное наклонение, ≤ 72 символов>

<тело — объясняет ПОЧЕМУ, не ЧТО. Обрезай по 72.>

<sign-off / co-author trailer'ы — если нужны>
```

Используемые типы:

- `feat` — новая возможность
- `fix` — исправление бага
- `docs` — только документация
- `chore` — тулинг, зависимости, проектная мета
- `build` — упаковка / Makefile / CI
- `release` — версия, подготовка тега
- `refactor` — изменения кода без изменения поведения

Идентификаторы задач ссылаются на [`backlog`](k-radar_backlog.md)
(`T-N` для отслеживаемой работы, `H-N` / `M-N` для находок security
audit'а, `F-N` для будущих возможностей). Опциональны, но полезны
для прослеживания.

Примеры:

```
feat T-13.1: persistence detector — bashrc/cron/systemd watch
fix M-2: drop allowlist prefix-match — sshd no longer covers sshooly
docs(readme): clarify IPv6 limitation in the comparison table
```

## Процесс pull request'а

1. Форк. Ветка от `master`. Имя ветки не важно, но
   `<тип>/<короткий-slug>` смотрится прилично (например,
   `feat/dns-detector`).
2. Сделай изменение. Добавь или обнови тесты.
3. Прогони `make`, `cargo test --workspace`,
   `cargo fmt --all --check`,
   `cargo clippy --workspace --all-targets -- -D warnings`. Все
   четыре должны пройти до push'а.
4. Открой PR против `master`. Шаблон попросит привязанный `issue`,
   краткое резюме, план тестов и несколько чекбоксов — заполни
   честно.
5. Ревью обычно через ~3 рабочих дня. Если тишина — пингуй в треде
   PR. Maintainer один, бывает что слетает.

## Лицензия и происхождение

Отправляя контрибьюшен, ты соглашаешься, что он публикуется под
**GPL-2.0-only** — под той же лицензией, что и остальной проект.

Добавляй sign-off к каждому коммиту ([Developer Certificate of
Origin](https://developercertificate.org/), `git commit -s`):

```
Signed-off-by: Имя Фамилия <email@example.org>
```

Можно использовать псевдоним + noreply-почту, если не хочешь
светить настоящую личность. Не проверяем, не спросим.

## Чего не примем

- Код под лицензией, несовместимой с GPL.
- Детекторы, которые отправляют данные на сторонние сервисы без явного
  config-флага, контролируемого пользователем.
- Vendor-привязанный код (проприетарные ядра, закрытые helpers).
- Big-bang переписывания несвязанных подсистем заодно с твоей фичей.
- Коммиты, авторизованные как обычные люди, а не `Ferith Tools
  Project` … шутка. Имя авторства — на твой выбор.
