# Contributing to kernelradar

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
| Report a security issue | [`SECURITY.md`](SECURITY.md) - **not** a public issue |

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
running `cargo build` directly - `make rust` first builds the BPF
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
non-obvious - a hidden constraint, a workaround for a specific bug,
behaviour that would surprise a reader. Don't explain WHAT the code
does - well-named identifiers do that.

**`unsafe`.** Acceptable in the BPF ring-buffer reader (`read_unaligned`
on raw bytes, the load-bearing pattern in every detector handler).
New `unsafe` outside that pattern needs a SAFETY comment naming the
invariant the caller relies on.

**No personal data.** Source files carry the `Ferith Tools Project`
copyright line and never personal names, emails, or hostnames. CI
will not enforce this - it's on every contributor to keep clean.

## Commit messages

Format used across the repo:

```
<type>[ <task-id>]: <one-line summary, imperative, ≤ 72 chars>

<body - explain WHY, not WHAT. Wrap at 72.>

<optional sign-off / co-author trailers>
```

Types we use:

- `feat` - new feature
- `fix` - bug fix
- `docs` - documentation only
- `chore` - tooling, dependencies, project-meta
- `build` - packaging / Makefile / CI
- `release` - version bump, tag preparation
- `refactor` - non-behavioural code changes

Examples:

```
feat: persistence detector - bashrc/cron/systemd watch
fix: drop allowlist prefix-match - sshd no longer covers sshooly
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
   linked issue, summary, test plan, and a few checkboxes - fill
   them honestly.
5. Reviewer responds within ~3 working days. If you don't hear
   back, ping the PR thread - it's a one-maintainer project, things
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
your real identity - we don't verify, and we won't ask.

## What we won't accept

- Code under any non-GPL-compatible licence.
- Detectors that exfiltrate data to third-party services without an
  explicit user-controlled config flag.
- Vendor-specific code (proprietary kernels, closed-source helpers).
- Big-bang rewrites of unrelated subsystems alongside your feature.
- Commits authored as personal humans rather than `Ferith Tools
  Project` … sorry, that's a joke. Use whatever name you want.

