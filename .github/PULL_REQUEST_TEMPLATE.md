<!--
Thanks for the contribution! Tick what's done, leave the rest.
For full guidelines see CONTRIBUTING.md.
-->

## Summary

<!-- One short paragraph: what does this PR do, and why? -->

## Linked issue / task

<!-- "Closes #N" / "Refs #N" - leave blank if it's a drive-by fix
     that doesn't have an issue. -->

## Type of change

- [ ] `feat` - new feature
- [ ] `fix` - bug fix
- [ ] `docs` - docs / comments only
- [ ] `chore` - tooling, deps, project metadata
- [ ] `build` - packaging / Makefile / CI
- [ ] `refactor` - non-behavioural code change
- [ ] `release` - version bump / tag prep

## How was this tested?

<!-- Describe what you actually ran. "cargo test" alone is not
     enough for behavioural changes - show the manual repro you did
     to convince yourself it works. -->

```text
$ make
$ cargo test --workspace --all-targets
$ # … your additional repro …
```

## Pre-flight checklist

- [ ] `make` builds clean (BPF + userspace).
- [ ] `cargo test --workspace --all-targets` passes.
- [ ] `cargo fmt --all --check` is clean.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` is clean.
- [ ] New behaviour has a test, or the PR explains why it can't.
- [ ] User-facing changes are reflected in `README.md` and/or `CHANGELOG.md`.
- [ ] No personal names / emails / hostnames added to source files
      (only `Ferith Tools Project` is acceptable).
- [ ] Commits are signed off (`git commit -s`) per
      [DCO](https://developercertificate.org/).
- [ ] If this is a security-relevant change, it does NOT bypass
      `SECURITY.md` private-disclosure flow.

## Reviewer notes

<!-- Anything the reviewer should look at first, known limitations,
     follow-ups you'll do in a separate PR. Optional. -->
