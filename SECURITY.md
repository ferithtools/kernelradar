# Security policy

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

