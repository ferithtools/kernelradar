# kernelradar - Hardening guide

This document covers production hardening and the LSM enforcement
mode. Default settings keep the daemon strictly observe-only;
everything below is opt-in.

## Capabilities

The daemon checks effective capabilities at startup and warns about
missing ones:

| Capability         | Required for                          |
|--------------------|----------------------------------------|
| `CAP_BPF`          | Loading BPF programs (modern kernels) |
| `CAP_PERFMON`      | Tracepoint attach                      |
| `CAP_SYS_RESOURCE` | Large BPF maps under RLIMIT_MEMLOCK    |
| `CAP_SYS_ADMIN`    | `bpf_probe_read_user`, LSM hooks       |

The systemd unit grants all four by default. To run without root,
strip them down based on which detectors you enable.

## BPF object directory

`/var/lib/kernelradar/bpf` is the runtime location of all `.bpf.o`
files. The daemon warns if the directory is world-writable,
group-writable, or **not owned by uid 0**. The last point matters:
the directory's owner can replace `.bpf.o` files between daemon
restarts, and only the integrity check then stands between them
and arbitrary BPF code in the kernel. Always:

```bash
sudo chown -R root:root /var/lib/kernelradar/bpf
sudo chmod 0755 /var/lib/kernelradar/bpf
sudo chmod 0644 /var/lib/kernelradar/bpf/*.bpf.o
```

For maximum protection, bind-mount the directory read-only:

```bash
# /etc/fstab
/var/lib/kernelradar/bpf  /var/lib/kernelradar/bpf  none  bind,ro  0  0
```

Or on systems using only `tmpfs` for state, ship the BPF objects in
the kernelradar binary itself - the integrity check below makes this
safe even when the on-disk copy is mutable.

## BPF integrity verification

At build time, `build.rs` computes SHA-256 of every `.bpf.o` file and
embeds the digest in the binary. At load time the daemon re-hashes
the file on disk before passing it to the verifier.

Two modes:

- **Strict** (default, `[integrity] strict_mode = true`): a hash
  mismatch OR a missing build-time hash refuses to load that
  detector. This is the only safe setting for binaries an operator
  did not just build themselves - including any binary downloaded
  from a release artefact.
- **Permissive** (`strict_mode = false`): mismatch logs a loud
  `error!` and the daemon continues. Useful while iterating on
  `.bpf.o` files after install. Flip strict back on before shipping.

Drift can come from:
- An admin replacing a `.bpf.o` file out-of-band
- A package upgrade that updated some objects but not others
- A real attack (file replaced by a malicious BPF program)

In permissive mode kernelradar logs a loud ERROR and continues so
that a hardware fault or partial upgrade does not take down the
security daemon. Investigate any
mismatch immediately.

## Prerequisite for self-protect and enforcement: enable BPF in the active LSM stack

BPF LSM hooks only work when `bpf` is in the kernel's active LSM list.
Even with `CONFIG_BPF_LSM=y`, distros usually omit it from the runtime
chain. Verify:

```bash
$ cat /sys/kernel/security/lsm
lockdown,capability,landlock,yama,apparmor,ima,evm
```

If `bpf` is missing, edit `/etc/default/grub`:

```
GRUB_CMDLINE_LINUX_DEFAULT="<existing flags> lsm=lockdown,capability,landlock,yama,apparmor,bpf"
```

```bash
sudo update-grub
sudo reboot
```

After reboot:

```bash
$ cat /sys/kernel/security/lsm
lockdown,capability,landlock,yama,apparmor,bpf
```

Without this, kernelradar logs `failed to load selfprotect`
(or the equivalent for `enforce_bpf` / `enforce_kmod`) and falls back
to observe-only operation.

## Self-protection

`enforcement.selfprotect_enabled = true` loads a BPF LSM hook that
returns `-EPERM` for `task_kill` aimed at kernelradar's own TGID.
Exceptions:

- Signals from PID 1 (systemd) - for clean shutdown
- Signals from kernelradar itself - for internal handling

Disabling self-protection requires either:
1. PID 1 sends a signal (`systemctl stop kernelradar`)
2. The daemon itself exits cleanly
3. Kernel reboot

There is no userspace force-kill. Use this only when you have
remote console / IPMI access in case of a daemon malfunction.

## Enforcement mode

Two LSM hooks block syscalls for non-allowlisted processes:

```toml
[enforcement]
bpf_enforce_enabled  = true
bpf_allowlist        = ["bpftrace", "falco", "kernelradar"]

kmod_enforce_enabled = true
kmod_allowlist       = ["modprobe", "kmod", "insmod", "systemd-udevd"]
```

### bpf_enforce - block BPF_PROG_LOAD

LSM hook on `bpf` denies `BPF_PROG_LOAD` for any process whose `comm`
isn't in the allowlist. Effective against:

- BPF-based rootkits
- Unauthorized telemetry agents
- Attackers attempting kernel introspection via BPF

False-positive risks: tools that load BPF dynamically (Cilium DaemonSet,
custom monitoring agents). Always test in observe-only mode first
(`detectors.bpf-loader` already alerts on unauthorized loads - reach
zero noise there before flipping enforcement on).

### kmod_enforce - block kernel module loads

LSM hook on `kernel_read_file` denies `READING_MODULE` for any process
whose `comm` isn't allowlisted. Effective against:

- Kernel-module rootkits
- Loadable backdoors

False-positive risks: udev triggering modprobe for newly attached
hardware. The default allowlist includes `systemd-udevd` and `modprobe`
to cover this.

## Startup order checklist

When enabling enforcement on a real server:

1. **Test in observe mode for 24-48h.** Watch `kernelradar.bpf-loader`
   and `kernelradar.kmod` alerts in journald. Add every legitimate
   process you see to the allowlist.
2. **Validate the config:** `kernelradar config-cmd validate`.
3. **Have console access ready** (IPMI, KVM, physical) - if enforcement
   misfires, you may not be able to SSH in if sshd somehow gets blocked.
4. **Enable one hook at a time**, restart, watch.
5. **Monitor `journalctl -t kernelradar -f`** for enforcement errors.

## Running `config-cmd validate` safely

`kernelradar config-cmd validate <path>` reads any path the invoking
user can read and runs the TOML parser. On a parse error the parser
prints a chunk of the file content into stderr to point at the
syntax issue. **Do not** run this command via `sudo` against a path
the invoking user cannot read on their own (e.g. `/etc/shadow`,
`/root/.ssh/id_*`) - the parser snippet display can echo bytes
from those files into the terminal.

The default install does not ship `kernelradar` setuid; running it
as your own user only leaks what your user can already read. If you
need to validate a config that lives under a privileged path, copy
it to a location your user owns first:

```bash
sudo cat /etc/kernelradar/config.toml > /tmp/check.toml
kernelradar config-cmd validate --path /tmp/check.toml
```

## Recovery

If kernelradar enforcement breaks the system:

```bash
# From a recovery shell or via systemd's emergency target
systemctl stop kernelradar
mv /etc/kernelradar/config.toml /etc/kernelradar/config.toml.bak
kernelradar config-cmd example > /etc/kernelradar/config.toml
systemctl start kernelradar
```

The default config has all enforcement disabled.
