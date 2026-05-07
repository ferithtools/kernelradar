# kernelradar: threat model

kernelradar is a defensive observability tool. It watches kernel
behaviour and emits alerts when patterns associated with
post-compromise activity show up. It does not prevent the initial
intrusion; it tries to make the next step visible.

## What kernelradar covers

- Linux hosts running workloads (containers, VMs, bare-metal
  services). Single-host scope; no fleet aggregation in the daemon
  itself - aggregate the alerts via journald-shipping or any
  Falco-compatible SIEM.
- Specifically: detecting post-exploitation activity. Not initial
  RCE, not phishing, not network-level intrusion.

## Attacker model

The intended adversary is one who has already gained code execution
as a non-root user on the host and is trying to:

1. Escalate privileges (`setuid`/`setgid` to root, credential file
   reads, ssh-key theft).
2. Establish persistence (kernel modules, BPF-based rootkits,
   tampering with `/etc/pam.d/`, `/etc/cron.*`, init scripts, ssh
   `authorized_keys`).
3. Escape isolation (namespace / cgroup manipulation via `unshare`
   and `setns`).
4. Move laterally or call home (outbound `connect()` to public
   IPv4, including known reverse-shell ports).
5. Inject into other processes (`ptrace` ATTACH/POKE,
   `process_vm_writev`).

## What the daemon does and does not do

Does:

- Observe kernel-level behaviours through eBPF tracepoints
  (read-only).
- Optionally enforce three LSM hooks (off by default): block kill
  of the daemon's own TGID, block `BPF_PROG_LOAD` outside an
  allowlist, block kernel-module loads outside an allowlist.
- Emit structured alerts with `timestamp`, `pid`, `uid`, `comm`,
  `correlation_id`, severity, detector identity, and detector
  payload.

Does not:

- Scan files for malware signatures.
- Block network traffic.
- Prevent initial exploitation.
- Provide its own dashboard or fleet manager.

## Trust boundaries

| Trusted | Untrusted |
|---|---|
| kernelradar BPF programs (loaded once, verified by the kernel BPF verifier; integrity-checked at load time against build-time SHA-256) | Every other process on the host, including ones running as root |
| The kernelradar daemon process (runs with `CAP_BPF` + `CAP_PERFMON` + `CAP_SYS_RESOURCE` + `CAP_SYS_ADMIN` under the shipped systemd unit; full root not required on kernels >= 5.8) | Network input to any service running on the host |
| The on-disk `.bpf.o` files (build-time SHA-256 verified at load) | The host's `/etc`, `/root`, `/home` filesystems (the FIM and cred detectors monitor them) |

## Hard limits, by design

- **kernelradar cannot detect attacks that happened before it
  started.** It is not a forensic timeline reconstruction tool.
- **A root-equivalent attacker can defeat kernelradar.** Once the
  attacker has `CAP_BPF` they can unload kernelradar's BPF
  programs (this is documented; the LSM `selfprotect` mode is a
  hardening hint, not a guarantee).
- **The comm-based enforcement allowlists are a hardening hint,
  not a security boundary.** `comm` is a 16-byte process name
  trivially set by `prctl(PR_SET_NAME)`; an attacker who can
  rename their own process can defeat `enforce_bpf` /
  `enforce_kmod`. The allowlists matter against opportunistic /
  unsophisticated payloads, not targeted attackers.
- **Process attribution is best-effort.** The daemon reads
  `/proc/<pid>/exe` after the BPF event and re-checks
  `/proc/<pid>/comm` to mitigate PID-reuse and `execve` races, but
  a process that `execve`s to a binary sharing the first 15 `comm`
  bytes can still slip through. This is a documented accuracy
  bound, not a scheduled fix.
- **BPF programs are subject to the kernel verifier.** If a future
  kernel rejects one of the BPF programs (instruction-count limit,
  helper restriction), that detector is lost on that kernel until
  the BPF code is rewritten.

## Out of scope (use other tools)

- Network-level intrusion detection: Suricata, Zeek.
- Static file / binary analysis: ClamAV, YARA.
- Cloud control-plane audit: CloudTrail, GCP Audit Logs.
- Endpoint behaviour analytics at scale (thousands of hosts):
  commercial EDR, or Falco/Tetragon with a CNCF-class community
  behind them.
