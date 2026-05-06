# kernelradar: Threat Model

kernelradar is a **defensive** tool. It observes kernel behavior to detect
anomalous patterns that may indicate a security incident on the monitored host.

## What kernelradar protects

- Linux servers running workloads (containers, VMs, bare-metal services)
- Specifically: detecting post-compromise activity, not preventing initial entry

## Attacker model

kernelradar assumes an attacker who has already gained code execution as a
low-privileged user and is attempting to:

1. Escalate privileges (setuid abuse, credential manipulation)
2. Establish persistence (malicious kernel modules, BPF-based hooks)
3. Escape container isolation (namespace/cgroup boundary violations)
4. Cover tracks (hiding processes, manipulating audit logs)

## Detection approach

kernelradar does NOT:
- Scan files for known malware signatures
- Block network traffic
- Prevent initial exploitation

kernelradar DOES:
- Observe kernel-level behaviors that indicate post-exploitation activity
- Alert on deviations from established behavioral baselines
- Log forensic-quality events (timestamp, pid, uid, cgroup, comm)

## Trust boundaries

```
Trusted:    kernelradar BPF programs (loaded at startup, verified by kernel verifier)
Trusted:    kernelradar daemon process (runs as root)
Untrusted:  All other processes, including root processes (monitored)
Untrusted:  Network input to monitored services
```

## Limitations

- kernelradar cannot detect attacks that occur before it starts
- A sufficiently privileged attacker may be able to disable kernelradar
  (mitigated by Phase 4 LSM enforcement mode)
- BPF programs are subject to kernel BPF verifier constraints

## Out of scope

- Network-level intrusion detection (use Suricata, Zeek)
- Static file analysis (use ClamAV, YARA)
- Cloud control-plane events (use CloudTrail, GCP Audit Logs)
