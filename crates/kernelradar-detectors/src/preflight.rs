// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Ferith Tools
//
// Part of the kernelradar project — Linux kernel anomaly detection via BPF.
// See LICENSE for terms.

/// Startup preflight checks (T-6.6 + T-6.7).
///
/// Verifies that the running process has the capabilities BPF needs,
/// warns about insecure permissions on the BPF object directory,
/// and gives admin-friendly hints when something is missing.
use std::path::Path;

#[derive(Debug, Clone, Copy)]
pub struct Capabilities {
    pub cap_bpf: bool,
    pub cap_perfmon: bool,
    pub cap_sys_admin: bool,
    pub cap_sys_resource: bool,
}

/// Probe `/proc/self/status` for the effective capability bitmask.
/// Returns None if /proc isn't available (containers etc.).
pub fn current_caps() -> Option<Capabilities> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = s.lines().find(|l| l.starts_with("CapEff:"))?;
    let hex = line.split_whitespace().nth(1)?;
    let bits = u64::from_str_radix(hex, 16).ok()?;

    Some(Capabilities {
        // Numbers from include/uapi/linux/capability.h
        cap_sys_admin: bits & (1u64 << 21) != 0,
        cap_sys_resource: bits & (1u64 << 24) != 0,
        cap_perfmon: bits & (1u64 << 38) != 0,
        cap_bpf: bits & (1u64 << 39) != 0,
    })
}

/// Log warnings for missing capabilities. Returns false if the process
/// is *almost certainly* unable to load BPF programs at all.
pub fn check_capabilities() -> bool {
    let caps = match current_caps() {
        Some(c) => c,
        None => {
            tracing::warn!("preflight: cannot read /proc/self/status");
            return true; // optimistic: let aya fail with a real error
        }
    };

    let mut ok = true;

    if !caps.cap_bpf && !caps.cap_sys_admin {
        tracing::error!(
            "preflight: missing CAP_BPF (and CAP_SYS_ADMIN). \
             BPF program loading will fail. Run as root or grant \
             CAP_BPF+CAP_PERFMON via systemd AmbientCapabilities."
        );
        ok = false;
    }

    if !caps.cap_perfmon && !caps.cap_sys_admin {
        tracing::warn!(
            "preflight: missing CAP_PERFMON. Tracepoint attach \
             may fail. Add CAP_PERFMON or run with CAP_SYS_ADMIN."
        );
    }

    if !caps.cap_sys_resource {
        tracing::info!(
            "preflight: missing CAP_SYS_RESOURCE — \
             large BPF maps may hit RLIMIT_MEMLOCK on older kernels."
        );
    }

    if !caps.cap_sys_admin {
        tracing::info!(
            "preflight: running without CAP_SYS_ADMIN. \
             bpf_probe_read_user (used by FIM/cred path filtering) \
             requires CAP_SYS_ADMIN on some kernels."
        );
    }

    ok
}

/// Warn if the BPF object directory is world-writable.
/// Recommend a read-only bind mount when applicable.
pub fn check_bpf_dir(path: &str) {
    let p = Path::new(path);
    if !p.exists() {
        tracing::warn!(path, "preflight: BPF object dir does not exist");
        return;
    }

    // Permission check
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(p) {
        let mode = meta.permissions().mode();
        if mode & 0o002 != 0 {
            tracing::warn!(
                path,
                mode = format!("{:o}", mode),
                "preflight: BPF dir is world-writable — \
                 anyone can swap loaded BPF programs"
            );
        }
        if mode & 0o020 != 0 {
            tracing::warn!(
                path,
                mode = format!("{:o}", mode),
                "preflight: BPF dir is group-writable — \
                 chmod 0755 or stricter recommended"
            );
        }
    }

    // Read-only mount hint
    if let Ok(mounts) = std::fs::read_to_string("/proc/mounts") {
        for line in mounts.lines() {
            let parts: Vec<_> = line.split_whitespace().collect();
            if parts.len() < 4 {
                continue;
            }
            let mountpoint = parts[1];
            // Match the closest mount that contains our path
            if path.starts_with(mountpoint) || mountpoint == path {
                let opts = parts[3];
                if !opts.split(',').any(|o| o == "ro") {
                    tracing::info!(
                        path,
                        mount = mountpoint,
                        "preflight: BPF dir is on a read-write mount. \
                         For stronger isolation, bind-mount {path} read-only \
                         (see docs/hardening.md)"
                    );
                }
                break;
            }
        }
    }
}
