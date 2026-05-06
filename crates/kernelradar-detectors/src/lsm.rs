// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Ferith Tools
//
// Part of the kernelradar project — Linux kernel anomaly detection via BPF.
// See LICENSE for terms.

/// LSM enforcement & self-protection (T-0.9 + T-6.4).
///
/// Loads BPF LSM programs that DENY operations:
///   • selfprotect.bpf.o      — block kill of kernelradar itself
///   • enforce_bpf.bpf.o      — block BPF_PROG_LOAD by non-allowlisted comms
///   • enforce_kmod.bpf.o     — block kernel module load by non-allowlisted comms
///
/// All three are OFF by default. Enable with explicit config opt-in.
/// On enabled-but-failed-load we LOG the error and continue running
/// in observe-only mode — never abort the daemon.
use anyhow::{Context, Result};
use aya::{
    maps::{Array, HashMap, MapData},
    programs::Lsm,
    Btf, Ebpf,
};
use std::path::Path;
use std::sync::OnceLock;

use crate::integrity::verify as verify_bpf;

#[derive(Debug, Clone)]
pub struct EnforcementConfig {
    pub selfprotect_enabled: bool,
    pub bpf_enforce_enabled: bool,
    pub kmod_enforce_enabled: bool,

    pub selfprotect_obj_path: String,
    pub bpf_enforce_obj_path: String,
    pub kmod_enforce_obj_path: String,

    /// Comm strings allowed to load BPF programs (T-0.9 enforcement).
    pub bpf_allowlist: Vec<String>,
    /// Comm strings allowed to load kernel modules.
    pub kmod_allowlist: Vec<String>,
}

impl Default for EnforcementConfig {
    fn default() -> Self {
        Self {
            selfprotect_enabled: false,
            bpf_enforce_enabled: false,
            kmod_enforce_enabled: false,
            selfprotect_obj_path: "/var/lib/kernelradar/bpf/selfprotect.bpf.o".into(),
            bpf_enforce_obj_path: "/var/lib/kernelradar/bpf/enforce_bpf.bpf.o".into(),
            kmod_enforce_obj_path: "/var/lib/kernelradar/bpf/enforce_kmod.bpf.o".into(),
            bpf_allowlist: vec!["bpftrace".into(), "falco".into(), "kernelradar".into()],
            kmod_allowlist: vec![
                "modprobe".into(),
                "kmod".into(),
                "insmod".into(),
                "systemd-udevd".into(),
            ],
        }
    }
}

/// Holds the loaded Ebpf instances so they aren't dropped while the
/// daemon runs. We keep them in a global OnceLock to keep ownership.
struct LoadedLsm {
    _selfprotect: Option<Ebpf>,
    _bpf_enforce: Option<Ebpf>,
    _kmod_enforce: Option<Ebpf>,
}

static LOADED: OnceLock<std::sync::Mutex<Option<LoadedLsm>>> = OnceLock::new();

/// Load and attach LSM programs as configured. Always Ok — failures
/// are logged but never propagate, so the daemon keeps running.
pub fn install(cfg: &EnforcementConfig) {
    let mut state = LoadedLsm {
        _selfprotect: None,
        _bpf_enforce: None,
        _kmod_enforce: None,
    };

    let btf = match Btf::from_sys_fs() {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!("LSM: cannot read /sys/kernel/btf/vmlinux: {e}");
            return;
        }
    };

    if cfg.selfprotect_enabled {
        match load_selfprotect(&cfg.selfprotect_obj_path, &btf) {
            Ok(b) => {
                tracing::warn!(
                    "T-6.4 self-protection ENABLED: \
                                 kernelradar PID is unkillable except by systemd"
                );
                state._selfprotect = Some(b);
            }
            Err(e) => tracing::error!("T-6.4: failed to load selfprotect: {e}"),
        }
    }

    if cfg.bpf_enforce_enabled {
        match load_bpf_enforce(&cfg.bpf_enforce_obj_path, &btf, &cfg.bpf_allowlist) {
            Ok(b) => {
                tracing::warn!(
                    "T-0.9 bpf-loader ENFORCEMENT ENABLED: \
                                 BPF_PROG_LOAD denied for non-allowlisted procs"
                );
                state._bpf_enforce = Some(b);
            }
            Err(e) => tracing::error!("T-0.9: failed to load enforce_bpf: {e}"),
        }
    }

    if cfg.kmod_enforce_enabled {
        match load_kmod_enforce(&cfg.kmod_enforce_obj_path, &btf, &cfg.kmod_allowlist) {
            Ok(b) => {
                tracing::warn!(
                    "T-0.9 kmod ENFORCEMENT ENABLED: \
                                 kernel_read_file(MODULE) denied for non-allowlisted"
                );
                state._kmod_enforce = Some(b);
            }
            Err(e) => tracing::error!("T-0.9: failed to load enforce_kmod: {e}"),
        }
    }

    let cell = LOADED.get_or_init(|| std::sync::Mutex::new(None));
    *cell.lock().expect("lsm mutex") = Some(state);
}

/// Load an LSM program object file, verify its SHA-256 against the
/// build-time hash, and attach the named LSM program. `detector` is
/// the integrity-table key (must match `build.rs` name list);
/// `prog_name` is the BPF program SEC name inside the object.
fn load_lsm(path: &str, btf: &Btf, detector: &str, prog_name: &'static str) -> Result<Ebpf> {
    let bytes = std::fs::read(Path::new(path)).with_context(|| format!("read {path}"))?;

    // H-2: LSM is the last line of defense. Integrity-check the BPF
    // object before loading — same policy as the observation detectors.
    verify_bpf(detector, &bytes)?;

    let mut bpf = Ebpf::load(&bytes).context("verifier rejected LSM program")?;

    let prog: &mut Lsm = bpf.program_mut(prog_name).context(prog_name)?.try_into()?;
    prog.load(prog_name, btf).context("Lsm::load")?;
    prog.attach().context("Lsm::attach")?;
    Ok(bpf)
}

fn load_selfprotect(path: &str, btf: &Btf) -> Result<Ebpf> {
    let mut bpf = load_lsm(path, btf, "selfprotect", "kr_task_kill")?;

    // Populate the protected TGID with our own pid (since this process
    // is the BPF orchestrator, our tgid equals the daemon's tgid).
    let tgid = std::process::id();
    let map = bpf
        .take_map("kr_protected_tgid")
        .context("kr_protected_tgid map missing")?;
    let mut arr: Array<MapData, u32> = Array::try_from(map)?;
    arr.set(0, &tgid, 0)?;

    Ok(bpf)
}

fn load_bpf_enforce(path: &str, btf: &Btf, allowlist: &[String]) -> Result<Ebpf> {
    let mut bpf = load_lsm(path, btf, "enforce_bpf", "kr_bpf_enforce")?;

    let map = bpf
        .take_map("kr_bpf_allowed")
        .context("kr_bpf_allowed map missing")?;
    let mut hm: HashMap<MapData, [u8; 16], u8> = HashMap::try_from(map)?;
    for entry in allowlist {
        let mut key = [0u8; 16];
        let bytes = entry.as_bytes();
        let n = bytes.len().min(15);
        key[..n].copy_from_slice(&bytes[..n]);
        hm.insert(key, 1u8, 0)?;
    }
    Ok(bpf)
}

fn load_kmod_enforce(path: &str, btf: &Btf, allowlist: &[String]) -> Result<Ebpf> {
    let mut bpf = load_lsm(path, btf, "enforce_kmod", "kr_kmod_enforce")?;

    let map = bpf
        .take_map("kr_kmod_allowed")
        .context("kr_kmod_allowed map missing")?;
    let mut hm: HashMap<MapData, [u8; 16], u8> = HashMap::try_from(map)?;
    for entry in allowlist {
        let mut key = [0u8; 16];
        let bytes = entry.as_bytes();
        let n = bytes.len().min(15);
        key[..n].copy_from_slice(&bytes[..n]);
        hm.insert(key, 1u8, 0)?;
    }
    Ok(bpf)
}
