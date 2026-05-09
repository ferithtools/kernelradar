// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Ferith Tools
//
// Part of the kernelradar project - Linux kernel anomaly detection via BPF.
// See LICENSE for terms.

/// LSM enforcement and self-protection.
///
/// Loads BPF LSM programs that DENY operations:
///   • selfprotect.bpf.o      - block kill of kernelradar itself
///   • enforce_bpf.bpf.o      - block BPF_PROG_LOAD by non-allowlisted comms
///   • enforce_kmod.bpf.o     - block kernel module load by non-allowlisted comms
///
/// All three are OFF by default. Enable with explicit config opt-in.
/// On enabled-but-failed-load we LOG the error and continue running
/// in observe-only mode - never abort the daemon.
use anyhow::{Context, Result};
use aya::{
    maps::{Array, HashMap, MapData, RingBuf},
    programs::Lsm,
    Btf, Ebpf,
};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::OnceLock;
use tokio::io::unix::AsyncFd;

use crate::integrity::verify as verify_bpf;

#[derive(Debug, Clone)]
pub struct EnforcementConfig {
    pub selfprotect_enabled: bool,
    pub bpf_enforce_enabled: bool,
    pub kmod_enforce_enabled: bool,

    pub selfprotect_obj_path: String,
    pub bpf_enforce_obj_path: String,
    pub kmod_enforce_obj_path: String,

    /// Comm strings allowed to load BPF programs.
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

/// Load and attach LSM programs as configured. Always Ok - failures
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
                    "self-protection ENABLED: \
                                 kernelradar PID is unkillable except by systemd"
                );
                state._selfprotect = Some(b);
            }
            Err(e) => tracing::error!("failed to load selfprotect: {e}"),
        }
    }

    if cfg.bpf_enforce_enabled {
        match load_bpf_enforce(&cfg.bpf_enforce_obj_path, &btf, &cfg.bpf_allowlist) {
            Ok(b) => {
                tracing::warn!(
                    "bpf-loader ENFORCEMENT ENABLED: \
                                 BPF_PROG_LOAD denied for non-allowlisted procs"
                );
                state._bpf_enforce = Some(b);
            }
            Err(e) => tracing::error!("failed to load enforce_bpf: {e}"),
        }
    }

    if cfg.kmod_enforce_enabled {
        match load_kmod_enforce(&cfg.kmod_enforce_obj_path, &btf, &cfg.kmod_allowlist) {
            Ok(b) => {
                tracing::warn!(
                    "kmod ENFORCEMENT ENABLED: \
                                 kernel_read_file(MODULE) denied for non-allowlisted"
                );
                state._kmod_enforce = Some(b);
            }
            Err(e) => tracing::error!("failed to load enforce_kmod: {e}"),
        }
    }

    let cell = LOADED.get_or_init(|| std::sync::Mutex::new(None));
    // Poisoned mutex → log and recover. install() runs once at startup,
    // so poisoning is unlikely; fall back to overwriting the inner state.
    let mut guard = cell.lock().unwrap_or_else(|e| {
        tracing::warn!("LSM state mutex was poisoned; recovering");
        e.into_inner()
    });
    *guard = Some(state);
}

/// Load an LSM program object file, verify its SHA-256 against the
/// build-time hash, and attach the named LSM program. `detector` is
/// the integrity-table key (must match `build.rs` name list);
/// `prog_name` is the BPF program SEC name inside the object.
fn load_lsm(path: &str, btf: &Btf, detector: &str, prog_name: &'static str) -> Result<Ebpf> {
    let bytes = std::fs::read(Path::new(path)).with_context(|| format!("read {path}"))?;

    // LSM is the last line of defense. Integrity-check the BPF object
    // before loading - same policy as the observation detectors.
    verify_bpf(detector, &bytes)?;

    let mut bpf = Ebpf::load(&bytes).context("verifier rejected LSM program")?;

    let prog: &mut Lsm = bpf.program_mut(prog_name).context(prog_name)?.try_into()?;
    prog.load(prog_name, btf).context("Lsm::load")?;
    prog.attach().context("Lsm::attach")?;
    Ok(bpf)
}

fn load_selfprotect(path: &str, btf: &Btf) -> Result<Ebpf> {
    let mut bpf = load_lsm(path, btf, "selfprotect", "kr_task_kill")?;

    // Populate the protected TGID with our HOST pid. The BPF hook
    // reads `BPF_CORE_READ(p, tgid)`, which is the global init-namespace
    // tgid on `task_struct`. If we run inside a pid namespace and use
    // `std::process::id()` (namespace-local pid, often 1), the values
    // never match and selfprotect silently does nothing. Read NSpid
    // from /proc/self/status; the LAST field is the global pid.
    let tgid = crate::util::host_tgid();
    let map = bpf
        .take_map("kr_protected_tgid")
        .context("kr_protected_tgid map missing")?;
    let mut arr: Array<MapData, u32> = Array::try_from(map)?;
    arr.set(0, tgid, 0)?;

    // Take ownership of the denial-event ring buffer and spawn the
    // userspace reader. The reader emits a CRITICAL alert per denied
    // kill so an attempt to silence the daemon shows up in journald,
    // Prometheus, and any wired-up webhook. Without this every block
    // would be invisible (KR-03 in the redteam audit).
    let events = bpf
        .take_map("kr_selfprotect_events")
        .context("kr_selfprotect_events map missing")?;
    let ring: RingBuf<MapData> = RingBuf::try_from(events)?;
    spawn_selfprotect_reader(ring);

    Ok(bpf)
}

/// Drive the self-protect ring buffer. Each entry becomes a
/// CRITICAL alert with detector="selfprotect" so the rest of the
/// alert pipeline (rate limit, output channels, webhook, Prometheus)
/// treats it like any other event.
fn spawn_selfprotect_reader(ring: RingBuf<MapData>) {
    use kernelradar_core::event::KrEvent;
    tokio::spawn(async move {
        let mut async_ring =
            match AsyncFd::with_interest(SelfprotectRing(ring), tokio::io::Interest::READABLE) {
                Ok(a) => a,
                Err(e) => {
                    tracing::error!(error = %e,
                    "selfprotect: failed to register ring buffer with reactor");
                    return;
                }
            };
        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => break,
                ready = async_ring.readable_mut() => {
                    let mut guard = match ready {
                        Ok(g) => g,
                        Err(e) => {
                            tracing::error!(error = %e,
                                "selfprotect: ring buffer readable() error");
                            break;
                        }
                    };
                    let SelfprotectRing(ring) = guard.get_inner_mut();
                    while let Some(item) = ring.next() {
                        if item.len() < std::mem::size_of::<KrEvent>() {
                            continue;
                        }
                        let ev: KrEvent = unsafe {
                            std::ptr::read_unaligned(item.as_ptr() as *const KrEvent)
                        };
                        emit_selfprotect_alert(&ev);
                    }
                    guard.clear_ready();
                }
            }
        }
    });
}

fn emit_selfprotect_alert(ev: &kernelradar_core::event::KrEvent) {
    use crate::util::{comm_str, make_alert, print_alert, read_exe_path};
    let comm = comm_str(ev);
    let exe = read_exe_path(ev.pid);
    let signal = ev.data[0] as i32;
    let target = ev.data[1] as u32;
    let title =
        format!("selfprotect: BLOCKED kill(sig={signal}) of kernelradar tgid={target} by {comm}");
    let ctx = serde_json::json!({
        "blocked_signal":   signal,
        "target_tgid":      target,
        "sender_comm":      comm,
        "sender_exe":       exe,
    });
    let alert = make_alert(ev, exe.as_deref(), "selfprotect", &title, ctx);
    print_alert(&alert, false);
}

/// Newtype around `aya::maps::RingBuf` that delegates `AsRawFd`,
/// mirroring the helper in `runtime.rs`. Lets `tokio::io::unix::AsyncFd`
/// take ownership and reach the underlying fd unambiguously.
struct SelfprotectRing(RingBuf<MapData>);

impl AsRawFd for SelfprotectRing {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.0.as_raw_fd()
    }
}

fn load_bpf_enforce(path: &str, btf: &Btf, allowlist: &[String]) -> Result<Ebpf> {
    let mut bpf = load_lsm(path, btf, "enforce_bpf", "kr_bpf_enforce")?;
    let map = bpf
        .take_map("kr_bpf_allowed")
        .context("kr_bpf_allowed map missing")?;
    let mut hm: HashMap<MapData, [u8; 16], u8> = HashMap::try_from(map)?;
    populate_comm_allowlist(&mut hm, allowlist, "bpf_allowlist")?;
    Ok(bpf)
}

fn load_kmod_enforce(path: &str, btf: &Btf, allowlist: &[String]) -> Result<Ebpf> {
    let mut bpf = load_lsm(path, btf, "enforce_kmod", "kr_kmod_enforce")?;
    let map = bpf
        .take_map("kr_kmod_allowed")
        .context("kr_kmod_allowed map missing")?;
    let mut hm: HashMap<MapData, [u8; 16], u8> = HashMap::try_from(map)?;
    populate_comm_allowlist(&mut hm, allowlist, "kmod_allowlist")?;
    Ok(bpf)
}

/// Insert each allowlist entry into the BPF comm-keyed map.
///
/// Entries longer than `TASK_COMM_LEN - 1` (15 bytes) are silently
/// truncated by the kernel side and would alias against any other
/// entry sharing the first 15 bytes ("systemd-resolved" and
/// "systemd-resolveX" both collapse to "systemd-resolve\0"). Refuse
/// such entries at load time and log a loud warning so operators
/// notice instead of getting a security boundary that depends on
/// tmprosperity. Empty entries would match any process whose comm
/// happens to be all zeros, so they are also refused.
fn populate_comm_allowlist(
    hm: &mut HashMap<MapData, [u8; 16], u8>,
    allowlist: &[String],
    cfg_name: &str,
) -> Result<()> {
    for entry in allowlist {
        let bytes = entry.as_bytes();
        if bytes.is_empty() {
            tracing::warn!(
                cfg = cfg_name,
                "LSM enforcement: empty allowlist entry ignored"
            );
            continue;
        }
        if bytes.len() > 15 {
            tracing::warn!(
                cfg = cfg_name,
                entry = entry.as_str(),
                len = bytes.len(),
                "LSM enforcement: allowlist entry too long for TASK_COMM_LEN-1 \
                 (15 bytes) - the kernel side compares only the first 15 bytes, \
                 so this entry would collide with any other 15-byte prefix. \
                 Entry refused; pick a unique name <= 15 bytes."
            );
            continue;
        }
        let mut key = [0u8; 16];
        key[..bytes.len()].copy_from_slice(bytes);
        hm.insert(key, 1u8, 0)?;
    }
    Ok(())
}
