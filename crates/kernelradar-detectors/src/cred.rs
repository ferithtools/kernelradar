/// Credential theft detector — T-0.8
///
/// Watches read-only opens of credential files. The READ counterpart
/// to FIM (which watches writes). Narrower path set to avoid noise.

use anyhow::{Context, Result};
use aya::{maps::RingBuf, programs::TracePoint, Ebpf};
use std::path::Path;
use tokio::signal;

use kernelradar_core::event::KrEvent;
use crate::allowlist::SharedAllowlist;
use crate::util::{comm_str, is_allowed, make_alert, print_alert, read_exe_path};

#[derive(Debug, Clone, Copy)]
enum MatchKind { Exact, Prefix, Contains }

#[derive(Debug, Clone, Copy)]
struct CredRule {
    pattern:  &'static str,
    kind:     MatchKind,
    severity: u8,
}

const CRED_RULES: &[CredRule] = &[
    // Severity 3 (CRITICAL): direct password hashes / private keys
    CredRule { pattern: "/etc/shadow",    kind: MatchKind::Exact,    severity: 3 },
    CredRule { pattern: "/etc/gshadow",   kind: MatchKind::Exact,    severity: 3 },
    CredRule { pattern: "/root/.ssh/id_", kind: MatchKind::Prefix,   severity: 3 },
    // Severity 2 (ALERT): authorized_keys + cloud creds + auth config
    CredRule { pattern: "/root/.ssh/authorized_keys", kind: MatchKind::Exact, severity: 2 },
    CredRule { pattern: "/root/.aws/",    kind: MatchKind::Prefix,   severity: 2 },
    CredRule { pattern: "/root/.config/gh/", kind: MatchKind::Prefix, severity: 2 },
    CredRule { pattern: "/etc/sudoers",   kind: MatchKind::Prefix,   severity: 2 },
];

/// Match path against credential rules; also handle /home/<user>/.ssh/id_*.
fn match_cred(path: &str) -> Option<&'static CredRule> {
    if let Some(rest) = path.strip_prefix("/home/") {
        if let Some(slash) = rest.find('/') {
            let after_user = &rest[slash + 1..];
            // /home/<user>/.ssh/id_*
            if after_user.starts_with(".ssh/id_") {
                static HOME_KEY: CredRule = CredRule {
                    pattern: "/home/<user>/.ssh/id_*",
                    kind:    MatchKind::Prefix,
                    severity: 3,
                };
                return Some(&HOME_KEY);
            }
            // /home/<user>/.aws/credentials
            if after_user.starts_with(".aws/credentials") {
                static HOME_AWS: CredRule = CredRule {
                    pattern: "/home/<user>/.aws/credentials",
                    kind:    MatchKind::Exact,
                    severity: 3,
                };
                return Some(&HOME_AWS);
            }
        }
    }

    CRED_RULES.iter().find(|r| match r.kind {
        MatchKind::Exact    => path == r.pattern,
        MatchKind::Prefix   => path.starts_with(r.pattern),
        MatchKind::Contains => path.contains(r.pattern),
    })
}

pub struct CredDetector {
    bpf_obj_path: String,
    allowlist:    SharedAllowlist,
}

impl CredDetector {
    pub fn new(bpf_obj_path: &str, allowlist: SharedAllowlist) -> Self {
        Self { bpf_obj_path: bpf_obj_path.to_string(), allowlist }
    }

    pub async fn run(&self) -> Result<()> {
        let path = Path::new(&self.bpf_obj_path);
        anyhow::ensure!(path.exists(), "BPF object not found: {}", self.bpf_obj_path);

        let mut bpf = Ebpf::load(&std::fs::read(path)?)
            .context("verifier rejected cred BPF")?;

        let tp: &mut TracePoint = bpf
            .program_mut("kr_tp_openat_read")
            .context("kr_tp_openat_read")?
            .try_into()?;
        tp.load()?;
        tp.attach("syscalls", "sys_enter_openat")?;
        tracing::info!("attached tracepoint: syscalls/sys_enter_openat (cred)");

        let mut ring: RingBuf<_> = RingBuf::try_from(
            bpf.map_mut("kr_cred_events").context("kr_cred_events not found")?
        )?;

        tracing::info!(detector = "cred",
                        allowlist_size = self.allowlist.snapshot().len(),
                        "watching reads of credential files");

        loop {
            tokio::select! {
                _ = signal::ctrl_c() => break,
                _ = tokio::time::sleep(tokio::time::Duration::from_millis(100)) => {
                    while let Some(item) = ring.next() {
                        if item.len() < std::mem::size_of::<KrEvent>() { continue; }
                        let ev: KrEvent = unsafe {
                            std::ptr::read_unaligned(item.as_ptr() as *const KrEvent)
                        };
                        self.handle(&ev);
                    }
                }
            }
        }
        Ok(())
    }

    fn handle(&self, ev: &KrEvent) {
        // Reconstruct path from data[0..4] (32 bytes, NUL-terminated)
        let path_bytes: [u8; 32] = unsafe { std::mem::transmute(ev.data) };
        let path = String::from_utf8_lossy(
            path_bytes.split(|&b| b == 0).next().unwrap_or(&[])
        ).to_string();

        let rule = match match_cred(&path) {
            Some(r) => r,
            None    => return,
        };

        let comm = comm_str(ev);
        let exe  = read_exe_path(ev.pid);
        let al   = self.allowlist.snapshot();
        if is_allowed(&comm, exe.as_deref(), &al) { return; }

        let mut ev_copy = ev.clone();
        ev_copy.severity = rule.severity;

        let title = format!("read access to {} by {}", path, comm);
        let ctx = serde_json::json!({
            "path":  path,
            "rule":  rule.pattern,
            "exe":   exe,
        });
        let alert = make_alert(&ev_copy, exe.as_deref(), "cred", &title, ctx);
        print_alert(&alert, false);
    }
}
