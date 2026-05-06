/// File Integrity Monitor — T-0.5
///
/// Watches openat() calls with write/append/create flags against
/// sensitive paths under /etc, /root, /home. BPF does cheap prefix
/// filtering; this code does fine-grained matching against a list
/// of monitored paths and exact rules.

use anyhow::{Context, Result};
use aya::{maps::RingBuf, programs::TracePoint, Ebpf};
use std::path::Path;
use tokio::signal;

use kernelradar_core::event::KrEvent;
use crate::allowlist::SharedAllowlist;
use crate::util::{comm_str, is_allowed, make_alert, print_alert, read_exe_path};

/// Paths and prefixes considered sensitive.
/// Order matters: more specific first (suffix match wins over prefix).
const SENSITIVE_RULES: &[FimRule] = &[
    FimRule { pattern: "/etc/shadow",        kind: MatchKind::Exact,  severity: 3 },
    FimRule { pattern: "/etc/gshadow",       kind: MatchKind::Exact,  severity: 3 },
    FimRule { pattern: "/etc/passwd",        kind: MatchKind::Exact,  severity: 2 },
    FimRule { pattern: "/etc/group",         kind: MatchKind::Exact,  severity: 2 },
    FimRule { pattern: "/etc/sudoers",       kind: MatchKind::Exact,  severity: 3 },
    FimRule { pattern: "/etc/sudoers.d/",    kind: MatchKind::Prefix, severity: 3 },
    FimRule { pattern: "/etc/ssh/",          kind: MatchKind::Prefix, severity: 2 },
    FimRule { pattern: "/etc/pam.d/",        kind: MatchKind::Prefix, severity: 2 },
    FimRule { pattern: "/etc/cron.d/",       kind: MatchKind::Prefix, severity: 2 },
    FimRule { pattern: "/etc/cron.daily/",   kind: MatchKind::Prefix, severity: 2 },
    FimRule { pattern: "/etc/cron.hourly/",  kind: MatchKind::Prefix, severity: 2 },
    FimRule { pattern: "/etc/init.d/",       kind: MatchKind::Prefix, severity: 2 },
    FimRule { pattern: "/etc/systemd/",      kind: MatchKind::Prefix, severity: 2 },
    FimRule { pattern: "/root/.ssh/",        kind: MatchKind::Prefix, severity: 3 },
    FimRule { pattern: "/root/.bashrc",      kind: MatchKind::Exact,  severity: 2 },
    FimRule { pattern: "/root/.profile",     kind: MatchKind::Exact,  severity: 2 },
];

#[derive(Debug, Clone, Copy)]
enum MatchKind { Exact, Prefix }

#[derive(Debug, Clone, Copy)]
struct FimRule {
    pattern:  &'static str,
    kind:     MatchKind,
    severity: u8,        // 2 = WARNING, 3 = ALERT
}

fn match_path(path: &str) -> Option<&'static FimRule> {
    // Also check ~/.ssh/authorized_keys for any /home user
    if let Some(rest) = path.strip_prefix("/home/") {
        if let Some(idx) = rest.find('/') {
            let after_user = &rest[idx + 1..];
            if after_user.starts_with(".ssh/") || after_user == ".bashrc"
               || after_user == ".profile" {
                static HOME_SSH: FimRule = FimRule {
                    pattern: "/home/<user>/.ssh/...",
                    kind:    MatchKind::Prefix,
                    severity: 3,
                };
                return Some(&HOME_SSH);
            }
        }
    }

    SENSITIVE_RULES.iter().find(|r| match r.kind {
        MatchKind::Exact  => path == r.pattern,
        MatchKind::Prefix => path.starts_with(r.pattern),
    })
}

pub struct FimDetector {
    bpf_obj_path: String,
    allowlist:    SharedAllowlist,
}

impl FimDetector {
    pub fn new(bpf_obj_path: &str, allowlist: SharedAllowlist) -> Self {
        Self { bpf_obj_path: bpf_obj_path.to_string(), allowlist }
    }

    pub async fn run(&self) -> Result<()> {
        let path = Path::new(&self.bpf_obj_path);
        anyhow::ensure!(path.exists(), "BPF object not found: {}", self.bpf_obj_path);

        let mut bpf = Ebpf::load(&std::fs::read(path)?)
            .context("verifier rejected fim BPF")?;

        let tp: &mut TracePoint = bpf
            .program_mut("kr_tp_openat").context("kr_tp_openat")?.try_into()?;
        tp.load()?;
        tp.attach("syscalls", "sys_enter_openat")?;
        tracing::info!("attached tracepoint: syscalls/sys_enter_openat");

        let mut ring: RingBuf<_> = RingBuf::try_from(
            bpf.map_mut("kr_fim_events").context("kr_fim_events not found")?
        )?;

        tracing::info!(detector = "fim",
                        allowlist_size = self.allowlist.snapshot().len(),
                        "watching writes to /etc, /root, /home/*/.ssh");

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
        // Path is packed in data[0..4] as 32 raw bytes (NUL-terminated)
        let path_bytes: [u8; 32] = unsafe {
            std::mem::transmute(ev.data)
        };
        let path = String::from_utf8_lossy(
            path_bytes.split(|&b| b == 0).next().unwrap_or(&[])
        ).to_string();

        // Userspace fine-grained match
        let rule = match match_path(&path) {
            Some(r) => r,
            None    => return,   // BPF filter passed but not in our rules
        };

        let comm = comm_str(ev);
        let exe  = read_exe_path(ev.pid);
        let al   = self.allowlist.snapshot();
        if is_allowed(&comm, exe.as_deref(), &al) { return; }

        // Override BPF severity with rule severity
        let mut ev_copy = ev.clone();
        ev_copy.severity = rule.severity;

        let title = format!("write open to {} by {}", path, comm);
        let ctx = serde_json::json!({
            "path":    path,
            "rule":    rule.pattern,
            "exe":     exe,
        });
        let alert = make_alert(&ev_copy, exe.as_deref(), "fim", &title, ctx);
        print_alert(&alert, false);
    }
}
