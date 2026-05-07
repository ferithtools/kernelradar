// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Ferith Tools
//
// Part of the kernelradar project - Linux kernel anomaly detection via BPF.
// See LICENSE for terms.

/// File Integrity Monitor.
///
/// Watches openat() calls with write/append/create flags against
/// sensitive paths under /etc, /root, /home. BPF does cheap prefix
/// filtering; this code does fine-grained matching against a list
/// of monitored paths and exact rules.
use anyhow::Result;

use crate::allowlist::SharedAllowlist;
use crate::runtime::TracepointDetector;
use crate::util::{comm_str, is_allowed, make_alert, print_alert, read_exe_path_verified};
use kernelradar_core::event::KrEvent;

/// Paths and prefixes considered sensitive.
/// Order matters: more specific first (suffix match wins over prefix).
const SENSITIVE_RULES: &[FimRule] = &[
    FimRule {
        pattern: "/etc/shadow",
        kind: MatchKind::Exact,
        severity: 3,
    },
    FimRule {
        pattern: "/etc/gshadow",
        kind: MatchKind::Exact,
        severity: 3,
    },
    FimRule {
        pattern: "/etc/passwd",
        kind: MatchKind::Exact,
        severity: 2,
    },
    FimRule {
        pattern: "/etc/group",
        kind: MatchKind::Exact,
        severity: 2,
    },
    FimRule {
        pattern: "/etc/sudoers",
        kind: MatchKind::Exact,
        severity: 3,
    },
    FimRule {
        pattern: "/etc/sudoers.d/",
        kind: MatchKind::Prefix,
        severity: 3,
    },
    FimRule {
        pattern: "/etc/ssh/",
        kind: MatchKind::Prefix,
        severity: 2,
    },
    FimRule {
        pattern: "/etc/pam.d/",
        kind: MatchKind::Prefix,
        severity: 2,
    },
    FimRule {
        pattern: "/etc/cron.d/",
        kind: MatchKind::Prefix,
        severity: 2,
    },
    FimRule {
        pattern: "/etc/cron.daily/",
        kind: MatchKind::Prefix,
        severity: 2,
    },
    FimRule {
        pattern: "/etc/cron.hourly/",
        kind: MatchKind::Prefix,
        severity: 2,
    },
    FimRule {
        pattern: "/etc/init.d/",
        kind: MatchKind::Prefix,
        severity: 2,
    },
    FimRule {
        pattern: "/etc/systemd/",
        kind: MatchKind::Prefix,
        severity: 2,
    },
    FimRule {
        pattern: "/root/.ssh/",
        kind: MatchKind::Prefix,
        severity: 3,
    },
    FimRule {
        pattern: "/root/.bashrc",
        kind: MatchKind::Exact,
        severity: 2,
    },
    FimRule {
        pattern: "/root/.profile",
        kind: MatchKind::Exact,
        severity: 2,
    },
];

#[derive(Debug, Clone, Copy)]
enum MatchKind {
    Exact,
    Prefix,
}

#[derive(Debug, Clone, Copy)]
struct FimRule {
    pattern: &'static str,
    kind: MatchKind,
    severity: u8, // 2 = WARNING, 3 = ALERT
}

fn match_path(path: &str) -> Option<&'static FimRule> {
    // Also check ~/.ssh/authorized_keys for any /home user
    if let Some(rest) = path.strip_prefix("/home/") {
        if let Some(idx) = rest.find('/') {
            let after_user = &rest[idx + 1..];
            if after_user.starts_with(".ssh/")
                || after_user == ".bashrc"
                || after_user == ".profile"
            {
                static HOME_SSH: FimRule = FimRule {
                    pattern: "/home/<user>/.ssh/...",
                    kind: MatchKind::Prefix,
                    severity: 3,
                };
                return Some(&HOME_SSH);
            }
        }
    }

    SENSITIVE_RULES.iter().find(|r| match r.kind {
        MatchKind::Exact => path == r.pattern,
        MatchKind::Prefix => path.starts_with(r.pattern),
    })
}

pub struct FimDetector {
    bpf_obj_path: String,
    allowlist: SharedAllowlist,
}

impl FimDetector {
    pub fn new(bpf_obj_path: &str, allowlist: SharedAllowlist) -> Self {
        Self {
            bpf_obj_path: bpf_obj_path.to_string(),
            allowlist,
        }
    }

    pub async fn run(&self) -> Result<()> {
        let mut det = TracepointDetector::load("fim", &self.bpf_obj_path, "fim")?;
        det.attach_tracepoint("kr_tp_openat", "syscalls", "sys_enter_openat")?;

        tracing::info!(
            detector = "fim",
            allowlist_size = self.allowlist.snapshot().len(),
            "watching writes to /etc, /root, /home/*/.ssh"
        );

        det.run("kr_fim_events", |ev| self.handle(ev)).await
    }

    fn handle(&self, ev: &KrEvent) {
        // Path is packed into data[0..4] as 32 NUL-terminated raw bytes by
        // the BPF side. Reassemble word-by-word - same native endianness as
        // the BPF write, no `unsafe` needed.
        let mut path_bytes = [0u8; 32];
        for (i, word) in ev.data.iter().enumerate() {
            path_bytes[i * 8..(i + 1) * 8].copy_from_slice(&word.to_ne_bytes());
        }
        let path = String::from_utf8_lossy(path_bytes.split(|&b| b == 0).next().unwrap_or(&[]))
            .to_string();

        // Userspace fine-grained match
        let rule = match match_path(&path) {
            Some(r) => r,
            None => return, // BPF filter passed but not in our rules
        };

        let comm = comm_str(ev);
        let exe = read_exe_path_verified(ev.pid, &comm);
        let al = self.allowlist.snapshot();
        if is_allowed(&comm, exe.as_deref(), &al) {
            return;
        }

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
