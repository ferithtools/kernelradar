// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Ferith Tools
//
// Part of the kernelradar project — Linux kernel anomaly detection via BPF.
// See LICENSE for terms.

/// Credential theft detector.
///
/// Watches read-only opens of credential files. The READ counterpart
/// to FIM (which watches writes). Narrower path set to avoid noise.
use anyhow::Result;

use crate::allowlist::SharedAllowlist;
use crate::runtime::TracepointDetector;
use crate::util::{comm_str, is_allowed, make_alert, print_alert, read_exe_path_verified};
use kernelradar_core::event::KrEvent;

#[derive(Debug, Clone, Copy)]
enum MatchKind {
    Exact,
    Prefix,
    #[allow(dead_code)]
    Contains,
}

#[derive(Debug, Clone, Copy)]
struct CredRule {
    pattern: &'static str,
    kind: MatchKind,
    severity: u8,
}

const CRED_RULES: &[CredRule] = &[
    // Severity 3 (CRITICAL): direct password hashes / private keys
    CredRule {
        pattern: "/etc/shadow",
        kind: MatchKind::Exact,
        severity: 3,
    },
    CredRule {
        pattern: "/etc/gshadow",
        kind: MatchKind::Exact,
        severity: 3,
    },
    CredRule {
        pattern: "/root/.ssh/id_",
        kind: MatchKind::Prefix,
        severity: 3,
    },
    // Severity 2 (ALERT): authorized_keys + cloud creds + auth config
    CredRule {
        pattern: "/root/.ssh/authorized_keys",
        kind: MatchKind::Exact,
        severity: 2,
    },
    CredRule {
        pattern: "/root/.aws/",
        kind: MatchKind::Prefix,
        severity: 2,
    },
    CredRule {
        pattern: "/root/.config/gh/",
        kind: MatchKind::Prefix,
        severity: 2,
    },
    CredRule {
        pattern: "/etc/sudoers",
        kind: MatchKind::Prefix,
        severity: 2,
    },
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
                    kind: MatchKind::Prefix,
                    severity: 3,
                };
                return Some(&HOME_KEY);
            }
            // /home/<user>/.aws/credentials
            if after_user.starts_with(".aws/credentials") {
                static HOME_AWS: CredRule = CredRule {
                    pattern: "/home/<user>/.aws/credentials",
                    kind: MatchKind::Exact,
                    severity: 3,
                };
                return Some(&HOME_AWS);
            }
        }
    }

    CRED_RULES.iter().find(|r| match r.kind {
        MatchKind::Exact => path == r.pattern,
        MatchKind::Prefix => path.starts_with(r.pattern),
        MatchKind::Contains => path.contains(r.pattern),
    })
}

pub struct CredDetector {
    bpf_obj_path: String,
    allowlist: SharedAllowlist,
}

impl CredDetector {
    pub fn new(bpf_obj_path: &str, allowlist: SharedAllowlist) -> Self {
        Self {
            bpf_obj_path: bpf_obj_path.to_string(),
            allowlist,
        }
    }

    pub async fn run(&self) -> Result<()> {
        let mut det = TracepointDetector::load("cred", &self.bpf_obj_path, "cred")?;
        det.attach_tracepoint("kr_tp_openat_read", "syscalls", "sys_enter_openat")?;

        tracing::info!(
            detector = "cred",
            allowlist_size = self.allowlist.snapshot().len(),
            "watching reads of credential files"
        );

        det.run("kr_cred_events", |ev| self.handle(ev)).await
    }

    fn handle(&self, ev: &KrEvent) {
        // Path is packed into data[0..4] as 32 NUL-terminated raw bytes by
        // the BPF side. Reassemble word-by-word — same native endianness as
        // the BPF write, no `unsafe` needed.
        let mut path_bytes = [0u8; 32];
        for (i, word) in ev.data.iter().enumerate() {
            path_bytes[i * 8..(i + 1) * 8].copy_from_slice(&word.to_ne_bytes());
        }
        let path = String::from_utf8_lossy(path_bytes.split(|&b| b == 0).next().unwrap_or(&[]))
            .to_string();

        let rule = match match_cred(&path) {
            Some(r) => r,
            None => return,
        };

        let comm = comm_str(ev);
        let exe = read_exe_path_verified(ev.pid, &comm);
        let al = self.allowlist.snapshot();
        if is_allowed(&comm, exe.as_deref(), &al) {
            return;
        }

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
