// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Ferith Tools
//
// Part of the kernelradar project - Linux kernel anomaly detection via BPF.
// See LICENSE for terms.

//! Shared allowlist with hot-reload support.
//!
//! Each detector holds an `Arc<SharedAllowlist>`; the SIGHUP handler in
//! the CLI atomically replaces the inner [`CompiledAllowlist`]. The
//! per-event read path is allocation-free: it grabs an `Arc<Compiled>`
//! out of the RwLock and dispatches matching against pre-compiled
//! regex / pre-hashed exact strings - no `regex::Regex::new` per
//! event, no `Vec<String>` clone.

use std::collections::HashSet;
use std::sync::{Arc, RwLock};

use regex::RegexSet;

/// Pre-compiled view of an allowlist.
///
/// Built once per `replace()` call; dispatched on every event.
/// `RegexSet` consolidates every `/regex/` entry into a single DFA
/// so that `is_match` runs in one pass regardless of how many
/// regex entries are on the list.
pub struct CompiledAllowlist {
    /// `comm`, `exe`, or basename(exe) exact-string matches.
    exact: HashSet<String>,
    /// All regex entries combined into one set; one DFA traversal.
    regex: RegexSet,
}

impl CompiledAllowlist {
    pub fn build(entries: &[String]) -> Self {
        let mut exact: HashSet<String> = HashSet::with_capacity(entries.len());
        let mut patterns: Vec<&str> = Vec::new();
        for e in entries {
            if let Some(p) = e.strip_prefix('/').and_then(|s| s.strip_suffix('/')) {
                patterns.push(p);
            } else {
                exact.insert(e.clone());
            }
        }
        let regex = RegexSet::new(&patterns).unwrap_or_else(|err| {
            // Bad regex was already caught by Config::validate at
            // startup; if we hit this branch on hot-reload, log the
            // bad pattern and fall back to an empty set so the
            // exact-string portion still works.
            tracing::warn!(error = %err,
                "allowlist: regex compile failed during reload, regex matches disabled");
            RegexSet::new::<&str, _>(std::iter::empty()).expect("empty RegexSet always builds")
        });
        Self { exact, regex }
    }

    /// Number of allowlist entries (exact + regex). For diagnostics.
    pub fn len(&self) -> usize {
        self.exact.len() + self.regex.patterns().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Return true if any of `comm`, `exe`, or `basename(exe)` matches
    /// an allowlist entry. Match order matches the legacy free-function:
    /// exact first, regex second.
    pub fn is_allowed(&self, comm: &str, exe: Option<&str>) -> bool {
        if self.exact.contains(comm) {
            return true;
        }
        if let Some(p) = exe {
            if self.exact.contains(p) {
                return true;
            }
            if let Some(b) = p.rsplit('/').next() {
                if self.exact.contains(b) {
                    return true;
                }
            }
        }
        if !self.regex.is_empty() && self.regex.is_match(comm) {
            return true;
        }
        if let Some(p) = exe {
            if !self.regex.is_empty() {
                if self.regex.is_match(p) {
                    return true;
                }
                if let Some(b) = p.rsplit('/').next() {
                    if self.regex.is_match(b) {
                        return true;
                    }
                }
            }
        }
        false
    }
}

#[derive(Clone)]
pub struct SharedAllowlist {
    inner: Arc<RwLock<Arc<CompiledAllowlist>>>,
}

impl SharedAllowlist {
    pub fn new(initial: Vec<String>) -> Self {
        let compiled = Arc::new(CompiledAllowlist::build(&initial));
        Self {
            inner: Arc::new(RwLock::new(compiled)),
        }
    }

    /// Cheap snapshot: clones the Arc, not the underlying Compiled.
    pub fn snapshot(&self) -> Arc<CompiledAllowlist> {
        self.inner
            .read()
            .map(|v| v.clone())
            .unwrap_or_else(|_| Arc::new(CompiledAllowlist::build(&[])))
    }

    /// Atomically replace contents. Used by SIGHUP handler.
    /// Compilation happens here, not on the per-event hot path.
    pub fn replace(&self, new_list: Vec<String>) {
        let compiled = Arc::new(CompiledAllowlist::build(&new_list));
        if let Ok(mut w) = self.inner.write() {
            *w = compiled;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn al(entries: &[&str]) -> CompiledAllowlist {
        CompiledAllowlist::build(&entries.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn exact_comm_match() {
        let a = al(&["sshd"]);
        assert!(a.is_allowed("sshd", None));
        assert!(!a.is_allowed("sshooly", None));
        assert!(!a.is_allowed("ssh", None));
    }

    #[test]
    fn exact_exe_and_basename_match() {
        let a = al(&["/usr/sbin/sshd", "kernelradar"]);
        assert!(a.is_allowed("ignored", Some("/usr/sbin/sshd")));
        assert!(a.is_allowed("ignored", Some("/sbin/kernelradar")));
        // Same basename match - "kernelradar" entry matches via basename
        assert!(a.is_allowed("kernelradar", None));
    }

    #[test]
    fn regex_match() {
        let a = al(&["/^systemd.*/"]);
        assert!(a.is_allowed("systemd-udevd", None));
        assert!(a.is_allowed("systemd-resolved", None));
        assert!(!a.is_allowed("not-systemd", None));
    }

    #[test]
    fn no_prefix_starts_with_match() {
        // The regression that motivated removing prefix matching:
        // "sshd" must NOT silently allow "sshd-derived" via starts_with.
        let a = al(&["sshd"]);
        assert!(!a.is_allowed("sshd-session", None));
        assert!(!a.is_allowed("sshooly-rev-shell", None));
    }

    #[test]
    fn invalid_regex_logs_and_falls_back() {
        // Mismatched paren - should not panic, just produce an
        // allowlist that matches nothing on the regex side.
        let a = al(&["/[(/"]);
        assert!(!a.is_allowed("anything", None));
    }
}
