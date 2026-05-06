// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Ferith Tools
//
// Part of the kernelradar project — Linux kernel anomaly detection via BPF.
// See LICENSE for terms.

/// Shared allowlist with hot-reload support (T-2.4 + T-2.6).
///
/// Each detector holds an `Arc<SharedAllowlist>`; SIGHUP handler in
/// CLI replaces the inner Vec atomically. Read path is lock-free
/// after the initial RwLock acquisition.
use std::sync::{Arc, RwLock};

#[derive(Clone)]
pub struct SharedAllowlist {
    inner: Arc<RwLock<Vec<String>>>,
}

impl SharedAllowlist {
    pub fn new(initial: Vec<String>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(initial)),
        }
    }

    /// Read snapshot. Cheap: clones the Vec (typically 20-40 strings).
    pub fn snapshot(&self) -> Vec<String> {
        self.inner.read().map(|v| v.clone()).unwrap_or_default()
    }

    /// Atomically replace contents. Used by SIGHUP handler.
    pub fn replace(&self, new_list: Vec<String>) {
        if let Ok(mut w) = self.inner.write() {
            *w = new_list;
        }
    }
}
