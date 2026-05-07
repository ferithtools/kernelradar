// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Ferith Tools
//
// Part of the kernelradar project - Linux kernel anomaly detection via BPF.
// See LICENSE for terms.

//! Shared scaffolding for tracepoint-based detectors.
//!
//! Every detector goes through the same dance: read the `.bpf.o` from disk,
//! integrity-check it, load via Aya, pin `kr_stats` for external consumers,
//! attach one or more tracepoints, then drive the per-CPU ring buffer in a
//! polling loop. `TracepointDetector` collapses that boilerplate into a
//! builder so each individual detector keeps only its event-handling logic.

use anyhow::{Context, Result};
use aya::{maps::RingBuf, programs::TracePoint, Ebpf};
use std::os::fd::AsRawFd;
use std::path::Path;
use tokio::io::unix::AsyncFd;
use tokio::signal;

use crate::integrity::verify as verify_bpf;
use kernelradar_core::event::KrEvent;

/// Builder + runner for a tracepoint-driven detector.
///
/// Holds an owned `Ebpf` instance for the lifetime of the detector, so the
/// `RingBuf` taken out of it during `run` keeps its borrow valid until the
/// detector exits.
pub struct TracepointDetector {
    name: &'static str,
    ebpf: Ebpf,
}

impl TracepointDetector {
    /// Load the BPF object at `path`, verify its build-time SHA-256 against
    /// the integrity table, and pin the `kr_stats` map at
    /// `/sys/fs/bpf/kr_stats_<pin_suffix>` for external metric collectors.
    /// `name` is the integrity-table key (must match the `build.rs` table).
    pub fn load(name: &'static str, path: &str, pin_suffix: &str) -> Result<Self> {
        let p = Path::new(path);
        anyhow::ensure!(
            p.exists(),
            "BPF object not found: {path}\nBuild: cd crates/kernelradar-bpf && make"
        );
        let bytes = std::fs::read(p)?;
        verify_bpf(name, &bytes)?;
        let mut ebpf =
            Ebpf::load(&bytes).with_context(|| format!("verifier rejected {name} BPF"))?;

        if let Some(stats) = ebpf.map_mut("kr_stats") {
            let _ = stats.pin(format!("/sys/fs/bpf/kr_stats_{pin_suffix}"));
        }

        Ok(Self { name, ebpf })
    }

    /// Attach a tracepoint program named `prog` (the `SEC` name on the BPF
    /// side) to the kernel hook `category/hook` (e.g. `"syscalls"` /
    /// `"sys_enter_setuid"`).
    pub fn attach_tracepoint(
        &mut self,
        prog: &'static str,
        category: &'static str,
        hook: &'static str,
    ) -> Result<&mut Self> {
        let tp: &mut TracePoint = self.ebpf.program_mut(prog).context(prog)?.try_into()?;
        tp.load()?;
        tp.attach(category, hook)
            .with_context(|| format!("attach {category}/{hook}"))?;
        tracing::info!("attached tracepoint: {category}/{hook}");
        Ok(self)
    }

    /// Drain `events_map` (the per-CPU ring buffer) and dispatch every
    /// payload to `handle` until SIGINT. The ring buffer's file descriptor
    /// is registered with tokio as readable-interest; events wake the task
    /// directly instead of being polled every 100 ms, so end-to-end
    /// latency is no longer bounded by the polling interval. Missed events
    /// (kernel produces faster than userspace can drain) still show up as
    /// `kr_stats_<det>_dropped_total` rather than as silent loss.
    pub async fn run<F>(mut self, events_map: &'static str, mut handle: F) -> Result<()>
    where
        F: FnMut(&KrEvent),
    {
        // Take ownership of the events map out of Ebpf so the resulting
        // RingBuf is owned (not borrowed from `&mut self.ebpf`); AsyncFd
        // needs an owned `T: AsRawFd` to register with the reactor.
        let map = self
            .ebpf
            .take_map(events_map)
            .with_context(|| format!("{events_map} not found"))?;
        let ring: RingBuf<aya::maps::MapData> = RingBuf::try_from(map)?;
        let _det = self.name;
        let mut async_ring =
            AsyncFd::with_interest(RawFdRing(ring), tokio::io::Interest::READABLE)?;

        loop {
            tokio::select! {
                _ = signal::ctrl_c() => break,
                ready = async_ring.readable_mut() => {
                    let mut guard = ready?;
                    let RawFdRing(ring) = guard.get_inner_mut();
                    while let Some(item) = ring.next() {
                        if item.len() < std::mem::size_of::<KrEvent>() {
                            continue;
                        }
                        let ev: KrEvent = unsafe {
                            std::ptr::read_unaligned(item.as_ptr() as *const KrEvent)
                        };
                        handle(&ev);
                    }
                    guard.clear_ready();
                }
            }
        }
        Ok(())
    }
}

/// Newtype wrapper around `aya::maps::RingBuf` that delegates `AsRawFd`.
/// Aya's `RingBuf` exposes its fd via `Deref` to `MapData`; making the
/// blanket `AsRawFd` impl explicit on the wrapper avoids any ambiguity
/// when `tokio::io::unix::AsyncFd` reaches for the descriptor.
struct RawFdRing(RingBuf<aya::maps::MapData>);

impl AsRawFd for RawFdRing {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.0.as_raw_fd()
    }
}
