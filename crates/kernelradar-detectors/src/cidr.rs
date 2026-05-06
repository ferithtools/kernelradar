//! IPv4 CIDR matcher with hot-reload support, for the network detector's
//! destination allowlist (F-1).
//!
//! Modeled after `SharedAllowlist`: each detector holds an `Arc<RwLock>`,
//! the SIGHUP handler in CLI replaces the inner Vec atomically.
//!
//! IPv4-only; the kernel-side filter in network.bpf.c is also IPv4-only.
//! IPv6 support can come with a parallel `Cidr6` type when the BPF side
//! grows IPv6 hooks.

use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};

/// Parsed CIDR. `network` already has host bits zeroed; `mask` has the
/// top `prefix_len` bits set. Both are in host byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    pub network: u32,
    pub mask:    u32,
}

impl Cidr {
    /// Parse `"a.b.c.d/N"`. Returns None on any malformed input —
    /// caller is expected to log + skip (validation happens at config
    /// load time, but be lenient at runtime).
    pub fn parse(s: &str) -> Option<Self> {
        let (addr_s, len_s) = s.split_once('/')?;
        let addr: Ipv4Addr = addr_s.trim().parse().ok()?;
        let len: u32       = len_s.trim().parse().ok()?;
        if len > 32 { return None; }

        let mask = if len == 0 {
            0
        } else {
            // Shift by 32 is UB in C and panics in Rust debug; len>0 is
            // guaranteed here so 32 - len ∈ [0, 31].
            u32::MAX.checked_shl(32 - len).unwrap_or(0)
        };
        let network = u32::from(addr) & mask;
        Some(Self { network, mask })
    }

    /// Match an IPv4 address (host byte order) against this CIDR.
    #[inline]
    pub fn contains(&self, addr_host: u32) -> bool {
        (addr_host & self.mask) == self.network
    }
}

/// Hot-reloadable shared CIDR list. Matches the `SharedAllowlist` API.
#[derive(Clone)]
pub struct SharedCidrList {
    inner: Arc<RwLock<Vec<Cidr>>>,
}

impl SharedCidrList {
    pub fn new(initial: Vec<Cidr>) -> Self {
        Self { inner: Arc::new(RwLock::new(initial)) }
    }

    /// True if any CIDR in the list contains the given IPv4 address.
    pub fn contains(&self, addr_host: u32) -> bool {
        match self.inner.read() {
            Ok(v) => v.iter().any(|c| c.contains(addr_host)),
            Err(_) => false,
        }
    }

    pub fn len(&self) -> usize {
        self.inner.read().map(|v| v.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool { self.len() == 0 }

    /// Atomically replace contents. Used by SIGHUP handler.
    pub fn replace(&self, new_list: Vec<Cidr>) {
        if let Ok(mut w) = self.inner.write() {
            *w = new_list;
        }
    }
}

/// Parse a list of CIDR strings into `Vec<Cidr>`. Invalid entries are
/// logged via `tracing::warn` and skipped — never panics. Returns the
/// parsed Vec plus the count of skipped entries (for startup logging).
///
/// Intended for both initial `SharedCidrList::new(parse_all(...).0)`
/// and SIGHUP reload (`shared.replace(parse_all(...).0)`).
pub fn parse_all(items: &[String]) -> (Vec<Cidr>, usize) {
    let mut parsed = Vec::with_capacity(items.len());
    let mut skipped = 0usize;
    for s in items {
        match Cidr::parse(s) {
            Some(c) => parsed.push(c),
            None => {
                tracing::warn!(entry = %s,
                    "network: invalid CIDR in destination allowlist — skipped");
                skipped += 1;
            }
        }
    }
    (parsed, skipped)
}

/// Convenience: parse + wrap in a fresh `SharedCidrList`.
pub fn shared_from_strings(items: &[String]) -> (SharedCidrList, usize) {
    let (parsed, skipped) = parse_all(items);
    (SharedCidrList::new(parsed), skipped)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> u32 { u32::from(s.parse::<Ipv4Addr>().unwrap()) }

    #[test]
    fn parse_valid_cidrs() {
        let c = Cidr::parse("149.154.0.0/16").unwrap();
        assert_eq!(c.network, ip("149.154.0.0"));
        assert_eq!(c.mask,    0xFFFF_0000);

        let c = Cidr::parse("10.0.0.0/8").unwrap();
        assert_eq!(c.network, ip("10.0.0.0"));
        assert_eq!(c.mask,    0xFF00_0000);

        // /32 — single host
        let c = Cidr::parse("8.8.8.8/32").unwrap();
        assert_eq!(c.network, ip("8.8.8.8"));
        assert_eq!(c.mask,    u32::MAX);

        // /0 — match everything
        let c = Cidr::parse("0.0.0.0/0").unwrap();
        assert_eq!(c.network, 0);
        assert_eq!(c.mask,    0);
    }

    #[test]
    fn parse_normalizes_host_bits() {
        // Host bits in addr should be masked out by parse().
        let c = Cidr::parse("10.255.255.255/8").unwrap();
        assert_eq!(c.network, ip("10.0.0.0"));
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(Cidr::parse("").is_none());
        assert!(Cidr::parse("not-an-ip/16").is_none());
        assert!(Cidr::parse("10.0.0.0").is_none());        // no slash
        assert!(Cidr::parse("10.0.0.0/").is_none());        // empty len
        assert!(Cidr::parse("10.0.0.0/33").is_none());      // len > 32
        assert!(Cidr::parse("10.0.0.0/-1").is_none());      // negative
        assert!(Cidr::parse("10.0.0.0/foo").is_none());     // non-numeric
        assert!(Cidr::parse("10.0.0.999/16").is_none());    // bad octet
    }

    #[test]
    fn contains_matches_inside_cidr() {
        let tg = Cidr::parse("149.154.0.0/16").unwrap();
        assert!(tg.contains(ip("149.154.0.1")));
        assert!(tg.contains(ip("149.154.166.110")));    // api.telegram.org
        assert!(tg.contains(ip("149.154.255.255")));
        assert!(!tg.contains(ip("149.155.0.0")));
        assert!(!tg.contains(ip("149.153.255.255")));
        assert!(!tg.contains(ip("8.8.8.8")));
    }

    #[test]
    fn contains_handles_edge_lens() {
        // /32 — only the exact host
        let host = Cidr::parse("8.8.8.8/32").unwrap();
        assert!(host.contains(ip("8.8.8.8")));
        assert!(!host.contains(ip("8.8.8.9")));

        // /0 — matches every IPv4 address
        let any = Cidr::parse("0.0.0.0/0").unwrap();
        assert!(any.contains(ip("1.2.3.4")));
        assert!(any.contains(ip("255.255.255.255")));
        assert!(any.contains(0));
    }

    #[test]
    fn shared_list_match() {
        let raw: Vec<String> = vec![
            "149.154.0.0/16".into(),    // Telegram
            "64.233.160.0/19".into(),   // Google range
            "172.65.0.0/16".into(),     // Cloudflare
        ];
        let (list, skipped) = shared_from_strings(&raw);
        assert_eq!(skipped, 0);
        assert_eq!(list.len(), 3);

        assert!(list.contains(ip("149.154.166.110")));   // Telegram
        assert!(list.contains(ip("64.233.160.5")));      // Google
        assert!(list.contains(ip("172.65.42.1")));       // Cloudflare
        assert!(!list.contains(ip("1.1.1.1")));          // not in any
    }

    #[test]
    fn shared_list_replace_is_atomic() {
        let (list, _) = shared_from_strings(&[]);
        assert!(list.is_empty());
        assert!(!list.contains(ip("1.2.3.4")));

        list.replace(vec![Cidr::parse("1.2.0.0/16").unwrap()]);
        assert_eq!(list.len(), 1);
        assert!(list.contains(ip("1.2.3.4")));
        assert!(!list.contains(ip("2.0.0.0")));

        list.replace(vec![]);
        assert!(list.is_empty());
        assert!(!list.contains(ip("1.2.3.4")));
    }

    #[test]
    fn shared_from_strings_skips_garbage_and_counts() {
        let raw: Vec<String> = vec![
            "10.0.0.0/8".into(),          // ok
            "garbage".into(),              // bad
            "10.0.0.0/99".into(),          // bad
            "192.168.0.0/16".into(),      // ok
        ];
        let (list, skipped) = shared_from_strings(&raw);
        assert_eq!(list.len(), 2);
        assert_eq!(skipped, 2);
    }
}
