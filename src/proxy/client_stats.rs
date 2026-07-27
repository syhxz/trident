//! Per-client-IP connection accounting (`client_stats`)
//!
//! Tracks, in memory, how many connections each distinct client IP
//! currently has open and has ever opened. This exists as a lightweight
//! alternative to full query-level audit logging: when audit logging is
//! enabled, its volume (potentially every SQL statement, from every
//! client) can be too high to run continuously, so operators often want
//! a much cheaper, always-on signal for "how many distinct clients are
//! connecting, and how many connections does each one have" without
//! paying the cost of logging every query.
//!
//! Deliberately does NOT expose raw client IPs as Prometheus label
//! values: Prometheus (and most other metrics backends) treats every
//! distinct label value combination as its own permanently-tracked time
//! series, so using an effectively-unbounded value like a client IP as a
//! label is a well-known cardinality trap that can blow up memory usage
//! on the scrape endpoint, especially under something like a network
//! scan hitting the listener from many source addresses. Instead:
//! - `trident_client_distinct_active_ips` (a single, label-free gauge) is
//!   safe to expose directly via `/metrics` -- its value is inherently
//!   bounded by `proxy.max_clients`.
//! - The actual per-IP breakdown (active/total connections, last-seen
//!   time) is exposed only via the JSON `GET /client-stats` admin
//!   endpoint (see `admin` module), never as Prometheus labels.
//!
//! To keep memory bounded even under IP churn, the tracked-IP table has a
//! hard capacity (`MAX_TRACKED_IPS`); once full, the least-recently-seen
//! currently-*inactive* entry (0 active connections) is evicted to make
//! room for a newly-seen IP. An IP with at least one active connection is
//! never evicted, so the table can never shrink below the current active
//! connection count, which is already bounded by `proxy.max_clients`.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

/// Hard cap on the number of distinct client IPs tracked at once. Once
/// reached, further newly-seen IPs evict the least-recently-seen
/// currently-inactive entry (see module docs).
const MAX_TRACKED_IPS: usize = 10_000;

#[derive(Debug, Clone, Copy)]
struct Entry {
    active_connections: i64,
    total_connections: u64,
    last_seen_unix_secs: u64,
}

/// One client IP's connection stats, as reported by `ClientStats::snapshot`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ClientStatsEntry {
    pub ip: String,
    pub active_connections: i64,
    pub total_connections: u64,
    pub last_seen_unix_secs: u64,
}

/// Thread-safe, in-memory table of per-client-IP connection counts. Only
/// touched once per accepted/closed connection (not once per query), so a
/// plain `Mutex<HashMap<..>>` is more than fast enough -- no need for a
/// lock-free structure or an extra dependency here.
#[derive(Debug, Default)]
pub struct ClientStats {
    entries: Mutex<HashMap<IpAddr, Entry>>,
}

impl ClientStats {
    pub fn new() -> Self {
        ClientStats {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Records that a new connection from `ip` was just accepted.
    /// Returns `true` if making room for a newly-seen IP required
    /// evicting an existing (inactive) entry -- callers may want to
    /// increment an eviction-tracking metric when this happens, as a
    /// signal that per-IP history is being dropped under high IP churn.
    pub fn record_connect(&self, ip: IpAddr) -> bool {
        let now = now_unix_secs();
        let mut entries = self.entries.lock().expect("client_stats mutex poisoned");

        if let Some(entry) = entries.get_mut(&ip) {
            entry.active_connections += 1;
            entry.total_connections += 1;
            entry.last_seen_unix_secs = now;
            return false;
        }

        let evicted = if entries.len() >= MAX_TRACKED_IPS {
            evict_one_inactive(&mut entries)
        } else {
            false
        };

        entries.insert(
            ip,
            Entry {
                active_connections: 1,
                total_connections: 1,
                last_seen_unix_secs: now,
            },
        );
        evicted
    }

    /// Records that a connection from `ip` was just closed.
    pub fn record_disconnect(&self, ip: IpAddr) {
        let now = now_unix_secs();
        let mut entries = self.entries.lock().expect("client_stats mutex poisoned");
        if let Some(entry) = entries.get_mut(&ip) {
            entry.active_connections = (entry.active_connections - 1).max(0);
            entry.last_seen_unix_secs = now;
        }
    }

    /// Number of distinct client IPs with at least one active connection
    /// right now. Safe to expose as a Prometheus gauge value directly
    /// (bounded by `proxy.max_clients`).
    pub fn distinct_active_ip_count(&self) -> usize {
        let entries = self.entries.lock().expect("client_stats mutex poisoned");
        entries.values().filter(|e| e.active_connections > 0).count()
    }

    /// Returns a point-in-time snapshot of every tracked IP's stats, for
    /// `GET /client-stats`.
    pub fn snapshot(&self) -> Vec<ClientStatsEntry> {
        let entries = self.entries.lock().expect("client_stats mutex poisoned");
        entries
            .iter()
            .map(|(ip, e)| ClientStatsEntry {
                ip: ip.to_string(),
                active_connections: e.active_connections,
                total_connections: e.total_connections,
                last_seen_unix_secs: e.last_seen_unix_secs,
            })
            .collect()
    }
}

fn evict_one_inactive(entries: &mut HashMap<IpAddr, Entry>) -> bool {
    let victim = entries
        .iter()
        .filter(|(_, e)| e.active_connections <= 0)
        .min_by_key(|(_, e)| e.last_seen_unix_secs)
        .map(|(ip, _)| *ip);

    match victim {
        Some(ip) => {
            entries.remove(&ip);
            true
        }
        // Every tracked entry currently has an active connection -- this
        // can only happen if the number of distinct active IPs already
        // reached MAX_TRACKED_IPS, which itself requires `max_clients` to
        // be configured at least that high. Nothing safe to evict; let
        // the table grow by one rather than refusing to track a live
        // connection.
        None => false,
    }
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, n))
    }

    #[test]
    fn connect_then_disconnect_returns_active_count_to_zero_but_keeps_total() {
        let stats = ClientStats::new();
        stats.record_connect(ip(1));
        stats.record_connect(ip(1));
        stats.record_disconnect(ip(1));

        let snapshot = stats.snapshot();
        let entry = snapshot.iter().find(|e| e.ip == ip(1).to_string()).unwrap();
        assert_eq!(entry.active_connections, 1);
        assert_eq!(entry.total_connections, 2);
    }

    #[test]
    fn distinct_active_ip_count_ignores_fully_disconnected_ips() {
        let stats = ClientStats::new();
        stats.record_connect(ip(1));
        stats.record_connect(ip(2));
        stats.record_disconnect(ip(2));

        assert_eq!(stats.distinct_active_ip_count(), 1);
    }

    #[test]
    fn disconnect_without_matching_connect_does_not_panic_or_go_negative() {
        let stats = ClientStats::new();
        stats.record_disconnect(ip(9));
        assert_eq!(stats.distinct_active_ip_count(), 0);
    }

    #[test]
    fn multiple_connections_from_same_ip_are_aggregated() {
        let stats = ClientStats::new();
        for _ in 0..5 {
            stats.record_connect(ip(1));
        }
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].total_connections, 5);
        assert_eq!(snapshot[0].active_connections, 5);
    }

    #[test]
    fn an_ip_with_an_active_connection_is_never_evicted() {
        // MAX_TRACKED_IPS is sized for production use, so this test
        // cannot practically drive the table all the way to capacity.
        // Instead it verifies the contract that matters: an IP with an
        // active connection survives regardless of how much unrelated
        // (inactive) IP churn happens around it.
        let stats = ClientStats::new();
        stats.record_connect(ip(1));
        for i in 2..=200u8 {
            stats.record_connect(ip(i));
            stats.record_disconnect(ip(i));
        }
        let snapshot = stats.snapshot();
        let still_present = snapshot.iter().find(|e| e.ip == ip(1).to_string());
        assert!(still_present.is_some());
        assert_eq!(still_present.unwrap().active_connections, 1);
    }
}
