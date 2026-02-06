pub mod delta;
pub mod hlc;
pub mod lww_map;
pub mod g_counter;

use delta::CrdtDelta;
use hlc::{Hlc, HlcTimestamp};
use lww_map::LwwMap;
use g_counter::RateLimitStore;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct CrdtStore {
    hlc: Hlc,
    cache: LwwMap,
    rate_limits: RateLimitStore,
    last_broadcast_ts: HlcTimestamp,
}

impl CrdtStore {
    pub fn new(node_id: u64) -> Self {
        Self {
            hlc: Hlc::new(node_id),
            cache: LwwMap::new(),
            rate_limits: RateLimitStore::new(node_id),
            last_broadcast_ts: HlcTimestamp::ZERO,
        }
    }

    fn wall_ms_now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    pub fn cache_get(&self, key: &str) -> Option<Vec<u8>> {
        self.cache.get(key, Self::wall_ms_now())
    }

    pub fn cache_set(&mut self, key: String, value: Vec<u8>, ttl_ms: u64) {
        let ts = self.hlc.now();
        self.cache.set(key, value, ts, ttl_ms, Self::wall_ms_now());
    }

    pub fn cache_delete(&mut self, key: &str) {
        let ts = self.hlc.now();
        self.cache.delete(key, ts, Self::wall_ms_now());
    }

    pub fn rate_limit_peek(&self, key: &str, window_ms: u64) -> u64 {
        self.rate_limits
            .peek_count(key, window_ms, Self::wall_ms_now())
    }

    pub fn rate_limit_check(&mut self, key: &str, limit: u32, window_ms: u64) -> bool {
        self.rate_limits
            .check_and_increment(key, limit, window_ms, Self::wall_ms_now())
    }

    pub fn peek_broadcast_delta(&self) -> CrdtDelta {
        let cache_delta = {
            let d = self.cache.extract_delta_since(self.last_broadcast_ts);
            match d.entries.is_empty() {
                true => None,
                false => Some(d),
            }
        };
        let rate_limit_deltas = self.rate_limits.extract_dirty_deltas();
        CrdtDelta {
            version: 1,
            source_node: self.hlc.node_id(),
            cache_delta,
            rate_limit_deltas,
        }
    }

    pub fn commit_broadcast(&mut self, delta: &CrdtDelta) {
        let max_ts = delta
            .cache_delta
            .as_ref()
            .and_then(|d| d.entries.iter().map(|(_, e)| e.timestamp).max())
            .unwrap_or(self.last_broadcast_ts);
        self.last_broadcast_ts = max_ts;
        let committed_keys: std::collections::HashSet<&str> = delta
            .rate_limit_deltas
            .iter()
            .map(|d| d.key.as_str())
            .collect();
        committed_keys.iter().for_each(|&key| {
            let still_matches = self
                .rate_limits
                .peek_dirty_counter(key)
                .zip(delta.rate_limit_deltas.iter().find(|d| d.key == key))
                .is_some_and(|(current, committed)| {
                    current.window_start_ms == committed.counter.window_start_ms
                        && current.total() == committed.counter.total()
                });
            if still_matches {
                self.rate_limits.clear_single_dirty(key);
            }
        });
    }

    pub fn merge_delta(&mut self, delta: &CrdtDelta) -> bool {
        if !delta.is_compatible() {
            tracing::warn!(
                version = delta.version,
                "dropping incompatible CRDT delta version"
            );
            return false;
        }
        let mut changed = false;
        if let Some(ref cache_delta) = delta.cache_delta {
            cache_delta.entries.iter().for_each(|(key, entry)| {
                let _ = self.hlc.receive(entry.timestamp);
                if self.cache.merge_entry(key.clone(), entry.clone()) {
                    changed = true;
                }
            });
        }
        delta.rate_limit_deltas.iter().for_each(|rd| {
            if self
                .rate_limits
                .merge_counter(rd.key.clone(), &rd.counter)
            {
                changed = true;
            }
        });
        changed
    }

    pub fn run_maintenance(&mut self) {
        let now = Self::wall_ms_now();
        self.cache.gc_tombstones(now);
        self.cache.gc_expired(now);
        self.rate_limits.gc_expired(now);
    }

    pub fn cache_estimated_bytes(&self) -> usize {
        self.cache.estimated_bytes()
    }

    pub fn rate_limit_estimated_bytes(&self) -> usize {
        self.rate_limits.estimated_bytes()
    }

    pub fn evict_lru(&mut self) -> Option<String> {
        self.cache.evict_lru()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_cache() {
        let mut store = CrdtStore::new(1);
        store.cache_set("key".into(), b"value".to_vec(), 60_000);
        assert_eq!(store.cache_get("key"), Some(b"value".to_vec()));
    }

    #[test]
    fn delta_merge_convergence() {
        let mut store_a = CrdtStore::new(1);
        let mut store_b = CrdtStore::new(2);

        store_a.cache_set("x".into(), b"from_a".to_vec(), 60_000);
        store_b.cache_set("y".into(), b"from_b".to_vec(), 60_000);

        let delta_a = store_a.peek_broadcast_delta();
        store_a.commit_broadcast(&delta_a);
        let delta_b = store_b.peek_broadcast_delta();
        store_b.commit_broadcast(&delta_b);

        store_b.merge_delta(&delta_a);
        store_a.merge_delta(&delta_b);

        assert_eq!(store_a.cache_get("x"), Some(b"from_a".to_vec()));
        assert_eq!(store_a.cache_get("y"), Some(b"from_b".to_vec()));
        assert_eq!(store_b.cache_get("x"), Some(b"from_a".to_vec()));
        assert_eq!(store_b.cache_get("y"), Some(b"from_b".to_vec()));
    }

    #[test]
    fn rate_limit_across_stores() {
        let mut store_a = CrdtStore::new(1);
        let mut store_b = CrdtStore::new(2);

        store_a.rate_limit_check("rl:test", 5, 60_000);
        store_a.rate_limit_check("rl:test", 5, 60_000);
        store_b.rate_limit_check("rl:test", 5, 60_000);

        let delta_a = store_a.peek_broadcast_delta();
        store_a.commit_broadcast(&delta_a);
        store_b.merge_delta(&delta_a);

        let delta_b = store_b.peek_broadcast_delta();
        store_b.commit_broadcast(&delta_b);
        store_a.merge_delta(&delta_b);
    }

    #[test]
    fn incompatible_version_rejected() {
        let mut store = CrdtStore::new(1);
        let delta = CrdtDelta {
            version: 255,
            source_node: 99,
            cache_delta: None,
            rate_limit_deltas: vec![],
        };
        assert!(!store.merge_delta(&delta));
    }
}
