pub mod delta;
pub mod hlc;
pub mod lww_map;
pub mod g_counter;

use crate::config::fnv1a;
use delta::CrdtDelta;
use hlc::{Hlc, HlcTimestamp};
use lww_map::{LwwDelta, LwwMap};
use g_counter::RateLimitStore;
use parking_lot::{Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

const SHARD_COUNT: usize = 64;
const MAX_PROMOTIONS_PER_SHARD: usize = 8192;
const MAX_REPLICABLE_VALUE_SIZE: usize = 15 * 1024 * 1024;

struct CrdtShard {
    cache: LwwMap,
    rate_limits: RateLimitStore,
    last_broadcast_ts: HlcTimestamp,
}

impl CrdtShard {
    fn new(node_id: u64) -> Self {
        Self {
            cache: LwwMap::new(),
            rate_limits: RateLimitStore::new(node_id),
            last_broadcast_ts: HlcTimestamp::ZERO,
        }
    }
}

pub struct ShardedCrdtStore {
    hlc: Mutex<Hlc>,
    shards: Box<[RwLock<CrdtShard>]>,
    promotions: Box<[Mutex<Vec<String>>]>,
    shard_mask: usize,
    node_id: u64,
}

impl ShardedCrdtStore {
    pub fn new(node_id: u64) -> Self {
        const { assert!(SHARD_COUNT.is_power_of_two()) };
        let shards: Vec<RwLock<CrdtShard>> = (0..SHARD_COUNT)
            .map(|_| RwLock::new(CrdtShard::new(node_id)))
            .collect();
        let promotions: Vec<Mutex<Vec<String>>> = (0..SHARD_COUNT)
            .map(|_| Mutex::new(Vec::new()))
            .collect();
        Self {
            hlc: Mutex::new(Hlc::new(node_id)),
            shards: shards.into_boxed_slice(),
            promotions: promotions.into_boxed_slice(),
            shard_mask: SHARD_COUNT - 1,
            node_id,
        }
    }

    fn shard_for(&self, key: &str) -> usize {
        fnv1a(key.as_bytes()) as usize & self.shard_mask
    }

    fn wall_ms_now() -> u64 {
        u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
        )
        .unwrap_or(u64::MAX)
    }

    pub fn cache_get(&self, key: &str) -> Option<Vec<u8>> {
        let idx = self.shard_for(key);
        let result = self.shards[idx].read().cache.get(key, Self::wall_ms_now());
        if result.is_some() {
            let mut promos = self.promotions[idx].lock();
            if promos.len() < MAX_PROMOTIONS_PER_SHARD {
                promos.push(key.to_string());
            }
        }
        result
    }

    pub fn cache_set(&self, key: String, value: Vec<u8>, ttl_ms: u64) {
        if value.len() > MAX_REPLICABLE_VALUE_SIZE {
            tracing::warn!(
                key = %key,
                value_size = value.len(),
                max = MAX_REPLICABLE_VALUE_SIZE,
                "value exceeds replicable size limit, may fail to replicate to peers"
            );
        }
        let ts = self.hlc.lock().now();
        let wall = Self::wall_ms_now();
        self.shards[self.shard_for(&key)]
            .write()
            .cache
            .set(key, value, ts, ttl_ms, wall);
    }

    pub fn cache_delete(&self, key: &str) {
        let ts = self.hlc.lock().now();
        let wall = Self::wall_ms_now();
        self.shards[self.shard_for(key)]
            .write()
            .cache
            .delete(key, ts, wall);
    }

    pub fn rate_limit_peek(&self, key: &str, window_ms: u64) -> u64 {
        self.shards[self.shard_for(key)]
            .read()
            .rate_limits
            .peek_count(key, window_ms, Self::wall_ms_now())
    }

    pub fn rate_limit_check(&self, key: &str, limit: u32, window_ms: u64) -> bool {
        self.shards[self.shard_for(key)]
            .write()
            .rate_limits
            .check_and_increment(key, limit, window_ms, Self::wall_ms_now())
    }

    pub fn peek_broadcast_delta(&self) -> CrdtDelta {
        let mut cache_entries: Vec<(String, lww_map::LwwEntry)> = Vec::new();
        let mut rate_limit_deltas: Vec<g_counter::GCounterDelta> = Vec::new();

        self.shards.iter().for_each(|shard_lock| {
            let shard = shard_lock.read();
            let lww_delta = shard.cache.extract_delta_since(shard.last_broadcast_ts);
            cache_entries.extend(lww_delta.entries);
            rate_limit_deltas.extend(shard.rate_limits.extract_dirty_deltas());
        });

        let cache_delta = match cache_entries.is_empty() {
            true => None,
            false => Some(LwwDelta { entries: cache_entries }),
        };

        CrdtDelta {
            version: 1,
            source_node: self.node_id,
            cache_delta,
            rate_limit_deltas,
        }
    }

    pub fn commit_broadcast(&self, delta: &CrdtDelta) {
        let cache_entries_by_shard: Vec<(usize, &HlcTimestamp)> = delta
            .cache_delta
            .as_ref()
            .map(|d| {
                d.entries
                    .iter()
                    .map(|(key, entry)| (self.shard_for(key), &entry.timestamp))
                    .collect()
            })
            .unwrap_or_default();

        let mut max_ts_per_shard: Vec<Option<HlcTimestamp>> = (0..self.shards.len())
            .map(|_| None)
            .collect();

        cache_entries_by_shard.iter().for_each(|&(shard_idx, ts)| {
            let slot = &mut max_ts_per_shard[shard_idx];
            *slot = Some(match slot {
                Some(existing) if *existing >= *ts => *existing,
                _ => *ts,
            });
        });

        let rl_index: std::collections::HashMap<&str, &g_counter::GCounter> = delta
            .rate_limit_deltas
            .iter()
            .map(|d| (d.key.as_str(), &d.counter))
            .collect();

        let mut shard_rl_keys: Vec<Vec<&str>> = (0..self.shards.len())
            .map(|_| Vec::new())
            .collect();
        rl_index.keys().for_each(|&key| {
            shard_rl_keys[self.shard_for(key)].push(key);
        });

        self.shards.iter().enumerate().for_each(|(idx, shard_lock)| {
            let has_cache_update = max_ts_per_shard[idx].is_some();
            let has_rl_keys = !shard_rl_keys[idx].is_empty();
            if !has_cache_update && !has_rl_keys {
                return;
            }
            let mut shard = shard_lock.write();
            if let Some(max_ts) = max_ts_per_shard[idx] {
                shard.last_broadcast_ts = max_ts;
            }
            shard_rl_keys[idx].iter().for_each(|&key| {
                let still_matches = shard
                    .rate_limits
                    .peek_dirty_counter(key)
                    .zip(rl_index.get(key))
                    .is_some_and(|(current, committed)| {
                        current.window_start_ms == committed.window_start_ms
                            && current.total() == committed.total()
                    });
                if still_matches {
                    shard.rate_limits.clear_single_dirty(key);
                }
            });
        });
    }

    pub fn merge_delta(&self, delta: &CrdtDelta) -> bool {
        if !delta.is_compatible() {
            tracing::warn!(
                version = delta.version,
                "dropping incompatible CRDT delta version"
            );
            return false;
        }

        if let Some(ref cache_delta) = delta.cache_delta {
            if let Some(max_ts) = cache_delta.entries.iter().map(|(_, e)| e.timestamp).max() {
                let _ = self.hlc.lock().receive(max_ts);
            }
        }

        let mut changed = false;

        if let Some(ref cache_delta) = delta.cache_delta {
            let mut entries_by_shard: Vec<Vec<(String, lww_map::LwwEntry)>> =
                (0..self.shards.len()).map(|_| Vec::new()).collect();

            cache_delta.entries.iter().for_each(|(key, entry)| {
                entries_by_shard[self.shard_for(key)].push((key.clone(), entry.clone()));
            });

            entries_by_shard.into_iter().enumerate().for_each(|(idx, entries)| {
                if entries.is_empty() {
                    return;
                }
                let mut shard = self.shards[idx].write();
                entries.into_iter().for_each(|(key, entry)| {
                    if shard.cache.merge_entry(key, entry) {
                        changed = true;
                    }
                });
            });
        }

        if !delta.rate_limit_deltas.is_empty() {
            let mut rl_by_shard: Vec<Vec<(String, &g_counter::GCounter)>> =
                (0..self.shards.len()).map(|_| Vec::new()).collect();

            delta.rate_limit_deltas.iter().for_each(|rd| {
                rl_by_shard[self.shard_for(&rd.key)].push((rd.key.clone(), &rd.counter));
            });

            rl_by_shard.into_iter().enumerate().for_each(|(idx, entries)| {
                if entries.is_empty() {
                    return;
                }
                let mut shard = self.shards[idx].write();
                entries.into_iter().for_each(|(key, counter)| {
                    if shard.rate_limits.merge_counter(key, counter) {
                        changed = true;
                    }
                });
            });
        }

        changed
    }

    pub fn run_maintenance(&self) {
        let now = Self::wall_ms_now();
        self.shards.iter().enumerate().for_each(|(idx, shard_lock)| {
            let pending: Vec<String> = self.promotions[idx].lock().drain(..).collect();
            let mut shard = shard_lock.write();
            pending.iter().for_each(|key| shard.cache.touch(key));
            shard.cache.gc_tombstones(now);
            shard.cache.gc_expired(now);
            shard.rate_limits.gc_expired(now);
        });
    }

    pub fn peek_full_state(&self) -> CrdtDelta {
        let mut cache_entries: Vec<(String, lww_map::LwwEntry)> = Vec::new();
        let mut rate_limit_deltas: Vec<g_counter::GCounterDelta> = Vec::new();

        self.shards.iter().for_each(|shard_lock| {
            let shard = shard_lock.read();
            let lww_delta = shard.cache.extract_delta_since(HlcTimestamp::ZERO);
            cache_entries.extend(lww_delta.entries);
            rate_limit_deltas.extend(shard.rate_limits.extract_all_deltas());
        });

        let cache_delta = match cache_entries.is_empty() {
            true => None,
            false => Some(LwwDelta { entries: cache_entries }),
        };

        CrdtDelta {
            version: 1,
            source_node: self.node_id,
            cache_delta,
            rate_limit_deltas,
        }
    }

    pub fn cache_estimated_bytes(&self) -> usize {
        self.shards
            .iter()
            .map(|s| s.read().cache.estimated_bytes())
            .fold(0usize, usize::saturating_add)
    }

    pub fn rate_limit_estimated_bytes(&self) -> usize {
        self.shards
            .iter()
            .map(|s| s.read().rate_limits.estimated_bytes())
            .fold(0usize, usize::saturating_add)
    }

    pub fn total_estimated_bytes(&self) -> usize {
        self.shards
            .iter()
            .map(|s| {
                let shard = s.read();
                shard.cache.estimated_bytes().saturating_add(shard.rate_limits.estimated_bytes())
            })
            .fold(0usize, usize::saturating_add)
    }

    pub fn evict_lru_round_robin(&self, start_shard: usize) -> Option<(usize, usize)> {
        (0..self.shards.len()).find_map(|offset| {
            let idx = (start_shard + offset) & self.shard_mask;
            let has_entries = self.shards[idx].read().cache.len() > 0;
            match has_entries {
                true => {
                    let mut shard = self.shards[idx].write();
                    let before = shard.cache.estimated_bytes();
                    shard.cache.evict_lru().map(|_| {
                        let freed = before.saturating_sub(shard.cache.estimated_bytes());
                        ((idx + 1) & self.shard_mask, freed)
                    })
                }
                false => None,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_cache() {
        let store = ShardedCrdtStore::new(1);
        store.cache_set("key".into(), b"value".to_vec(), 60_000);
        assert_eq!(store.cache_get("key"), Some(b"value".to_vec()));
    }

    #[test]
    fn delta_merge_convergence() {
        let store_a = ShardedCrdtStore::new(1);
        let store_b = ShardedCrdtStore::new(2);

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
        let store_a = ShardedCrdtStore::new(1);
        let store_b = ShardedCrdtStore::new(2);

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
        let store = ShardedCrdtStore::new(1);
        let delta = CrdtDelta {
            version: 255,
            source_node: 99,
            cache_delta: None,
            rate_limit_deltas: vec![],
        };
        assert!(!store.merge_delta(&delta));
    }
}
