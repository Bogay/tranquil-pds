use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GCounter {
    pub increments: HashMap<u64, u64>,
    pub window_start_ms: u64,
    pub window_duration_ms: u64,
}

impl GCounter {
    pub fn new(window_start_ms: u64, window_duration_ms: u64) -> Self {
        Self {
            increments: HashMap::new(),
            window_start_ms,
            window_duration_ms,
        }
    }

    pub fn total(&self) -> u64 {
        self.increments
            .values()
            .copied()
            .fold(0u64, u64::saturating_add)
    }

    pub fn increment(&mut self, node_id: u64) {
        let slot = self.increments.entry(node_id).or_insert(0);
        *slot = slot.saturating_add(1);
    }

    pub fn merge(&mut self, other: &GCounter) -> bool {
        let mut changed = false;
        other.increments.iter().for_each(|(&node, &count)| {
            let slot = self.increments.entry(node).or_insert(0);
            let new_val = (*slot).max(count);
            if new_val != *slot {
                *slot = new_val;
                changed = true;
            }
        });
        changed
    }

    pub fn is_expired(&self, now_wall_ms: u64) -> bool {
        now_wall_ms.saturating_sub(self.window_start_ms) >= self.window_duration_ms
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GCounterDelta {
    pub key: String,
    pub counter: GCounter,
}

pub struct RateLimitStore {
    counters: HashMap<String, GCounter>,
    node_id: u64,
    dirty: HashSet<String>,
}

impl RateLimitStore {
    pub fn new(node_id: u64) -> Self {
        Self {
            counters: HashMap::new(),
            node_id,
            dirty: HashSet::new(),
        }
    }

    fn aligned_window_start(now_wall_ms: u64, window_ms: u64) -> u64 {
        (now_wall_ms / window_ms.max(1)) * window_ms.max(1)
    }

    pub fn check_and_increment(
        &mut self,
        key: &str,
        limit: u32,
        window_ms: u64,
        now_wall_ms: u64,
    ) -> bool {
        if window_ms == 0 {
            return false;
        }
        let window_start = Self::aligned_window_start(now_wall_ms, window_ms);

        let counter = self
            .counters
            .entry(key.to_string())
            .and_modify(|c| {
                if c.window_start_ms != window_start {
                    *c = GCounter::new(window_start, window_ms);
                }
            })
            .or_insert_with(|| GCounter::new(window_start, window_ms));

        let current = counter.total();
        if current >= limit as u64 {
            return false;
        }
        counter.increment(self.node_id);
        self.dirty.insert(key.to_string());
        true
    }

    pub fn merge_counter(&mut self, key: String, remote: &GCounter) -> bool {
        if remote.window_duration_ms == 0 {
            return false;
        }
        match self.counters.get_mut(&key) {
            Some(local) if local.window_start_ms == remote.window_start_ms => {
                if local.window_duration_ms != remote.window_duration_ms {
                    tracing::warn!(
                        key = %key,
                        local_window = local.window_duration_ms,
                        remote_window = remote.window_duration_ms,
                        "window_duration_ms mismatch, rejecting merge"
                    );
                    return false;
                }
                let changed = local.merge(remote);
                if changed {
                    self.dirty.insert(key);
                }
                changed
            }
            Some(local) if remote.window_start_ms > local.window_start_ms => {
                self.counters.insert(key.clone(), remote.clone());
                self.dirty.insert(key);
                true
            }
            None => {
                self.counters.insert(key.clone(), remote.clone());
                self.dirty.insert(key);
                true
            }
            _ => false,
        }
    }

    pub fn extract_dirty_deltas(&self) -> Vec<GCounterDelta> {
        self.dirty
            .iter()
            .filter_map(|key| {
                self.counters.get(key).map(|counter| GCounterDelta {
                    key: key.clone(),
                    counter: counter.clone(),
                })
            })
            .collect()
    }

    pub fn clear_dirty(&mut self) {
        self.dirty.clear();
    }

    pub fn clear_dirty_keys(&mut self, keys: impl Iterator<Item = impl AsRef<str>>) {
        keys.for_each(|k| {
            self.dirty.remove(k.as_ref());
        });
    }

    pub fn peek_count(&self, key: &str, window_ms: u64, now_wall_ms: u64) -> u64 {
        if window_ms == 0 {
            return 0;
        }
        match self.counters.get(key) {
            Some(counter)
                if counter.window_start_ms
                    == Self::aligned_window_start(now_wall_ms, window_ms) =>
            {
                counter.total()
            }
            _ => 0,
        }
    }

    pub fn peek_dirty_counter(&self, key: &str) -> Option<&GCounter> {
        match self.dirty.contains(key) {
            true => self.counters.get(key),
            false => None,
        }
    }

    pub fn clear_single_dirty(&mut self, key: &str) {
        self.dirty.remove(key);
    }

    pub fn estimated_bytes(&self) -> usize {
        const PER_COUNTER_OVERHEAD: usize = 128;
        self.counters
            .iter()
            .map(|(key, counter)| {
                key.len()
                    + std::mem::size_of::<GCounter>()
                    + counter.increments.len() * (std::mem::size_of::<u64>() * 2)
                    + PER_COUNTER_OVERHEAD
            })
            .fold(0usize, usize::saturating_add)
    }

    pub fn extract_all_deltas(&self) -> Vec<GCounterDelta> {
        self.counters
            .iter()
            .map(|(key, counter)| GCounterDelta {
                key: key.clone(),
                counter: counter.clone(),
            })
            .collect()
    }

    pub fn gc_expired(&mut self, now_wall_ms: u64) {
        let expired: Vec<String> = self
            .counters
            .iter()
            .filter(|(_, c)| c.is_expired(now_wall_ms))
            .map(|(k, _)| k.clone())
            .collect();
        expired.iter().for_each(|key| {
            self.counters.remove(key);
            self.dirty.remove(key);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn increment_and_total() {
        let mut counter = GCounter::new(0, 60_000);
        counter.increment(1);
        counter.increment(1);
        counter.increment(2);
        assert_eq!(counter.total(), 3);
    }

    #[test]
    fn merge_per_node_max() {
        let mut a = GCounter::new(0, 60_000);
        a.increment(1);
        a.increment(1);
        a.increment(2);

        let mut b = GCounter::new(0, 60_000);
        b.increment(1);
        b.increment(2);
        b.increment(2);
        b.increment(2);

        a.merge(&b);
        assert_eq!(*a.increments.get(&1).unwrap(), 2);
        assert_eq!(*a.increments.get(&2).unwrap(), 3);
        assert_eq!(a.total(), 5);
    }

    #[test]
    fn merge_commutativity() {
        let mut a = GCounter::new(0, 60_000);
        a.increments.insert(1, 5);
        a.increments.insert(2, 3);

        let mut b = GCounter::new(0, 60_000);
        b.increments.insert(1, 3);
        b.increments.insert(2, 7);

        let mut ab = a.clone();
        ab.merge(&b);
        let mut ba = b.clone();
        ba.merge(&a);
        assert_eq!(ab.total(), ba.total());
    }

    #[test]
    fn window_rollover() {
        let mut store = RateLimitStore::new(1);
        assert!(store.check_and_increment("k", 2, 1000, 500));
        assert!(store.check_and_increment("k", 2, 1000, 600));
        assert!(!store.check_and_increment("k", 2, 1000, 700));
        assert!(store.check_and_increment("k", 2, 1000, 1500));
    }

    #[test]
    fn rate_limit_enforcement() {
        let mut store = RateLimitStore::new(1);
        assert!(store.check_and_increment("k", 3, 60_000, 100));
        assert!(store.check_and_increment("k", 3, 60_000, 200));
        assert!(store.check_and_increment("k", 3, 60_000, 300));
        assert!(!store.check_and_increment("k", 3, 60_000, 400));
    }

    #[test]
    fn gc_expired_windows() {
        let mut store = RateLimitStore::new(1);
        store.check_and_increment("k", 10, 1000, 0);
        assert_eq!(store.counters.len(), 1);
        assert_eq!(store.dirty.len(), 1);
        store.gc_expired(2000);
        assert_eq!(store.counters.len(), 0);
        assert_eq!(store.dirty.len(), 0);
    }

    #[test]
    fn dirty_tracking() {
        let mut store = RateLimitStore::new(1);
        assert!(store.extract_dirty_deltas().is_empty());

        store.check_and_increment("k1", 10, 60_000, 100);
        store.check_and_increment("k2", 10, 60_000, 100);
        assert_eq!(store.extract_dirty_deltas().len(), 2);

        store.clear_dirty();
        assert!(store.extract_dirty_deltas().is_empty());

        store.check_and_increment("k1", 10, 60_000, 200);
        assert_eq!(store.extract_dirty_deltas().len(), 1);
    }
}
