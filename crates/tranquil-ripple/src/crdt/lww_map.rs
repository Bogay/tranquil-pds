use super::hlc::HlcTimestamp;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LwwEntry {
    pub value: Option<Vec<u8>>,
    pub timestamp: HlcTimestamp,
    pub ttl_ms: u64,
    pub created_at_wall_ms: u64,
}

impl LwwEntry {
    fn is_expired(&self, now_wall_ms: u64) -> bool {
        self.ttl_ms > 0 && now_wall_ms.saturating_sub(self.created_at_wall_ms) >= self.ttl_ms
    }

    fn is_tombstone(&self) -> bool {
        self.value.is_none()
    }

    fn tombstone_expired(&self, now_wall_ms: u64) -> bool {
        self.is_tombstone()
            && self.ttl_ms > 0
            && now_wall_ms.saturating_sub(self.created_at_wall_ms) >= self.ttl_ms.saturating_mul(2)
    }

    fn entry_byte_size(&self, key: &str) -> usize {
        const HASHMAP_ENTRY_OVERHEAD: usize = 64;
        const BTREE_NODE_OVERHEAD: usize = 64;
        const STRING_HEADER: usize = 24;
        const COUNTER_SIZE: usize = 8;

        let key_len = key.len();
        let value_len = self.value.as_ref().map_or(0, Vec::len);

        let main_entry = key_len
            .saturating_add(value_len)
            .saturating_add(std::mem::size_of::<Self>())
            .saturating_add(HASHMAP_ENTRY_OVERHEAD);

        match self.is_tombstone() {
            true => main_entry,
            false => {
                let lru_btree = COUNTER_SIZE
                    .saturating_add(STRING_HEADER)
                    .saturating_add(key_len)
                    .saturating_add(BTREE_NODE_OVERHEAD);

                let lru_hashmap = STRING_HEADER
                    .saturating_add(key_len)
                    .saturating_add(COUNTER_SIZE)
                    .saturating_add(HASHMAP_ENTRY_OVERHEAD);

                main_entry
                    .saturating_add(lru_btree)
                    .saturating_add(lru_hashmap)
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LwwDelta {
    pub entries: Vec<(String, LwwEntry)>,
}

struct LruTracker {
    counter: u64,
    counter_to_key: BTreeMap<u64, String>,
    key_to_counter: HashMap<String, u64>,
}

impl LruTracker {
    fn new() -> Self {
        Self {
            counter: 0,
            counter_to_key: BTreeMap::new(),
            key_to_counter: HashMap::new(),
        }
    }

    fn promote(&mut self, key: &str) {
        if let Some(old_counter) = self.key_to_counter.remove(key) {
            self.counter_to_key.remove(&old_counter);
        }
        if self.counter >= u64::MAX - 1 {
            self.compact();
        }
        self.counter = self.counter.saturating_add(1);
        self.counter_to_key.insert(self.counter, key.to_string());
        self.key_to_counter.insert(key.to_string(), self.counter);
    }

    fn compact(&mut self) {
        let keys: Vec<String> = self.counter_to_key.values().cloned().collect();
        self.counter_to_key.clear();
        self.key_to_counter.clear();
        keys.into_iter().enumerate().for_each(|(i, key)| {
            let new_counter = (i as u64).saturating_add(1);
            self.counter_to_key.insert(new_counter, key.clone());
            self.key_to_counter.insert(key, new_counter);
        });
        self.counter = self.counter_to_key.len() as u64;
    }

    fn remove(&mut self, key: &str) {
        if let Some(counter) = self.key_to_counter.remove(key) {
            self.counter_to_key.remove(&counter);
        }
    }

    fn pop_least_recent(&mut self) -> Option<String> {
        let (&counter, _) = self.counter_to_key.iter().next()?;
        let key = self.counter_to_key.remove(&counter)?;
        self.key_to_counter.remove(&key);
        Some(key)
    }
}

pub struct LwwMap {
    entries: HashMap<String, LwwEntry>,
    lru: LruTracker,
    estimated_bytes: usize,
}

impl Default for LwwMap {
    fn default() -> Self {
        Self::new()
    }
}

impl LwwMap {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            lru: LruTracker::new(),
            estimated_bytes: 0,
        }
    }

    pub fn get(&self, key: &str, now_wall_ms: u64) -> Option<Vec<u8>> {
        let entry = self.entries.get(key)?;
        if entry.is_expired(now_wall_ms) || entry.is_tombstone() {
            return None;
        }
        entry.value.clone()
    }

    pub fn set(
        &mut self,
        key: String,
        value: Vec<u8>,
        timestamp: HlcTimestamp,
        ttl_ms: u64,
        wall_ms_now: u64,
    ) {
        let entry = LwwEntry {
            created_at_wall_ms: wall_ms_now,
            value: Some(value),
            timestamp,
            ttl_ms,
        };
        self.remove_estimated_bytes(&key);
        self.estimated_bytes += entry.entry_byte_size(&key);
        self.entries.insert(key.clone(), entry);
        self.lru.promote(&key);
    }

    pub fn delete(&mut self, key: &str, timestamp: HlcTimestamp, wall_ms_now: u64) {
        let ttl_ms = match self.entries.get(key) {
            Some(existing) if existing.timestamp >= timestamp => return,
            Some(existing) => existing.ttl_ms.max(60_000),
            None => 60_000,
        };
        let entry = LwwEntry {
            value: None,
            timestamp,
            ttl_ms,
            created_at_wall_ms: wall_ms_now,
        };
        self.remove_estimated_bytes(key);
        self.estimated_bytes += entry.entry_byte_size(key);
        self.entries.insert(key.to_string(), entry);
        self.lru.remove(key);
    }

    pub fn merge_entry(&mut self, key: String, remote: LwwEntry) -> bool {
        match self.entries.get(&key) {
            Some(existing) if existing.timestamp >= remote.timestamp => false,
            _ => {
                let is_tombstone = remote.is_tombstone();
                self.remove_estimated_bytes(&key);
                self.estimated_bytes += remote.entry_byte_size(&key);
                self.entries.insert(key.clone(), remote);
                match is_tombstone {
                    true => self.lru.remove(&key),
                    false => self.lru.promote(&key),
                }
                true
            }
        }
    }

    pub fn extract_delta_since(&self, watermark: HlcTimestamp) -> LwwDelta {
        let entries = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.timestamp > watermark)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        LwwDelta { entries }
    }

    pub fn gc_tombstones(&mut self, now_wall_ms: u64) {
        let expired_keys: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.tombstone_expired(now_wall_ms))
            .map(|(k, _)| k.clone())
            .collect();
        expired_keys.iter().for_each(|key| {
            self.remove_estimated_bytes(key);
            self.entries.remove(key);
            self.lru.remove(key);
        });
    }

    pub fn gc_expired(&mut self, now_wall_ms: u64) {
        let expired_keys: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.is_expired(now_wall_ms) && !entry.is_tombstone())
            .map(|(k, _)| k.clone())
            .collect();
        expired_keys.iter().for_each(|key| {
            self.remove_estimated_bytes(key);
            self.entries.remove(key);
            self.lru.remove(key);
        });
    }

    pub fn evict_lru(&mut self) -> Option<String> {
        let key = self.lru.pop_least_recent()?;
        self.remove_estimated_bytes(&key);
        self.entries.remove(&key);
        Some(key)
    }

    pub fn touch(&mut self, key: &str) {
        if self.entries.contains_key(key) {
            self.lru.promote(key);
        }
    }

    pub fn estimated_bytes(&self) -> usize {
        self.estimated_bytes
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn remove_estimated_bytes(&mut self, key: &str) {
        if let Some(existing) = self.entries.get(key) {
            let size = existing.entry_byte_size(key);
            if size > self.estimated_bytes {
                tracing::warn!(
                    entry_size = size,
                    estimated_bytes = self.estimated_bytes,
                    key = key,
                    "estimated_bytes underflow detected, resetting to 0"
                );
            }
            self.estimated_bytes = self.estimated_bytes.saturating_sub(size);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(wall: u64, counter: u32, node: u64) -> HlcTimestamp {
        HlcTimestamp {
            wall_ms: wall,
            counter,
            node_id: node,
        }
    }

    #[test]
    fn set_and_get() {
        let mut map = LwwMap::new();
        map.set("k1".into(), b"hello".to_vec(), ts(100, 0, 1), 60_000, 100);
        assert_eq!(map.get("k1", 100), Some(b"hello".to_vec()));
    }

    #[test]
    fn ttl_expiry() {
        let mut map = LwwMap::new();
        map.set("k1".into(), b"hello".to_vec(), ts(100, 0, 1), 1000, 100);
        assert_eq!(map.get("k1", 100), Some(b"hello".to_vec()));
        assert_eq!(map.get("k1", 1200), None);
    }

    #[test]
    fn merge_higher_timestamp_wins() {
        let mut map = LwwMap::new();
        map.set("k1".into(), b"old".to_vec(), ts(100, 0, 1), 60_000, 100);
        let merged = map.merge_entry(
            "k1".into(),
            LwwEntry {
                value: Some(b"new".to_vec()),
                timestamp: ts(200, 0, 2),
                ttl_ms: 60_000,
                created_at_wall_ms: 200,
            },
        );
        assert!(merged);
        assert_eq!(map.get("k1", 200), Some(b"new".to_vec()));
    }

    #[test]
    fn merge_lower_timestamp_rejected() {
        let mut map = LwwMap::new();
        map.set("k1".into(), b"current".to_vec(), ts(200, 0, 1), 60_000, 200);
        let merged = map.merge_entry(
            "k1".into(),
            LwwEntry {
                value: Some(b"stale".to_vec()),
                timestamp: ts(100, 0, 2),
                ttl_ms: 60_000,
                created_at_wall_ms: 100,
            },
        );
        assert!(!merged);
        assert_eq!(map.get("k1", 200), Some(b"current".to_vec()));
    }

    #[test]
    fn merge_commutativity() {
        let e1 = LwwEntry {
            value: Some(b"a".to_vec()),
            timestamp: ts(100, 0, 1),
            ttl_ms: 60_000,
            created_at_wall_ms: 100,
        };
        let e2 = LwwEntry {
            value: Some(b"b".to_vec()),
            timestamp: ts(200, 0, 2),
            ttl_ms: 60_000,
            created_at_wall_ms: 200,
        };

        let mut map_ab = LwwMap::new();
        map_ab.merge_entry("k".into(), e1.clone());
        map_ab.merge_entry("k".into(), e2.clone());

        let mut map_ba = LwwMap::new();
        map_ba.merge_entry("k".into(), e2);
        map_ba.merge_entry("k".into(), e1);

        assert_eq!(map_ab.get("k", 200), map_ba.get("k", 200));
    }

    #[test]
    fn merge_idempotency() {
        let e = LwwEntry {
            value: Some(b"a".to_vec()),
            timestamp: ts(100, 0, 1),
            ttl_ms: 60_000,
            created_at_wall_ms: 100,
        };
        let mut map = LwwMap::new();
        assert!(map.merge_entry("k".into(), e.clone()));
        assert!(!map.merge_entry("k".into(), e));
    }

    #[test]
    fn delete_creates_tombstone() {
        let mut map = LwwMap::new();
        map.set("k1".into(), b"val".to_vec(), ts(100, 0, 1), 60_000, 100);
        map.delete("k1", ts(200, 0, 1), 200);
        assert_eq!(map.get("k1", 200), None);
    }

    #[test]
    fn tombstone_gc() {
        let mut map = LwwMap::new();
        map.set("k1".into(), b"val".to_vec(), ts(100, 0, 1), 60_000, 100);
        map.delete("k1", ts(100, 1, 1), 100);
        assert_eq!(map.len(), 1);
        map.gc_tombstones(100 + 120_001);
        assert_eq!(map.len(), 0);
    }

    #[test]
    fn delta_extraction() {
        let mut map = LwwMap::new();
        map.set("k1".into(), b"a".to_vec(), ts(100, 0, 1), 60_000, 100);
        map.set("k2".into(), b"b".to_vec(), ts(200, 0, 1), 60_000, 200);
        let delta = map.extract_delta_since(ts(150, 0, 0));
        assert_eq!(delta.entries.len(), 1);
        assert_eq!(delta.entries[0].0, "k2");
    }

    #[test]
    fn lru_eviction_by_write_order() {
        let mut map = LwwMap::new();
        map.set("k1".into(), b"a".to_vec(), ts(100, 0, 1), 60_000, 100);
        map.set("k2".into(), b"b".to_vec(), ts(101, 0, 1), 60_000, 101);
        map.set("k3".into(), b"c".to_vec(), ts(102, 0, 1), 60_000, 102);
        let evicted = map.evict_lru();
        assert_eq!(evicted.as_deref(), Some("k1"));
    }

    #[test]
    fn merged_entries_are_evictable() {
        let mut map = LwwMap::new();
        map.merge_entry(
            "remote_key".into(),
            LwwEntry {
                value: Some(b"remote_val".to_vec()),
                timestamp: ts(100, 0, 2),
                ttl_ms: 60_000,
                created_at_wall_ms: 100,
            },
        );
        let evicted = map.evict_lru();
        assert_eq!(evicted.as_deref(), Some("remote_key"));
        assert_eq!(map.len(), 0);
    }
}
