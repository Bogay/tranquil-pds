use crate::crdt::CrdtStore;

pub struct MemoryBudget {
    max_bytes: usize,
}

impl MemoryBudget {
    pub fn new(max_bytes: usize) -> Self {
        Self { max_bytes }
    }

    pub fn enforce(&self, store: &mut CrdtStore) {
        store.run_maintenance();

        let max_bytes = self.max_bytes;
        let total_bytes = store.cache_estimated_bytes().saturating_add(store.rate_limit_estimated_bytes());
        let overshoot_ratio = match total_bytes > max_bytes && max_bytes > 0 {
            true => total_bytes / max_bytes,
            false => 0,
        };

        const BASE_BATCH: usize = 256;
        let batch_size = match overshoot_ratio {
            0..=1 => BASE_BATCH,
            2..=4 => BASE_BATCH * 4,
            _ => BASE_BATCH * 8,
        };

        let evicted = std::iter::from_fn(|| {
            let current = store.cache_estimated_bytes().saturating_add(store.rate_limit_estimated_bytes());
            match current > max_bytes {
                true => store.evict_lru(),
                false => None,
            }
        })
        .take(batch_size)
        .count();
        if evicted > 0 {
            tracing::info!(
                evicted_entries = evicted,
                cache_bytes = store.cache_estimated_bytes(),
                rate_limit_bytes = store.rate_limit_estimated_bytes(),
                max_bytes = self.max_bytes,
                "memory budget eviction"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eviction_under_budget() {
        let mut store = CrdtStore::new(1);
        let budget = MemoryBudget::new(1024 * 1024);
        store.cache_set("k".into(), vec![1, 2, 3], 60_000);
        budget.enforce(&mut store);
        assert!(store.cache_get("k").is_some());
    }

    #[test]
    fn eviction_over_budget() {
        let mut store = CrdtStore::new(1);
        let budget = MemoryBudget::new(100);
        (0..50).for_each(|i| {
            store.cache_set(
                format!("key-{i}"),
                vec![0u8; 64],
                60_000,
            );
        });
        budget.enforce(&mut store);
        let total = store.cache_estimated_bytes().saturating_add(store.rate_limit_estimated_bytes());
        assert!(total <= 100);
    }
}
