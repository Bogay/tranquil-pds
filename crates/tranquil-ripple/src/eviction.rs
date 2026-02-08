use crate::crdt::ShardedCrdtStore;
use crate::metrics;

pub struct MemoryBudget {
    max_bytes: usize,
    next_shard: std::sync::atomic::AtomicUsize,
}

impl MemoryBudget {
    pub fn new(max_bytes: usize) -> Self {
        Self {
            max_bytes,
            next_shard: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub fn enforce(&self, store: &ShardedCrdtStore) {
        store.run_maintenance();

        let cache_bytes = store.cache_estimated_bytes();
        let rl_bytes = store.rate_limit_estimated_bytes();
        metrics::set_cache_bytes(cache_bytes);
        metrics::set_rate_limit_bytes(rl_bytes);

        let max_bytes = self.max_bytes;
        let total_bytes = cache_bytes.saturating_add(rl_bytes);
        let overshoot_pct = match total_bytes > max_bytes && max_bytes > 0 {
            true => total_bytes.saturating_sub(max_bytes).saturating_mul(100) / max_bytes,
            false => 0,
        };

        const BASE_BATCH: usize = 256;
        let batch_size = match overshoot_pct {
            0..=25 => BASE_BATCH,
            26..=100 => BASE_BATCH * 4,
            _ => BASE_BATCH * 8,
        };

        let mut remaining = total_bytes;
        let mut next_shard: usize = self.next_shard.load(std::sync::atomic::Ordering::Relaxed);
        let mut evicted: usize = 0;
        (0..batch_size)
            .try_for_each(|_| match remaining > max_bytes {
                true => match store.evict_lru_round_robin(next_shard) {
                    Some((ns, freed)) => {
                        next_shard = ns;
                        remaining = remaining.saturating_sub(freed);
                        evicted += 1;
                        Ok(())
                    }
                    None => Err(()),
                },
                false => Err(()),
            })
            .ok();
        self.next_shard
            .store(next_shard, std::sync::atomic::Ordering::Relaxed);
        if evicted > 0 {
            metrics::record_evictions(evicted);
            let cache_bytes_after = store.cache_estimated_bytes();
            let rl_bytes_after = store.rate_limit_estimated_bytes();
            metrics::set_cache_bytes(cache_bytes_after);
            metrics::set_rate_limit_bytes(rl_bytes_after);
            tracing::info!(
                evicted_entries = evicted,
                cache_bytes = cache_bytes_after,
                rate_limit_bytes = rl_bytes_after,
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
        let store = ShardedCrdtStore::new(1);
        let budget = MemoryBudget::new(1024 * 1024);
        store.cache_set("k".into(), vec![1, 2, 3], 60_000);
        budget.enforce(&store);
        assert!(store.cache_get("k").is_some());
    }

    #[test]
    fn eviction_over_budget() {
        let store = ShardedCrdtStore::new(1);
        let budget = MemoryBudget::new(100);
        (0..50).for_each(|i| {
            store.cache_set(format!("key-{i}"), vec![0u8; 64], 60_000);
        });
        budget.enforce(&store);
        assert!(store.total_estimated_bytes() <= 100);
    }
}
