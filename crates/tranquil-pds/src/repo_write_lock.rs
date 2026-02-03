use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, OwnedMutexGuard, RwLock};
use uuid::Uuid;

const SWEEP_INTERVAL: Duration = Duration::from_secs(300);

pub struct RepoWriteLocks {
    locks: Arc<RwLock<HashMap<Uuid, Arc<Mutex<()>>>>>,
}

impl Default for RepoWriteLocks {
    fn default() -> Self {
        Self::new()
    }
}

impl RepoWriteLocks {
    pub fn new() -> Self {
        let locks = Arc::new(RwLock::new(HashMap::new()));
        let sweep_locks = Arc::clone(&locks);
        tokio::spawn(async move {
            sweep_loop(sweep_locks).await;
        });
        Self { locks }
    }

    pub async fn lock(&self, user_id: Uuid) -> OwnedMutexGuard<()> {
        let mutex = {
            let read_guard = self.locks.read().await;
            read_guard.get(&user_id).cloned()
        };

        match mutex {
            Some(m) => m.lock_owned().await,
            None => {
                let mut write_guard = self.locks.write().await;
                let mutex = write_guard
                    .entry(user_id)
                    .or_insert_with(|| Arc::new(Mutex::new(())))
                    .clone();
                drop(write_guard);
                mutex.lock_owned().await
            }
        }
    }
}

async fn sweep_loop(locks: Arc<RwLock<HashMap<Uuid, Arc<Mutex<()>>>>>) {
    tokio::time::sleep(SWEEP_INTERVAL).await;
    let mut write_guard = locks.write().await;
    let before = write_guard.len();
    write_guard.retain(|_, mutex| Arc::strong_count(mutex) > 1);
    let evicted = before - write_guard.len();
    if evicted > 0 {
        tracing::debug!(
            evicted,
            remaining = write_guard.len(),
            "repo write lock sweep"
        );
    }
    drop(write_guard);
    Box::pin(sweep_loop(locks)).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    #[tokio::test]
    async fn test_locks_serialize_same_user() {
        let locks = Arc::new(RepoWriteLocks::new());
        let user_id = Uuid::new_v4();
        let counter = Arc::new(AtomicU32::new(0));
        let max_concurrent = Arc::new(AtomicU32::new(0));

        let handles: Vec<_> = (0..10)
            .map(|_| {
                let locks = locks.clone();
                let counter = counter.clone();
                let max_concurrent = max_concurrent.clone();

                tokio::spawn(async move {
                    let _guard = locks.lock(user_id).await;
                    let current = counter.fetch_add(1, Ordering::SeqCst) + 1;
                    max_concurrent.fetch_max(current, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(1)).await;
                    counter.fetch_sub(1, Ordering::SeqCst);
                })
            })
            .collect();

        futures::future::join_all(handles).await;

        assert_eq!(
            max_concurrent.load(Ordering::SeqCst),
            1,
            "Only one task should hold the lock at a time for same user"
        );
    }

    #[tokio::test]
    async fn test_different_users_can_run_concurrently() {
        let locks = Arc::new(RepoWriteLocks::new());
        let user1 = Uuid::new_v4();
        let user2 = Uuid::new_v4();
        let concurrent_count = Arc::new(AtomicU32::new(0));
        let max_concurrent = Arc::new(AtomicU32::new(0));

        let locks1 = locks.clone();
        let count1 = concurrent_count.clone();
        let max1 = max_concurrent.clone();
        let handle1 = tokio::spawn(async move {
            let _guard = locks1.lock(user1).await;
            let current = count1.fetch_add(1, Ordering::SeqCst) + 1;
            max1.fetch_max(current, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(50)).await;
            count1.fetch_sub(1, Ordering::SeqCst);
        });

        tokio::time::sleep(Duration::from_millis(10)).await;

        let locks2 = locks.clone();
        let count2 = concurrent_count.clone();
        let max2 = max_concurrent.clone();
        let handle2 = tokio::spawn(async move {
            let _guard = locks2.lock(user2).await;
            let current = count2.fetch_add(1, Ordering::SeqCst) + 1;
            max2.fetch_max(current, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(50)).await;
            count2.fetch_sub(1, Ordering::SeqCst);
        });

        handle1.await.unwrap();
        handle2.await.unwrap();

        assert_eq!(
            max_concurrent.load(Ordering::SeqCst),
            2,
            "Different users should be able to run concurrently"
        );
    }

    #[tokio::test]
    async fn test_sweep_evicts_idle_entries() {
        let locks = Arc::new(RwLock::new(HashMap::new()));
        let user_id = Uuid::new_v4();

        {
            let mut write_guard = locks.write().await;
            write_guard.insert(user_id, Arc::new(Mutex::new(())));
        }

        assert_eq!(locks.read().await.len(), 1);

        let mut write_guard = locks.write().await;
        write_guard.retain(|_, mutex| Arc::strong_count(mutex) > 1);
        assert_eq!(write_guard.len(), 0, "Idle entry should be evicted");
    }

    #[tokio::test]
    async fn test_sweep_preserves_active_entries() {
        let locks = Arc::new(RwLock::new(HashMap::new()));
        let user_id = Uuid::new_v4();
        let active_mutex = Arc::new(Mutex::new(()));
        let _held_ref = active_mutex.clone();

        {
            let mut write_guard = locks.write().await;
            write_guard.insert(user_id, active_mutex);
        }

        let mut write_guard = locks.write().await;
        write_guard.retain(|_, mutex| Arc::strong_count(mutex) > 1);
        assert_eq!(write_guard.len(), 1, "Active entry should be preserved");
    }
}
