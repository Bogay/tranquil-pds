use crate::resolve::{ResolveError, resolve_lexicon};
use crate::schema::LexiconDoc;
use parking_lot::RwLock;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Notify;
use tranquil_types::Nsid;

const NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const POSITIVE_CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const REFRESH_FAILURE_BACKOFF: Duration = Duration::from_secs(60);
const MAX_DYNAMIC_SCHEMAS: usize = 1024;

struct NegativeEntry {
    expires_at: Instant,
}

struct PositiveEntry {
    doc: Arc<LexiconDoc>,
    expires_at: Instant,
}

pub(crate) enum CacheEntry {
    Fresh(Arc<LexiconDoc>),
    Stale(Arc<LexiconDoc>),
}

impl CacheEntry {
    #[cfg(test)]
    fn is_fresh(&self) -> bool {
        matches!(self, Self::Fresh(_))
    }
}

struct SchemaStore {
    schemas: HashMap<Nsid, PositiveEntry>,
    insertion_order: VecDeque<Nsid>,
}

pub struct DynamicRegistry {
    store: RwLock<SchemaStore>,
    negative_cache: RwLock<HashMap<Nsid, NegativeEntry>>,
    in_flight: RwLock<HashMap<Nsid, Arc<Notify>>>,
    network_disabled: AtomicBool,
}

struct InFlightGuard<'a> {
    registry: &'a DynamicRegistry,
    nsid: Nsid,
}

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        let notify = self.registry.in_flight.write().remove(&self.nsid);
        if let Some(n) = notify {
            n.notify_waiters();
        }
    }
}

impl DynamicRegistry {
    pub fn new() -> Self {
        Self {
            store: RwLock::new(SchemaStore {
                schemas: HashMap::new(),
                insertion_order: VecDeque::new(),
            }),
            negative_cache: RwLock::new(HashMap::new()),
            in_flight: RwLock::new(HashMap::new()),
            network_disabled: AtomicBool::new(false),
        }
    }

    pub fn from_env() -> Self {
        let registry = Self::new();
        let disabled =
            std::env::var("TRANQUIL_LEXICON_OFFLINE").is_ok_and(|v| v == "1" || v == "true");
        registry.set_network_disabled(disabled);
        registry
    }

    pub fn set_network_disabled(&self, disabled: bool) {
        self.network_disabled.store(disabled, Ordering::Relaxed);
    }

    pub fn get_cached(&self, nsid: &Nsid) -> Option<Arc<LexiconDoc>> {
        self.store
            .read()
            .schemas
            .get(nsid)
            .map(|e| Arc::clone(&e.doc))
    }

    pub(crate) fn get_entry(&self, nsid: &Nsid) -> Option<CacheEntry> {
        let now = Instant::now();
        self.store.read().schemas.get(nsid).map(|e| {
            if e.expires_at > now {
                CacheEntry::Fresh(Arc::clone(&e.doc))
            } else {
                CacheEntry::Stale(Arc::clone(&e.doc))
            }
        })
    }

    pub fn is_negative_cached(&self, nsid: &Nsid) -> bool {
        let cache = self.negative_cache.read();
        cache
            .get(nsid)
            .is_some_and(|entry| entry.expires_at > Instant::now())
    }

    fn insert_negative(&self, nsid: &Nsid) {
        let mut cache = self.negative_cache.write();
        if cache.len() >= MAX_DYNAMIC_SCHEMAS {
            let now = Instant::now();
            cache.retain(|_, entry| entry.expires_at > now);
        }
        cache.insert(
            nsid.clone(),
            NegativeEntry {
                expires_at: Instant::now() + NEGATIVE_CACHE_TTL,
            },
        );
    }

    pub(crate) fn insert_schema(&self, doc: LexiconDoc) -> Arc<LexiconDoc> {
        let arc = Arc::new(doc);
        let nsid = arc.id.clone();

        let mut store = self.store.write();

        if store.schemas.len() >= MAX_DYNAMIC_SCHEMAS {
            tracing::warn!(
                count = store.schemas.len(),
                "dynamic schema registry at capacity, evicting oldest entries"
            );
            let evict_count = store.schemas.len() / 4;
            (0..evict_count).for_each(|_| {
                if let Some(key) = store.insertion_order.pop_front() {
                    store.schemas.remove(&key);
                }
            });
        }

        let entry = PositiveEntry {
            doc: Arc::clone(&arc),
            expires_at: Instant::now() + POSITIVE_CACHE_TTL,
        };
        if store.schemas.insert(nsid.clone(), entry).is_some() {
            store.insertion_order.retain(|k| k != &nsid);
        }
        store.insertion_order.push_back(nsid.clone());
        drop(store);

        self.negative_cache.write().remove(&arc.id);

        arc
    }

    fn bump_expiry(&self, nsid: &Nsid, duration: Duration) {
        let mut store = self.store.write();
        if let Some(entry) = store.schemas.get_mut(nsid) {
            entry.expires_at = Instant::now() + duration;
        }
    }

    pub async fn resolve_and_cache(&self, nsid: &Nsid) -> Result<Arc<LexiconDoc>, ResolveError> {
        self.resolve_and_cache_with(nsid, |n| async move { resolve_lexicon(&n).await })
            .await
    }

    async fn resolve_and_cache_with<F, Fut>(
        &self,
        nsid: &Nsid,
        resolver: F,
    ) -> Result<Arc<LexiconDoc>, ResolveError>
    where
        F: FnOnce(Nsid) -> Fut,
        Fut: std::future::Future<Output = Result<LexiconDoc, ResolveError>>,
    {
        match self.get_entry(nsid) {
            Some(CacheEntry::Fresh(doc)) => Ok(doc),
            Some(CacheEntry::Stale(stale)) => self.refresh_stale(nsid, stale, resolver).await,
            None => self.resolve_fresh(nsid, resolver).await,
        }
    }

    async fn refresh_stale<F, Fut>(
        &self,
        nsid: &Nsid,
        stale: Arc<LexiconDoc>,
        resolver: F,
    ) -> Result<Arc<LexiconDoc>, ResolveError>
    where
        F: FnOnce(Nsid) -> Fut,
        Fut: std::future::Future<Output = Result<LexiconDoc, ResolveError>>,
    {
        if self.network_disabled.load(Ordering::Relaxed) {
            return Ok(stale);
        }

        match self.acquire_leadership(nsid) {
            Some(_guard) => match resolver(nsid.clone()).await {
                Ok(doc) => Ok(self.insert_schema(doc)),
                Err(e) => {
                    self.bump_expiry(nsid, REFRESH_FAILURE_BACKOFF);
                    tracing::warn!(
                        nsid = %nsid,
                        error = %e,
                        "lexicon refresh failed, serving stale cached entry"
                    );
                    Ok(stale)
                }
            },
            None => {
                self.wait_for_leader(nsid).await;
                Ok(self.get_cached(nsid).unwrap_or(stale))
            }
        }
    }

    async fn resolve_fresh<F, Fut>(
        &self,
        nsid: &Nsid,
        resolver: F,
    ) -> Result<Arc<LexiconDoc>, ResolveError>
    where
        F: FnOnce(Nsid) -> Fut,
        Fut: std::future::Future<Output = Result<LexiconDoc, ResolveError>>,
    {
        if self.network_disabled.load(Ordering::Relaxed) {
            return Err(ResolveError::NetworkDisabled);
        }
        if self.is_negative_cached(nsid) {
            return Err(ResolveError::NegativelyCached {
                nsid: nsid.clone(),
                ttl_secs: NEGATIVE_CACHE_TTL.as_secs(),
            });
        }

        match self.acquire_leadership(nsid) {
            Some(_guard) => match resolver(nsid.clone()).await {
                Ok(doc) => Ok(self.insert_schema(doc)),
                Err(e) => {
                    self.insert_negative(nsid);
                    tracing::debug!(nsid = %nsid, error = %e, "caching negative resolution result");
                    Err(e)
                }
            },
            None => {
                self.wait_for_leader(nsid).await;
                match self.get_cached(nsid) {
                    Some(doc) => Ok(doc),
                    None if self.is_negative_cached(nsid) => Err(ResolveError::NegativelyCached {
                        nsid: nsid.clone(),
                        ttl_secs: NEGATIVE_CACHE_TTL.as_secs(),
                    }),
                    None => Err(ResolveError::LeaderAborted { nsid: nsid.clone() }),
                }
            }
        }
    }

    fn acquire_leadership(&self, nsid: &Nsid) -> Option<InFlightGuard<'_>> {
        let mut map = self.in_flight.write();
        if map.contains_key(nsid) {
            None
        } else {
            map.insert(nsid.clone(), Arc::new(Notify::new()));
            Some(InFlightGuard {
                registry: self,
                nsid: nsid.clone(),
            })
        }
    }

    async fn wait_for_leader(&self, nsid: &Nsid) {
        let notify = {
            let map = self.in_flight.read();
            match map.get(nsid) {
                Some(n) => Arc::clone(n),
                None => return,
            }
        };
        let notified = notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        let still_active = self.in_flight.read().contains_key(nsid);
        if !still_active {
            return;
        }
        notified.as_mut().await;
    }

    pub fn schema_count(&self) -> usize {
        self.store.read().schemas.len()
    }

    #[cfg(test)]
    fn expire_now(&self, nsid: &Nsid) {
        let mut store = self.store.write();
        if let Some(entry) = store.schemas.get_mut(nsid) {
            entry.expires_at = Instant::now();
        }
    }
}

impl Default for DynamicRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nsid(s: &str) -> Nsid {
        s.parse().unwrap()
    }

    #[test]
    fn test_negative_cache() {
        let registry = DynamicRegistry::new();
        assert!(!registry.is_negative_cached(&nsid("com.example.test")));

        registry.insert_negative(&nsid("com.example.test"));
        assert!(registry.is_negative_cached(&nsid("com.example.test")));
    }

    #[tokio::test]
    async fn test_negative_cache_returns_appropriate_error_variant() {
        let registry = DynamicRegistry::new();
        registry.insert_negative(&nsid("com.example.cached"));

        let err = registry
            .resolve_and_cache(&nsid("com.example.cached"))
            .await
            .unwrap_err();

        assert!(
            !matches!(err, ResolveError::InvalidNsid(_)),
            "negative cache hit should not return InvalidNsid - the NSID is valid, it just failed resolution recently. got: {}",
            err
        );
    }

    #[test]
    fn test_empty_lookup() {
        let registry = DynamicRegistry::new();
        assert!(
            registry
                .get_cached(&nsid("com.example.nonexistent"))
                .is_none()
        );
        assert_eq!(registry.schema_count(), 0);
    }

    #[test]
    fn test_insert_and_retrieve() {
        let registry = DynamicRegistry::new();
        let doc = LexiconDoc {
            lexicon: 1,
            id: nsid("com.example.test"),
            defs: HashMap::new(),
        };

        let arc = registry.insert_schema(doc);
        assert_eq!(arc.id, "com.example.test");
        assert_eq!(registry.schema_count(), 1);

        let retrieved = registry.get_cached(&nsid("com.example.test"));
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, "com.example.test");

        let entry = registry.get_entry(&nsid("com.example.test")).unwrap();
        assert!(entry.is_fresh(), "freshly inserted entry must be fresh");
    }

    #[test]
    fn test_negative_cache_cleared_on_insert() {
        let registry = DynamicRegistry::new();

        registry.insert_negative(&nsid("com.example.test"));
        assert!(registry.is_negative_cached(&nsid("com.example.test")));

        let doc = LexiconDoc {
            lexicon: 1,
            id: nsid("com.example.test"),
            defs: HashMap::new(),
        };
        registry.insert_schema(doc);

        assert!(!registry.is_negative_cached(&nsid("com.example.test")));
    }

    #[test]
    fn test_positive_entry_reports_stale_after_ttl() {
        let registry = DynamicRegistry::new();
        let doc = LexiconDoc {
            lexicon: 1,
            id: nsid("pet.nel.stale"),
            defs: HashMap::new(),
        };
        registry.insert_schema(doc);

        assert!(
            registry
                .get_entry(&nsid("pet.nel.stale"))
                .unwrap()
                .is_fresh()
        );

        registry.expire_now(&nsid("pet.nel.stale"));

        assert!(
            !registry
                .get_entry(&nsid("pet.nel.stale"))
                .unwrap()
                .is_fresh(),
            "entry past expiry must be reported stale"
        );
    }

    #[tokio::test]
    async fn test_stale_served_on_resolve_failure() {
        let registry = DynamicRegistry::new();
        let doc = LexiconDoc {
            lexicon: 1,
            id: nsid("pet.nel.flaky"),
            defs: HashMap::new(),
        };
        registry.insert_schema(doc);
        registry.expire_now(&nsid("pet.nel.flaky"));

        let result = registry
            .resolve_and_cache_with(&nsid("pet.nel.flaky"), |n| async move {
                Err::<LexiconDoc, _>(ResolveError::DnsLookup {
                    domain: n,
                    reason: "simulated failure".to_string(),
                })
            })
            .await;

        let served = result.expect("stale entry must be served when refresh fails");
        assert_eq!(served.id, "pet.nel.flaky");
        assert!(
            registry
                .get_entry(&nsid("pet.nel.flaky"))
                .unwrap()
                .is_fresh(),
            "failed refresh must bump expiry so subsequent lookups skip the resolver"
        );
        assert!(
            !registry.is_negative_cached(&nsid("pet.nel.flaky")),
            "stale refresh failure must not poison negative cache"
        );
    }

    #[tokio::test]
    async fn test_fresh_hit_skips_resolver() {
        let registry = DynamicRegistry::new();
        let doc = LexiconDoc {
            lexicon: 1,
            id: nsid("pet.nel.fresh"),
            defs: HashMap::new(),
        };
        registry.insert_schema(doc);

        let result = registry
            .resolve_and_cache_with(&nsid("pet.nel.fresh"), |_| async move {
                panic!("resolver must not run on fresh hit")
            })
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_stale_served_when_network_disabled() {
        let registry = DynamicRegistry::new();
        let doc = LexiconDoc {
            lexicon: 1,
            id: nsid("pet.nel.offline"),
            defs: HashMap::new(),
        };
        registry.insert_schema(doc);
        registry.expire_now(&nsid("pet.nel.offline"));
        registry.set_network_disabled(true);

        let result = registry
            .resolve_and_cache_with(&nsid("pet.nel.offline"), |_| async move {
                panic!("resolver must not run when network disabled")
            })
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_successful_refresh_updates_cached_at() {
        let registry = DynamicRegistry::new();
        let doc = LexiconDoc {
            lexicon: 1,
            id: nsid("pet.nel.refresh"),
            defs: HashMap::new(),
        };
        registry.insert_schema(doc);
        registry.expire_now(&nsid("pet.nel.refresh"));

        assert!(
            !registry
                .get_entry(&nsid("pet.nel.refresh"))
                .unwrap()
                .is_fresh()
        );

        let refreshed = registry
            .resolve_and_cache_with(&nsid("pet.nel.refresh"), |n| async move {
                Ok(LexiconDoc {
                    lexicon: 1,
                    id: n,
                    defs: HashMap::new(),
                })
            })
            .await
            .unwrap();

        assert_eq!(refreshed.id, "pet.nel.refresh");
        assert!(
            registry
                .get_entry(&nsid("pet.nel.refresh"))
                .unwrap()
                .is_fresh(),
            "refresh must restore freshness"
        );
    }

    #[tokio::test]
    async fn test_single_flight_dedups_concurrent_resolves() {
        use std::sync::atomic::AtomicUsize;
        let registry = Arc::new(DynamicRegistry::new());
        let calls = Arc::new(AtomicUsize::new(0));

        let tasks: Vec<_> = (0..16)
            .map(|_| {
                let registry = Arc::clone(&registry);
                let calls = Arc::clone(&calls);
                tokio::spawn(async move {
                    registry
                        .resolve_and_cache_with(&nsid("pet.nel.herd"), |n| {
                            let calls = Arc::clone(&calls);
                            async move {
                                calls.fetch_add(1, Ordering::SeqCst);
                                tokio::time::sleep(Duration::from_millis(50)).await;
                                Ok(LexiconDoc {
                                    lexicon: 1,
                                    id: n,
                                    defs: HashMap::new(),
                                })
                            }
                        })
                        .await
                })
            })
            .collect();

        let results = futures_collect(tasks).await;
        results
            .iter()
            .for_each(|r| assert!(r.is_ok(), "all single-flight callers must succeed"));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "single-flight must coalesce concurrent resolves"
        );
        assert_eq!(registry.schema_count(), 1);
    }

    #[tokio::test]
    async fn test_single_flight_followers_observe_leader_failure() {
        use std::sync::atomic::AtomicUsize;
        let registry = Arc::new(DynamicRegistry::new());
        let calls = Arc::new(AtomicUsize::new(0));

        let tasks: Vec<_> = (0..8)
            .map(|_| {
                let registry = Arc::clone(&registry);
                let calls = Arc::clone(&calls);
                tokio::spawn(async move {
                    registry
                        .resolve_and_cache_with(&nsid("pet.nel.failHerd"), |n| {
                            let calls = Arc::clone(&calls);
                            async move {
                                calls.fetch_add(1, Ordering::SeqCst);
                                tokio::time::sleep(Duration::from_millis(50)).await;
                                Err::<LexiconDoc, _>(ResolveError::DnsLookup {
                                    domain: n,
                                    reason: "simulated".to_string(),
                                })
                            }
                        })
                        .await
                })
            })
            .collect();

        let results = futures_collect(tasks).await;
        results
            .iter()
            .for_each(|r| assert!(r.is_err(), "all followers must observe leader failure"));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "single-flight must coalesce failing resolves too"
        );
        assert!(registry.is_negative_cached(&nsid("pet.nel.failHerd")));
    }

    async fn futures_collect<T>(handles: Vec<tokio::task::JoinHandle<T>>) -> Vec<T> {
        futures::future::join_all(handles)
            .await
            .into_iter()
            .map(|r| r.expect("task panicked"))
            .collect()
    }

    #[test]
    fn test_eviction_is_fifo() {
        let registry = DynamicRegistry::new();

        (0..MAX_DYNAMIC_SCHEMAS).for_each(|i| {
            let doc = LexiconDoc {
                lexicon: 1,
                id: nsid(&format!("pet.nel.schema{}", i)),
                defs: HashMap::new(),
            };
            registry.insert_schema(doc);
        });
        assert_eq!(registry.schema_count(), MAX_DYNAMIC_SCHEMAS);

        let trigger = LexiconDoc {
            lexicon: 1,
            id: nsid("pet.nel.trigger"),
            defs: HashMap::new(),
        };
        registry.insert_schema(trigger);

        assert!(
            registry.get_cached(&nsid("pet.nel.schema0")).is_none(),
            "oldest entry should be evicted"
        );
        assert!(
            registry.get_cached(&nsid("pet.nel.trigger")).is_some(),
            "newly inserted entry should exist"
        );
        let evict_count = MAX_DYNAMIC_SCHEMAS / 4;
        assert!(
            registry
                .get_cached(&nsid(&format!("pet.nel.schema{}", evict_count)))
                .is_some(),
            "entry after eviction window should survive"
        );
    }

    #[test]
    fn test_eviction_frees_memory() {
        let registry = DynamicRegistry::new();
        let doc = LexiconDoc {
            lexicon: 1,
            id: nsid("pet.nel.tracked"),
            defs: HashMap::new(),
        };
        let arc = registry.insert_schema(doc);
        let weak = Arc::downgrade(&arc);
        drop(arc);

        assert!(weak.upgrade().is_some(), "registry still holds a reference");

        (0..MAX_DYNAMIC_SCHEMAS).for_each(|i| {
            registry.insert_schema(LexiconDoc {
                lexicon: 1,
                id: nsid(&format!("pet.nel.filler{}", i)),
                defs: HashMap::new(),
            });
        });

        assert!(
            weak.upgrade().is_none(),
            "evicted Arc should be freed when no external references remain"
        );
    }
}
