use crate::resolve::{ResolveError, resolve_lexicon};
use crate::schema::LexiconDoc;
use parking_lot::RwLock;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Notify;
use tranquil_infra::cache_keys::{lexicon_doc_key, lexicon_negative_key};
use tranquil_infra::{Cache, read_json, write_json};
use tranquil_types::Nsid;

const NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(60 * 60);
const POSITIVE_CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const REFRESH_FAILURE_BACKOFF: Duration = Duration::from_secs(60);
const MAX_DYNAMIC_SCHEMAS: usize = 1024;

struct NegativeEntry {
    expires_at: Instant,
}

fn negative_ttl_for(error: &ResolveError) -> Duration {
    match error.is_definitive() {
        true => NEGATIVE_CACHE_TTL,
        false => REFRESH_FAILURE_BACKOFF,
    }
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
    shared: RwLock<Option<Arc<dyn Cache>>>,
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
            shared: RwLock::new(None),
        }
    }

    pub fn set_shared_cache(&self, cache: Arc<dyn Cache>) {
        *self.shared.write() = Some(cache);
    }

    fn shared_cache(&self) -> Option<Arc<dyn Cache>> {
        self.shared.read().clone()
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
        self.negative_remaining(nsid).is_some()
    }

    fn negative_remaining(&self, nsid: &Nsid) -> Option<Duration> {
        self.negative_cache
            .read()
            .get(nsid)
            .and_then(|entry| entry.expires_at.checked_duration_since(Instant::now()))
    }

    fn insert_negative(&self, nsid: &Nsid, ttl: Duration) {
        let mut cache = self.negative_cache.write();
        if cache.len() >= MAX_DYNAMIC_SCHEMAS {
            let now = Instant::now();
            cache.retain(|_, entry| entry.expires_at > now);
        }
        cache.insert(
            nsid.clone(),
            NegativeEntry {
                expires_at: Instant::now() + ttl,
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

    async fn shared_get(&self, nsid: &Nsid) -> Option<Arc<LexiconDoc>> {
        let cache = self.shared_cache()?;
        let doc = read_json::<LexiconDoc>(cache.as_ref(), &lexicon_doc_key(nsid)).await?;
        Some(self.insert_schema(doc))
    }

    async fn shared_put(&self, doc: &LexiconDoc) {
        let Some(cache) = self.shared_cache() else {
            return;
        };
        write_json(
            cache.as_ref(),
            &lexicon_doc_key(&doc.id),
            doc,
            POSITIVE_CACHE_TTL,
        )
        .await;
        let _ = cache.delete(&lexicon_negative_key(&doc.id)).await;
    }

    async fn shared_is_negative(&self, nsid: &Nsid) -> bool {
        match self.shared_cache() {
            Some(cache) => cache.get(&lexicon_negative_key(nsid)).await.is_some(),
            None => false,
        }
    }

    async fn shared_put_negative(&self, nsid: &Nsid, error: &ResolveError) {
        if !error.is_definitive() {
            return;
        }
        if let Some(cache) = self.shared_cache() {
            let _ = cache
                .set(&lexicon_negative_key(nsid), "1", NEGATIVE_CACHE_TTL)
                .await;
        }
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
                Ok(doc) => {
                    self.shared_put(&doc).await;
                    Ok(self.insert_schema(doc))
                }
                Err(e) => {
                    let (doc, source) = match self.shared_get(nsid).await {
                        Some(doc) => (doc, "shared"),
                        None => (stale, "local"),
                    };
                    self.bump_expiry(nsid, REFRESH_FAILURE_BACKOFF);
                    tracing::warn!(
                        nsid = %nsid,
                        error = %e,
                        source,
                        "lexicon refresh failed, serving cached entry"
                    );
                    Ok(doc)
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
        if let Some(doc) = self.shared_get(nsid).await {
            return Ok(doc);
        }

        if let Some(remaining) = self.negative_remaining(nsid) {
            return Err(ResolveError::NegativelyCached {
                nsid: nsid.clone(),
                ttl_secs: remaining.as_secs(),
            });
        }

        if self.shared_is_negative(nsid).await {
            // Cache reports 0 remaining TTL for shared negative hit,
            // so we mirror for the backoff rather than a full `NEGATIVE_CACHE_TTL`.
            self.insert_negative(nsid, REFRESH_FAILURE_BACKOFF);
            return Err(ResolveError::NegativelyCached {
                nsid: nsid.clone(),
                ttl_secs: REFRESH_FAILURE_BACKOFF.as_secs(),
            });
        }

        if self.network_disabled.load(Ordering::Relaxed) {
            return Err(ResolveError::NetworkDisabled);
        }

        match self.acquire_leadership(nsid) {
            Some(_guard) => match resolver(nsid.clone()).await {
                Ok(doc) => {
                    self.shared_put(&doc).await;
                    Ok(self.insert_schema(doc))
                }
                Err(e) => {
                    let ttl = negative_ttl_for(&e);
                    self.insert_negative(nsid, ttl);
                    self.shared_put_negative(nsid, &e).await;
                    tracing::debug!(
                        nsid = %nsid,
                        error = %e,
                        ttl_secs = ttl.as_secs(),
                        "caching negative resolution result"
                    );
                    Err(e)
                }
            },
            None => {
                self.wait_for_leader(nsid).await;
                match (self.get_cached(nsid), self.negative_remaining(nsid)) {
                    (Some(doc), _) => Ok(doc),
                    (None, Some(remaining)) => Err(ResolveError::NegativelyCached {
                        nsid: nsid.clone(),
                        ttl_secs: remaining.as_secs(),
                    }),
                    (None, None) => Err(ResolveError::LeaderAborted { nsid: nsid.clone() }),
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
    use tranquil_infra::MemoryCache;

    fn nsid(s: &str) -> Nsid {
        s.parse().unwrap()
    }

    #[test]
    fn test_negative_cache() {
        let registry = DynamicRegistry::new();
        assert!(!registry.is_negative_cached(&nsid("pet.nel.negative")));

        registry.insert_negative(&nsid("pet.nel.negative"), NEGATIVE_CACHE_TTL);
        assert!(registry.is_negative_cached(&nsid("pet.nel.negative")));
    }

    #[tokio::test]
    async fn test_negative_cache_returns_appropriate_error_variant() {
        let registry = DynamicRegistry::new();
        registry.insert_negative(&nsid("pet.nel.cached"), NEGATIVE_CACHE_TTL);

        let err = registry
            .resolve_and_cache(&nsid("pet.nel.cached"))
            .await
            .unwrap_err();

        assert!(
            matches!(err, ResolveError::NegativelyCached { .. }),
            "negative cache hit must surface as NegativelyCached, got: {}",
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

        registry.insert_negative(&nsid("pet.nel.cleared"), NEGATIVE_CACHE_TTL);
        assert!(registry.is_negative_cached(&nsid("pet.nel.cleared")));

        let doc = LexiconDoc {
            lexicon: 1,
            id: nsid("pet.nel.cleared"),
            defs: HashMap::new(),
        };
        registry.insert_schema(doc);

        assert!(!registry.is_negative_cached(&nsid("pet.nel.cleared")));
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
                    domain: n.into_inner(),
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
                                    domain: n.into_inner(),
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

    #[tokio::test]
    async fn test_shared_positive_hit_skips_resolver() {
        let registry = DynamicRegistry::new();
        let cache = Arc::new(MemoryCache::new());
        registry.set_shared_cache(cache.clone());
        let doc = LexiconDoc {
            lexicon: 1,
            id: nsid("pet.nel.sharedDoc"),
            defs: HashMap::new(),
        };
        cache
            .set(
                &lexicon_doc_key(&nsid("pet.nel.sharedDoc")),
                &serde_json::to_string(&doc).unwrap(),
                POSITIVE_CACHE_TTL,
            )
            .await
            .unwrap();

        let resolved = registry
            .resolve_and_cache_with(&nsid("pet.nel.sharedDoc"), |_| async move {
                panic!("resolver mustn't run on a shared positive hit")
            })
            .await
            .unwrap();

        assert_eq!(resolved.id, "pet.nel.sharedDoc");
        assert!(registry.get_cached(&nsid("pet.nel.sharedDoc")).is_some());
    }

    #[tokio::test]
    async fn test_definitive_failure_writes_shared_negative_and_peers_mirror_it() {
        let cache = Arc::new(MemoryCache::new());
        let registry = DynamicRegistry::new();
        registry.set_shared_cache(cache.clone());

        let _ = registry
            .resolve_and_cache_with(&nsid("pet.nel.gone"), |n| async move {
                Err::<LexiconDoc, _>(ResolveError::SchemaNotFound {
                    nsid: n,
                    url: "https://oyster.cafe".to_string(),
                })
            })
            .await;
        assert!(
            cache
                .get(&lexicon_negative_key(&nsid("pet.nel.gone")))
                .await
                .is_some(),
            "definitive failure must write the shared negative key"
        );

        let _ = registry
            .resolve_and_cache_with(&nsid("pet.nel.transient"), |n| async move {
                Err::<LexiconDoc, _>(ResolveError::DnsLookup {
                    domain: n.into_inner(),
                    reason: "simulated".to_string(),
                })
            })
            .await;
        assert!(
            cache
                .get(&lexicon_negative_key(&nsid("pet.nel.transient")))
                .await
                .is_none(),
            "transient failure must stay out of the shared negative key"
        );

        let peer = DynamicRegistry::new();
        peer.set_shared_cache(cache);
        let err = peer
            .resolve_and_cache_with(&nsid("pet.nel.gone"), |_| async move {
                panic!("resolver mustn't run on a shared negative hit")
            })
            .await
            .unwrap_err();
        match err {
            ResolveError::NegativelyCached { ttl_secs, .. } => assert!(
                ttl_secs <= REFRESH_FAILURE_BACKOFF.as_secs(),
                "local mirror must use the backoff TTL, got {}s",
                ttl_secs
            ),
            other => panic!("expected NegativelyCached, got: {}", other),
        }
        assert!(
            peer.negative_remaining(&nsid("pet.nel.gone"))
                .expect("local mirror exists")
                <= REFRESH_FAILURE_BACKOFF
        );
    }
}
