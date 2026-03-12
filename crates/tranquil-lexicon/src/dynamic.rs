use crate::resolve::{ResolveError, resolve_lexicon};
use crate::schema::LexiconDoc;
use parking_lot::RwLock;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_DYNAMIC_SCHEMAS: usize = 1024;

struct NegativeEntry {
    expires_at: Instant,
}

struct SchemaStore {
    schemas: HashMap<String, Arc<LexiconDoc>>,
    insertion_order: VecDeque<String>,
}

pub struct DynamicRegistry {
    store: RwLock<SchemaStore>,
    negative_cache: RwLock<HashMap<String, NegativeEntry>>,
    network_disabled: AtomicBool,
}

impl DynamicRegistry {
    pub fn new() -> Self {
        let network_disabled =
            std::env::var("TRANQUIL_LEXICON_OFFLINE").is_ok_and(|v| v == "1" || v == "true");
        Self {
            store: RwLock::new(SchemaStore {
                schemas: HashMap::new(),
                insertion_order: VecDeque::new(),
            }),
            negative_cache: RwLock::new(HashMap::new()),
            network_disabled: AtomicBool::new(network_disabled),
        }
    }

    #[allow(dead_code)]
    pub fn set_network_disabled(&self, disabled: bool) {
        self.network_disabled.store(disabled, Ordering::Relaxed);
    }

    pub fn get(&self, nsid: &str) -> Option<Arc<LexiconDoc>> {
        self.store.read().schemas.get(nsid).cloned()
    }

    pub fn is_negative_cached(&self, nsid: &str) -> bool {
        let cache = self.negative_cache.read();
        cache
            .get(nsid)
            .is_some_and(|entry| entry.expires_at > Instant::now())
    }

    fn insert_negative(&self, nsid: &str) {
        let mut cache = self.negative_cache.write();
        if cache.len() > MAX_DYNAMIC_SCHEMAS {
            let now = Instant::now();
            cache.retain(|_, entry| entry.expires_at > now);
        }
        cache.insert(
            nsid.to_string(),
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

        if store
            .schemas
            .insert(nsid.clone(), Arc::clone(&arc))
            .is_some()
        {
            store.insertion_order.retain(|k| k != &nsid);
        }
        store.insertion_order.push_back(nsid.clone());

        self.negative_cache.write().remove(&arc.id);

        arc
    }

    pub async fn resolve_and_cache(&self, nsid: &str) -> Result<Arc<LexiconDoc>, ResolveError> {
        if let Some(doc) = self.get(nsid) {
            return Ok(doc);
        }

        if self.network_disabled.load(Ordering::Relaxed) {
            return Err(ResolveError::NetworkDisabled);
        }

        if self.is_negative_cached(nsid) {
            return Err(ResolveError::NegativelyCached {
                nsid: nsid.to_string(),
                ttl_secs: NEGATIVE_CACHE_TTL.as_secs(),
            });
        }

        match resolve_lexicon(nsid).await {
            Ok(doc) => Ok(self.insert_schema(doc)),
            Err(e) => {
                tracing::debug!(nsid = nsid, error = %e, "caching negative resolution result");
                self.insert_negative(nsid);
                Err(e)
            }
        }
    }

    pub fn schema_count(&self) -> usize {
        self.store.read().schemas.len()
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

    #[test]
    fn test_negative_cache() {
        let registry = DynamicRegistry::new();
        assert!(!registry.is_negative_cached("com.example.test"));

        registry.insert_negative("com.example.test");
        assert!(registry.is_negative_cached("com.example.test"));
    }

    #[tokio::test]
    async fn test_negative_cache_returns_appropriate_error_variant() {
        let registry = DynamicRegistry::new();
        registry.insert_negative("com.example.cached");

        let err = registry
            .resolve_and_cache("com.example.cached")
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
        assert!(registry.get("com.example.nonexistent").is_none());
        assert_eq!(registry.schema_count(), 0);
    }

    #[test]
    fn test_insert_and_retrieve() {
        let registry = DynamicRegistry::new();
        let doc = LexiconDoc {
            lexicon: 1,
            id: "com.example.test".to_string(),
            defs: HashMap::new(),
        };

        let arc = registry.insert_schema(doc);
        assert_eq!(arc.id, "com.example.test");
        assert_eq!(registry.schema_count(), 1);

        let retrieved = registry.get("com.example.test");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, "com.example.test");
    }

    #[test]
    fn test_negative_cache_cleared_on_insert() {
        let registry = DynamicRegistry::new();

        registry.insert_negative("com.example.test");
        assert!(registry.is_negative_cached("com.example.test"));

        let doc = LexiconDoc {
            lexicon: 1,
            id: "com.example.test".to_string(),
            defs: HashMap::new(),
        };
        registry.insert_schema(doc);

        assert!(!registry.is_negative_cached("com.example.test"));
    }

    #[test]
    fn test_eviction_is_fifo() {
        let registry = DynamicRegistry::new();

        (0..MAX_DYNAMIC_SCHEMAS).for_each(|i| {
            let doc = LexiconDoc {
                lexicon: 1,
                id: format!("com.example.schema{}", i),
                defs: HashMap::new(),
            };
            registry.insert_schema(doc);
        });
        assert_eq!(registry.schema_count(), MAX_DYNAMIC_SCHEMAS);

        let trigger = LexiconDoc {
            lexicon: 1,
            id: "com.example.trigger".to_string(),
            defs: HashMap::new(),
        };
        registry.insert_schema(trigger);

        assert!(
            registry.get("com.example.schema0").is_none(),
            "oldest entry should be evicted"
        );
        assert!(
            registry.get("com.example.trigger").is_some(),
            "newly inserted entry should exist"
        );
        let evict_count = MAX_DYNAMIC_SCHEMAS / 4;
        assert!(
            registry
                .get(&format!("com.example.schema{}", evict_count))
                .is_some(),
            "entry after eviction window should survive"
        );
    }

    #[test]
    fn test_eviction_frees_memory() {
        let registry = DynamicRegistry::new();
        let doc = LexiconDoc {
            lexicon: 1,
            id: "com.example.tracked".to_string(),
            defs: HashMap::new(),
        };
        let arc = registry.insert_schema(doc);
        let weak = Arc::downgrade(&arc);
        drop(arc);

        assert!(weak.upgrade().is_some(), "registry still holds a reference");

        (0..MAX_DYNAMIC_SCHEMAS).for_each(|i| {
            registry.insert_schema(LexiconDoc {
                lexicon: 1,
                id: format!("com.example.filler{}", i),
                defs: HashMap::new(),
            });
        });

        assert!(
            weak.upgrade().is_none(),
            "evicted Arc should be freed when no external references remain"
        );
    }
}
