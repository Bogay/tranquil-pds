use tranquil_db_traits::DbScope;
use tranquil_pds::cache::Cache;
use tranquil_pds::delegation::intersect_scopes;
use tranquil_pds::oauth::permission_set_resolver::expand_scopes;
use tranquil_scopes::ExpansionOutcome;

pub enum Authority<'a> {
    FullSelf,
    Delegated(&'a DbScope),
}

pub struct EffectiveScopes {
    pub resolved: String,
    pub outcome: ExpansionOutcome,
}

pub async fn resolve_effective_scopes(
    cache: &dyn Cache,
    requested: &str,
    authority: Authority<'_>,
) -> EffectiveScopes {
    let outcome = expand_scopes(cache, requested).await;
    let expanded = outcome.to_scope_string();
    let resolved = match authority {
        Authority::FullSelf => expanded,
        Authority::Delegated(granted) => intersect_scopes(&expanded, granted.as_str()),
    };
    EffectiveScopes { resolved, outcome }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::Duration;
    use tranquil_pds::cache::{Cache, CacheError};

    #[derive(Default)]
    struct MapCache(Mutex<HashMap<String, String>>);
    #[async_trait::async_trait]
    impl Cache for MapCache {
        async fn get(&self, k: &str) -> Option<String> { self.0.lock().unwrap().get(k).cloned() }
        async fn set(&self, k: &str, v: &str, _t: Duration) -> Result<(), CacheError> {
            self.0.lock().unwrap().insert(k.into(), v.into()); Ok(())
        }
        async fn delete(&self, k: &str) -> Result<(), CacheError> { self.0.lock().unwrap().remove(k); Ok(()) }
        async fn get_bytes(&self, _k: &str) -> Option<Vec<u8>> { None }
        async fn set_bytes(&self, _k: &str, _v: &[u8], _t: Duration) -> Result<(), CacheError> { Ok(()) }
    }

    fn cache_with(nsid: &str, scopes: &str) -> MapCache {
        let c = MapCache::default();
        let key = tranquil_pds::cache_keys::permission_set_key(&tranquil_types::Nsid::new(nsid).unwrap(), None);
        let json = serde_json::json!({
            "scope": scopes,
            "title": null,
            "detail": null,
            "refreshed_at": chrono::Utc::now().timestamp(),
        })
        .to_string();
        c.0.lock().unwrap().insert(key, json);
        c
    }

    #[tokio::test]
    async fn full_self_keeps_all_expanded() {
        let c = cache_with("io.atcr.authFullApp", "repo:io.atcr.manifest?action=create identity:*");
        let eff = resolve_effective_scopes(&c, "atproto include:io.atcr.authFullApp", Authority::FullSelf).await;
        assert!(eff.resolved.contains("atproto"));
        assert!(eff.resolved.contains("repo:io.atcr.manifest?action=create"));
        assert!(eff.resolved.contains("identity:*"));
        assert!(eff.outcome.failures.is_empty());
    }

    #[tokio::test]
    async fn delegated_intersects_expanded_against_grant() {
        let c = cache_with("io.atcr.authFullApp", "repo:io.atcr.manifest?action=create identity:*");
        let granted = DbScope::new("atproto repo:* blob:*/* account:*?action=manage").unwrap();
        let eff = resolve_effective_scopes(
            &c, "atproto include:io.atcr.authFullApp",
            Authority::Delegated(&granted),
        ).await;
        assert!(eff.resolved.contains("atproto"));
        assert!(eff.resolved.contains("repo:io.atcr.manifest?action=create"));
        assert!(!eff.resolved.contains("identity"));
    }
}
