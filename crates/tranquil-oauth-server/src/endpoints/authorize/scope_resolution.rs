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
    // The expanded set of scopes, minus any denied by delegation
    pub permitted: String,
    // The expanded set of scopes, before delegation processing
    pub outcome: ExpansionOutcome,
}

pub async fn resolve_effective_scopes(
    cache: &dyn Cache,
    requested: &str,
    authority: Authority<'_>,
) -> EffectiveScopes {
    let outcome = expand_scopes(cache, requested).await;
    let expanded = outcome.to_scope_string();
    let permitted = match authority {
        Authority::FullSelf => expanded,
        Authority::Delegated(granted) => intersect_scopes(&expanded, granted.as_str()),
    };
    EffectiveScopes { permitted, outcome }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tranquil_infra::MemoryCache;
    use tranquil_pds::cache::Cache;

    async fn cache_with(nsid: &str, scopes: &str) -> MemoryCache {
        let c = MemoryCache::new();
        let key = tranquil_pds::cache_keys::permission_set_key(
            &tranquil_types::Nsid::new(nsid).unwrap(),
            None,
        );
        let json = serde_json::json!({
            "scope": scopes,
            "title": null,
            "detail": null,
            "refreshed_at": chrono::Utc::now().timestamp(),
        })
        .to_string();
        let _ = c.set(&key, &json, Duration::from_secs(3600)).await;
        c
    }

    #[tokio::test]
    async fn full_self_keeps_all_expanded() {
        let c = cache_with(
            "io.atcr.authFullApp",
            "repo:io.atcr.manifest?action=create identity:*",
        )
        .await;
        let eff = resolve_effective_scopes(
            &c,
            "atproto include:io.atcr.authFullApp",
            Authority::FullSelf,
        )
        .await;
        assert!(eff.permitted.contains("atproto"));
        assert!(
            eff.permitted
                .contains("repo:io.atcr.manifest?action=create")
        );
        assert!(eff.permitted.contains("identity:*"));
        assert!(eff.outcome.failures.is_empty());
    }

    #[tokio::test]
    async fn delegated_intersects_expanded_against_grant() {
        let c = cache_with(
            "io.atcr.authFullApp",
            "repo:io.atcr.manifest?action=create identity:*",
        )
        .await;
        let granted = DbScope::new("atproto repo:* blob:*/* account:*?action=manage").unwrap();
        let eff = resolve_effective_scopes(
            &c,
            "atproto include:io.atcr.authFullApp",
            Authority::Delegated(&granted),
        )
        .await;
        assert!(eff.permitted.contains("atproto"));
        assert!(
            eff.permitted
                .contains("repo:io.atcr.manifest?action=create")
        );
        assert!(!eff.permitted.contains("identity"));
    }
}
