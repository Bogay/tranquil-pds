use tranquil_db_traits::DbScope;
use tranquil_pds::cache::Cache;
use tranquil_pds::delegation::{GrantCoverage, grant_coverage, intersect_scopes};
use tranquil_pds::oauth::permission_set_resolver::expand_scopes;
use tranquil_scopes::{ExpansionOutcome, RejectedScope, ScopeRejection};

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
    client_scope: Option<&str>,
) -> EffectiveScopes {
    let mut outcome = expand_scopes(cache, requested).await;
    if let Some(registered) = client_scope.map(str::trim).filter(|s| !s.is_empty()) {
        reject_unregistered(&mut outcome, registered);
    }
    let expanded = outcome.to_scope_string();
    let permitted = match authority {
        Authority::FullSelf => expanded,
        Authority::Delegated(granted) => intersect_scopes(&expanded, granted.as_str()),
    };
    EffectiveScopes { permitted, outcome }
}

fn reject_unregistered(outcome: &mut ExpansionOutcome, registered: &str) {
    let mut rejected = Vec::new();
    let mut keep = |scope: String| match grant_coverage(registered, &scope) {
        GrantCoverage::Full => Some(scope),
        GrantCoverage::Narrowed(narrowed) => Some(narrowed),
        GrantCoverage::Withheld => {
            rejected.push(RejectedScope {
                scope,
                reason: ScopeRejection::NotRegistered,
            });
            None
        }
    };

    outcome.passthrough = std::mem::take(&mut outcome.passthrough)
        .into_iter()
        .filter_map(&mut keep)
        .collect();
    outcome.sets = std::mem::take(&mut outcome.sets)
        .into_iter()
        .filter(|group| keep(group.include_token()).is_some())
        .collect();

    outcome.rejected.extend(rejected);
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
            None,
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
            None,
        )
        .await;
        assert!(eff.permitted.contains("atproto"));
        assert!(
            eff.permitted
                .contains("repo:io.atcr.manifest?action=create")
        );
        assert!(!eff.permitted.contains("identity"));
    }

    #[tokio::test]
    async fn unrecognized_scopes_never_reach_permitted() {
        let c = MemoryCache::new();
        let eff = resolve_effective_scopes(&c, "atproto chat", Authority::FullSelf, None).await;
        assert!(eff.permitted.split_whitespace().any(|s| s == "atproto"));
        assert!(
            !eff.permitted.split_whitespace().any(|s| s == "chat"),
            "permitted was {:?}",
            eff.permitted
        );
        assert_eq!(eff.outcome.rejected.len(), 1);
        assert_eq!(eff.outcome.rejected[0].reason, ScopeRejection::Unrecognized);
    }

    #[tokio::test]
    async fn scopes_absent_from_client_metadata_are_rejected() {
        let c = MemoryCache::new();
        let eff = resolve_effective_scopes(
            &c,
            "atproto identity:*",
            Authority::FullSelf,
            Some("atproto"),
        )
        .await;
        assert!(!eff.permitted.split_whitespace().any(|s| s == "identity:*"));
        assert_eq!(eff.outcome.rejected.len(), 1);
        assert_eq!(eff.outcome.rejected[0].scope, "identity:*");
        assert_eq!(
            eff.outcome.rejected[0].reason,
            ScopeRejection::NotRegistered
        );
    }

    #[tokio::test]
    async fn wildcard_client_registration_covers_narrower_request() {
        let c = MemoryCache::new();
        let eff = resolve_effective_scopes(
            &c,
            "atproto repo:app.bsky.feed.post?action=create",
            Authority::FullSelf,
            Some("atproto repo:*"),
        )
        .await;
        assert!(eff.outcome.rejected.is_empty());
        assert!(
            eff.permitted
                .contains("repo:app.bsky.feed.post?action=create")
        );
    }

    #[tokio::test]
    async fn absent_client_metadata_scope_constrains_nothing() {
        let c = MemoryCache::new();
        let eff =
            resolve_effective_scopes(&c, "atproto identity:*", Authority::FullSelf, None).await;
        assert!(eff.outcome.rejected.is_empty());
        assert!(eff.permitted.contains("identity:*"));
    }

    #[tokio::test]
    async fn set_expanded_scopes_bypass_the_client_registration_check() {
        let c = cache_with("io.atcr.authFullApp", "identity:*").await;
        let eff = resolve_effective_scopes(
            &c,
            "atproto include:io.atcr.authFullApp",
            Authority::FullSelf,
            Some("atproto include:io.atcr.authFullApp"),
        )
        .await;
        assert!(
            eff.outcome.rejected.is_empty(),
            "a permission set legitimately expands to scopes the client never registered"
        );
        assert!(eff.permitted.contains("identity:*"));
    }
}
