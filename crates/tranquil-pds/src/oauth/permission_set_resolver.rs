use crate::cache::Cache;
use crate::cache_keys::permission_set_key;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tranquil_scopes::{
    ExpansionOutcome, FailedSet, ResolveFailure, ResolvedSetGroup, ScopeExpansionError,
    fetch_and_expand, parse_include_scope,
};
use tranquil_types::Nsid;

#[derive(Serialize, Deserialize)]
struct CachedPermissionSet {
    scope: String,
    title: Option<String>,
    detail: Option<String>,
    #[serde(default)]
    refreshed_at: i64,
}

const STALE_AFTER_SECS: i64 = 24 * 60 * 60;
const PERMISSION_SET_CACHE_TTL_SECS: u64 = 90 * 24 * 60 * 60;

fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

fn is_stale(refreshed_at: i64) -> bool {
    now_secs().saturating_sub(refreshed_at) >= STALE_AFTER_SECS
}

pub async fn expand_scopes(cache: &dyn Cache, scope_string: &str) -> ExpansionOutcome {
    let mut outcome = ExpansionOutcome::default();
    for tok in scope_string.split_whitespace() {
        match tok.strip_prefix("include:") {
            None => outcome.passthrough.push(tok.to_string()),
            Some(rest) => {
                let (nsid, aud) = parse_include_scope(rest);
                match resolve_one(cache, nsid, aud).await {
                    Ok(group) => outcome.sets.push(group),
                    Err(reason) => outcome.failures.push(FailedSet {
                        given_nsid: nsid.to_string(),
                        given_aud: aud.map(str::to_string),
                        reason,
                    }),
                }
            }
        }
    }
    outcome
}

async fn resolve_one(
    cache: &dyn Cache,
    nsid: &str,
    aud: Option<&str>,
) -> Result<ResolvedSetGroup, ResolveFailure> {
    let parsed = Nsid::new(nsid).map_err(|_| ResolveFailure::Malformed)?;
    let key = permission_set_key(&parsed, aud);

    let cached = cache
        .get(&key)
        .await
        .and_then(|json| serde_json::from_str::<CachedPermissionSet>(&json).ok());

    if let Some(v) = &cached
        && !is_stale(v.refreshed_at)
    {
        return Ok(group_from(
            parsed,
            aud,
            v.scope.clone(),
            v.title.clone(),
            v.detail.clone(),
        ));
    }

    match fetch_and_expand(&parsed, aud).await {
        Ok(fetched) => {
            let stored = CachedPermissionSet {
                scope: fetched.expanded.clone(),
                title: fetched.title.clone(),
                detail: fetched.detail.clone(),
                refreshed_at: now_secs(),
            };
            if let Ok(json) = serde_json::to_string(&stored) {
                let _ = cache
                    .set(
                        &key,
                        &json,
                        Duration::from_secs(PERMISSION_SET_CACHE_TTL_SECS),
                    )
                    .await;
            }
            Ok(group_from(
                parsed,
                aud,
                fetched.expanded,
                fetched.title,
                fetched.detail,
            ))
        }
        Err(e) => match cached {
            Some(v) => Ok(group_from(parsed, aud, v.scope, v.title, v.detail)),
            None => Err(map_err(&e)),
        },
    }
}

fn group_from(
    nsid: Nsid,
    aud: Option<&str>,
    scope: String,
    title: Option<String>,
    detail: Option<String>,
) -> ResolvedSetGroup {
    ResolvedSetGroup {
        nsid,
        aud: aud.map(str::to_string),
        title,
        detail,
        expanded: scope.split_whitespace().map(str::to_string).collect(),
    }
}

fn map_err(e: &ScopeExpansionError) -> ResolveFailure {
    use ScopeExpansionError as E;
    match e {
        E::InvalidNsid(_) => ResolveFailure::Malformed,
        E::RecordNotFound => ResolveFailure::NotFound,
        E::UnexpectedType(_) => ResolveFailure::NotAPermissionSet,
        E::MissingDefinition(_) => ResolveFailure::MalformedLexicon,
        E::EmptyPermissions => ResolveFailure::EmptyPermissions,
        E::DnsResolution(_) | E::HttpFailed(_) | E::DidResolution(_) => ResolveFailure::Unreachable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tranquil_infra::MemoryCache;

    const SEED_TTL: Duration = Duration::from_secs(3600);

    async fn seed_at(cache: &MemoryCache, nsid: &str, scope: &str, refreshed_at: i64) {
        let key =
            crate::cache_keys::permission_set_key(&tranquil_types::Nsid::new(nsid).unwrap(), None);
        let val = serde_json::to_string(&CachedPermissionSet {
            scope: scope.to_string(),
            title: Some("Basic".into()),
            detail: None,
            refreshed_at,
        })
        .unwrap();
        let _ = cache.set(&key, &val, SEED_TTL).await;
    }

    async fn seed(cache: &MemoryCache, nsid: &str, scope: &str) {
        seed_at(cache, nsid, scope, now_secs()).await;
    }

    #[tokio::test]
    async fn cache_hit_expands_without_network() {
        let cache = MemoryCache::new();
        seed(
            &cache,
            "io.atcr.authFullApp",
            "repo:io.atcr.manifest?action=create identity:*",
        )
        .await;
        let out = expand_scopes(&cache, "atproto include:io.atcr.authFullApp").await;
        assert!(out.failures.is_empty());
        assert_eq!(out.passthrough, vec!["atproto".to_string()]);
        assert_eq!(out.sets.len(), 1);
        assert_eq!(out.sets[0].nsid, "io.atcr.authFullApp");
        assert!(
            out.flat_scopes()
                .iter()
                .any(|s| s == "repo:io.atcr.manifest?action=create")
        );
    }

    #[tokio::test]
    async fn stale_entry_is_served_when_refresh_fails() {
        let cache = MemoryCache::new();
        seed_at(
            &cache,
            "nonexistent.fake.permissionSet",
            "repo:nonexistent.fake.record?action=create",
            now_secs() - STALE_AFTER_SECS - 1,
        )
        .await;
        let out = expand_scopes(&cache, "include:nonexistent.fake.permissionSet").await;
        assert!(
            out.failures.is_empty(),
            "stale entry should survive an unresolvable publisher"
        );
        assert_eq!(out.sets.len(), 1);
        assert!(
            out.flat_scopes()
                .iter()
                .any(|s| s == "repo:nonexistent.fake.record?action=create")
        );
    }

    #[tokio::test]
    async fn entry_without_refreshed_at_is_treated_as_stale_but_usable() {
        let cache = MemoryCache::new();
        let key = crate::cache_keys::permission_set_key(
            &tranquil_types::Nsid::new("nonexistent.fake.permissionSet").unwrap(),
            None,
        );
        // Shape written before `refreshed_at` existed.
        let legacy =
            r#"{"scope":"repo:nonexistent.fake.record?action=create","title":null,"detail":null}"#;
        let _ = cache.set(&key, legacy, SEED_TTL).await;
        let out = expand_scopes(&cache, "include:nonexistent.fake.permissionSet").await;
        assert!(out.failures.is_empty());
        assert_eq!(out.sets.len(), 1);
    }

    #[tokio::test]
    async fn passthrough_scopes_untouched() {
        let cache = MemoryCache::new();
        let out = expand_scopes(&cache, "atproto repo:app.bsky.feed.post?action=create").await;
        assert!(out.failures.is_empty());
        assert!(out.sets.is_empty());
        assert_eq!(out.flat_scopes().len(), 2);
    }

    #[tokio::test]
    async fn cache_miss_unresolvable_is_a_failure() {
        let cache = MemoryCache::new();
        let out = expand_scopes(&cache, "include:nonexistent.fake.permissionSet").await;
        assert_eq!(out.sets.len(), 0);
        assert_eq!(out.failures.len(), 1);
        assert_eq!(out.failures[0].given_nsid, "nonexistent.fake.permissionSet");
    }
}
