use std::collections::HashSet;

pub use tranquil_db_traits::{
    DbScope as ValidatedDelegationScope, InvalidScopeError as InvalidDelegationScopeError,
};

#[derive(Debug, serde::Serialize)]
pub struct ScopePreset {
    pub name: &'static str,
    pub label: &'static str,
    pub description: &'static str,
    pub scopes: &'static str,
}

pub const SCOPE_PRESETS: &[ScopePreset] = &[
    ScopePreset {
        name: "owner",
        label: "Owner",
        description: "Full control including delegation management",
        scopes: "atproto",
    },
    ScopePreset {
        name: "admin",
        label: "Admin",
        description: "Manage account settings, post content, upload media",
        scopes: "atproto repo:* blob:*/* account:*?action=manage",
    },
    ScopePreset {
        name: "editor",
        label: "Editor",
        description: "Post content and upload media",
        scopes: "repo:*?action=create repo:*?action=update repo:*?action=delete blob:*/*",
    },
    ScopePreset {
        name: "viewer",
        label: "Viewer",
        description: "Read-only access",
        scopes: "",
    },
];

pub fn intersect_scopes(requested: &str, granted: &str) -> String {
    if granted.is_empty() {
        return String::new();
    }

    let requested_set: HashSet<&str> = requested.split_whitespace().collect();
    let granted_set: HashSet<&str> = granted.split_whitespace().collect();

    let granted_has_atproto = granted_set.contains("atproto");
    let requested_has_atproto = requested_set.contains("atproto");

    if granted_has_atproto {
        let mut scopes: Vec<&str> = requested_set.into_iter().collect();
        scopes.sort();
        return scopes.join(" ");
    }

    if requested_has_atproto {
        let mut scopes: Vec<&str> = granted_set.into_iter().collect();
        scopes.sort();
        return scopes.join(" ");
    }

    let mut result: Vec<&str> = requested_set
        .iter()
        .filter(|requested_scope| any_granted_covers(requested_scope, &granted_set))
        .copied()
        .collect();

    result.sort();
    result.join(" ")
}

fn any_granted_covers(requested: &str, granted: &HashSet<&str>) -> bool {
    granted
        .iter()
        .any(|granted_scope| scope_covers(granted_scope, requested))
}

fn scope_covers(granted: &str, requested: &str) -> bool {
    if granted == requested {
        return true;
    }

    let (granted_base, granted_params) = split_scope(granted);
    let (requested_base, requested_params) = split_scope(requested);

    let base_matches = if granted_base.ends_with(":*")
        && requested_base.starts_with(&granted_base[..granted_base.len() - 1])
    {
        true
    } else if let Some(prefix) = granted_base.strip_suffix(".*")
        && requested_base.starts_with(prefix)
        && requested_base.len() > prefix.len()
    {
        true
    } else {
        granted_base == requested_base
    };

    if !base_matches {
        return false;
    }

    match (granted_params, requested_params) {
        (None, _) => true,
        (Some(_), None) => true,
        (Some(gp), Some(rp)) => params_cover(gp, rp),
    }
}

fn params_cover(granted_params: &str, requested_params: &str) -> bool {
    let granted_kv: HashSet<(&str, &str)> = granted_params
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .collect();
    let requested_kv: HashSet<(&str, &str)> = requested_params
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .collect();

    let granted_keys: HashSet<&str> = granted_kv.iter().map(|(k, _)| *k).collect();
    let requested_keys: HashSet<&str> = requested_kv.iter().map(|(k, _)| *k).collect();

    requested_keys.iter().all(|key| {
        if !granted_keys.contains(key) {
            return false;
        }
        let requested_values: HashSet<&str> = requested_kv
            .iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| *v)
            .collect();
        let granted_values: HashSet<&str> = granted_kv
            .iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| *v)
            .collect();
        requested_values.is_subset(&granted_values)
    })
}

fn split_scope(scope: &str) -> (&str, Option<&str>) {
    if let Some(idx) = scope.find('?') {
        (&scope[..idx], Some(&scope[idx + 1..]))
    } else {
        (scope, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_intersect_both_atproto() {
        assert_eq!(intersect_scopes("atproto", "atproto"), "atproto");
    }

    #[test]
    fn test_intersect_granted_atproto() {
        let result = intersect_scopes("repo:* blob:*/*", "atproto");
        assert!(result.contains("repo:*"));
        assert!(result.contains("blob:*/*"));
    }

    #[test]
    fn test_intersect_requested_atproto() {
        let result = intersect_scopes("atproto", "repo:* blob:*/*");
        assert!(result.contains("repo:*"));
        assert!(result.contains("blob:*/*"));
    }

    #[test]
    fn test_intersect_exact_match() {
        assert_eq!(
            intersect_scopes("repo:*?action=create", "repo:*?action=create"),
            "repo:*?action=create"
        );
    }

    #[test]
    fn test_intersect_empty_granted() {
        assert_eq!(intersect_scopes("atproto", ""), "");
    }

    #[test]
    fn test_intersect_returns_requested_not_granted() {
        let result = intersect_scopes("repo:app.bsky.feed.post?action=create", "repo:*");
        assert_eq!(result, "repo:app.bsky.feed.post?action=create");
    }

    #[test]
    fn test_intersect_wildcard_granted_covers_specific_requested() {
        let result = intersect_scopes(
            "repo:app.bsky.feed.post?action=create",
            "repo:*?action=create repo:*?action=update blob:*/*",
        );
        assert_eq!(result, "repo:app.bsky.feed.post?action=create");
    }

    #[test]
    fn test_intersect_mismatched_params_rejects() {
        let result = intersect_scopes("repo:*?action=create", "repo:*?action=delete");
        assert!(result.is_empty());
    }

    #[test]
    fn test_intersect_granted_no_params_covers_requested_with_params() {
        let result = intersect_scopes("repo:app.bsky.feed.post?action=create", "repo:*");
        assert_eq!(result, "repo:app.bsky.feed.post?action=create");
    }

    #[test]
    fn test_intersect_granted_with_params_covers_requested_no_params() {
        let result = intersect_scopes(
            "repo:app.bsky.feed.post",
            "repo:*?action=create&action=delete",
        );
        assert_eq!(result, "repo:app.bsky.feed.post");
    }

    #[test]
    fn test_intersect_multi_action_subset() {
        let result = intersect_scopes(
            "repo:*?action=create",
            "repo:*?action=create&action=update&action=delete",
        );
        assert_eq!(result, "repo:*?action=create");
    }

    #[test]
    fn test_scope_covers_base_only() {
        assert!(scope_covers("repo:*", "repo:app.bsky.feed.post"));
        assert!(scope_covers(
            "repo:*",
            "repo:app.bsky.feed.post?action=create"
        ));
        assert!(!scope_covers("blob:*/*", "repo:app.bsky.feed.post"));
    }

    #[test]
    fn test_scope_covers_params() {
        assert!(scope_covers("repo:*?action=create", "repo:*?action=create"));
        assert!(!scope_covers(
            "repo:*?action=create",
            "repo:*?action=delete"
        ));
        assert!(scope_covers(
            "repo:*?action=create&action=delete",
            "repo:*?action=create"
        ));
        assert!(!scope_covers(
            "repo:*?action=create",
            "repo:*?action=create&action=delete"
        ));
    }

    #[test]
    fn test_scope_covers_no_granted_params_means_all() {
        assert!(scope_covers("repo:*", "repo:*?action=create"));
        assert!(scope_covers("repo:*", "repo:*?action=delete"));
    }

    #[test]
    fn test_validate_scopes_valid() {
        assert!(ValidatedDelegationScope::new("atproto").is_ok());
        assert!(ValidatedDelegationScope::new("repo:* blob:*/*").is_ok());
        assert!(ValidatedDelegationScope::new("").is_ok());
    }

    #[test]
    fn test_validate_scopes_invalid() {
        assert!(ValidatedDelegationScope::new("invalid:scope").is_err());
    }

    #[test]
    fn test_scope_presets_parse() {
        SCOPE_PRESETS.iter().for_each(|p| {
            ValidatedDelegationScope::new(p.scopes).unwrap_or_else(|e| {
                panic!(
                    "preset '{}' has invalid scopes '{}': {}",
                    p.name, p.scopes, e
                )
            });
        });
    }
}
