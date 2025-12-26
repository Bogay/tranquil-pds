use std::collections::HashSet;

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

    if granted_has_atproto && requested_has_atproto {
        return "atproto".to_string();
    }

    if granted_has_atproto {
        return requested_set.into_iter().collect::<Vec<_>>().join(" ");
    }

    if requested_has_atproto {
        return granted_set.into_iter().collect::<Vec<_>>().join(" ");
    }

    let mut result: Vec<&str> = Vec::new();

    for requested_scope in &requested_set {
        if granted_set.contains(requested_scope) {
            result.push(requested_scope);
            continue;
        }

        if let Some(match_result) = find_matching_scope(requested_scope, &granted_set) {
            result.push(match_result);
        }
    }

    result.sort();
    result.join(" ")
}

fn find_matching_scope<'a>(requested: &str, granted: &HashSet<&'a str>) -> Option<&'a str> {
    for granted_scope in granted {
        if scopes_compatible(granted_scope, requested) {
            return Some(granted_scope);
        }
    }
    None
}

fn scopes_compatible(granted: &str, requested: &str) -> bool {
    if granted == requested {
        return true;
    }

    let (granted_base, _granted_params) = split_scope(granted);
    let (requested_base, _requested_params) = split_scope(requested);

    if granted_base.ends_with(":*")
        && requested_base.starts_with(&granted_base[..granted_base.len() - 1])
    {
        return true;
    }

    if granted_base.ends_with(".*") {
        let prefix = &granted_base[..granted_base.len() - 2];
        if requested_base.starts_with(prefix) && requested_base.len() > prefix.len() {
            return true;
        }
    }

    false
}

fn split_scope(scope: &str) -> (&str, Option<&str>) {
    if let Some(idx) = scope.find('?') {
        (&scope[..idx], Some(&scope[idx + 1..]))
    } else {
        (scope, None)
    }
}

pub fn validate_delegation_scopes(scopes: &str) -> Result<(), String> {
    if scopes.is_empty() {
        return Ok(());
    }

    for scope in scopes.split_whitespace() {
        let (base, _) = split_scope(scope);

        if !is_valid_scope_prefix(base) {
            return Err(format!("Invalid scope: {}", scope));
        }
    }

    Ok(())
}

fn is_valid_scope_prefix(base: &str) -> bool {
    let valid_prefixes = [
        "atproto",
        "repo:",
        "blob:",
        "rpc:",
        "account:",
        "identity:",
        "transition:",
    ];

    for prefix in valid_prefixes {
        if base == prefix.trim_end_matches(':') || base.starts_with(prefix) {
            return true;
        }
    }

    false
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
    fn test_validate_scopes_valid() {
        assert!(validate_delegation_scopes("atproto").is_ok());
        assert!(validate_delegation_scopes("repo:* blob:*/*").is_ok());
        assert!(validate_delegation_scopes("").is_ok());
    }

    #[test]
    fn test_validate_scopes_invalid() {
        assert!(validate_delegation_scopes("invalid:scope").is_err());
    }
}
