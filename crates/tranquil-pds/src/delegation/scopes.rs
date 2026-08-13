use std::collections::BTreeSet;

use tranquil_scopes::{Coverage, ParsedScope, coverage, parse_scope};

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

pub const OWNER_FULL_SCOPES: &str = "atproto repo:* blob:*/* identity:* account:*?action=manage";

pub const EDITOR_FULL_SCOPES: &str =
    "atproto repo:*?action=create repo:*?action=update repo:*?action=delete blob:*/*";

pub const SCOPE_PRESETS: &[ScopePreset] = &[
    ScopePreset {
        name: "owner",
        label: "Owner",
        description: "Full control including delegation management",
        scopes: OWNER_FULL_SCOPES,
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
        scopes: EDITOR_FULL_SCOPES,
    },
    ScopePreset {
        name: "viewer",
        label: "Viewer",
        description: "Read-only access",
        scopes: "",
    },
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantCoverage {
    Full,
    Narrowed(String),
    Withheld,
}

fn scope_coverage(granted: &[ParsedScope], scope: &str) -> GrantCoverage {
    if scope == "atproto" {
        return GrantCoverage::Full;
    }

    match coverage(granted, &parse_scope(scope)) {
        Coverage::Full => GrantCoverage::Full,
        Coverage::Narrowed(ParsedScope::Repo(repo)) => {
            GrantCoverage::Narrowed(repo.to_scope_string())
        }
        Coverage::Narrowed(_) => GrantCoverage::Full,
        Coverage::Withheld => GrantCoverage::Withheld,
    }
}

pub fn grant_coverage(granted: &str, scope: &str) -> GrantCoverage {
    scope_coverage(&parse_grant(granted), scope)
}

fn parse_grant(granted: &str) -> Vec<ParsedScope> {
    granted.split_whitespace().map(parse_scope).collect()
}

pub fn intersect_scopes(requested: &str, granted: &str) -> String {
    let granted_parsed = parse_grant(granted);

    let scopes: BTreeSet<String> = requested
        .split_whitespace()
        .filter_map(
            |requested_scope| match scope_coverage(&granted_parsed, requested_scope) {
                GrantCoverage::Full => Some(requested_scope.to_string()),
                GrantCoverage::Narrowed(narrowed) => Some(narrowed),
                GrantCoverage::Withheld => None,
            },
        )
        .collect();

    scopes.into_iter().collect::<Vec<String>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_intersect_both_atproto() {
        assert_eq!(intersect_scopes("atproto", "atproto"), "atproto");
    }

    #[test]
    fn test_intersect_owner_grant_covers_requested() {
        let result = intersect_scopes("repo:* blob:*/*", OWNER_FULL_SCOPES);
        assert!(result.contains("repo:*"));
        assert!(result.contains("blob:*/*"));
    }

    #[test]
    fn test_intersect_bare_atproto_grant_is_auth_only() {
        let requested = "atproto repo:*?action=create blob:*/*";
        assert_eq!(intersect_scopes(requested, "atproto"), "atproto");
    }

    #[test]
    fn test_intersect_bare_atproto_request_is_auth_only() {
        assert_eq!(intersect_scopes("atproto", "repo:* blob:*/*"), "atproto");
    }

    #[test]
    fn test_intersect_downscoped_request_keeps_atproto() {
        let approved = "atproto repo:*?action=create blob:*/* account:*?action=manage";
        let result = intersect_scopes(approved, OWNER_FULL_SCOPES);
        assert!(result.split_whitespace().any(|s| s == "atproto"));
        assert!(result.contains("account:*?action=manage"));
        assert!(result.contains("repo:*?action=create"));
        assert!(result.contains("blob:*/*"));
        assert!(!result.contains("identity"));
    }

    #[test]
    fn test_intersect_owner_passes_through_identity() {
        let requested = "atproto repo:*?action=create identity:* account:*?action=manage";
        let result = intersect_scopes(requested, OWNER_FULL_SCOPES);
        assert!(result.contains("identity:*"));
        assert!(result.contains("account:*?action=manage"));
    }

    #[test]
    fn test_intersect_admin_excludes_identity() {
        let requested = "atproto repo:*?action=create identity:* account:*?action=manage";
        let granted = "atproto repo:* blob:*/* account:*?action=manage";
        let result = intersect_scopes(requested, granted);
        assert!(!result.contains("identity"));
        assert!(result.contains("account:*?action=manage"));
    }

    #[test]
    fn test_intersect_admin_excludes_identity_coverage_path() {
        let requested = "repo:*?action=create identity:* account:*?action=manage";
        let granted = "atproto repo:* blob:*/* account:*?action=manage";
        let result = intersect_scopes(requested, granted);
        assert!(!result.contains("identity"));
        assert!(result.contains("account:*?action=manage"));
        assert!(result.contains("repo:*?action=create"));
    }

    #[test]
    fn test_intersect_editor_grant_keeps_atproto() {
        let editor = SCOPE_PRESETS
            .iter()
            .find(|p| p.name == "editor")
            .expect("editor preset")
            .scopes;
        let requested = "atproto repo:*?action=create identity:* account:*?action=manage blob:*/*";
        let result = intersect_scopes(requested, editor);
        assert!(result.split_whitespace().any(|s| s == "atproto"));
        assert!(result.contains("repo:*?action=create"));
        assert!(result.contains("blob:*/*"));
        assert!(!result.contains("identity"));
        assert!(!result.contains("account"));
    }

    #[test]
    fn test_intersect_guarantees_atproto_for_custom_grant() {
        let result = intersect_scopes(
            "atproto repo:*?action=create blob:*/*",
            "repo:*?action=create blob:*/*",
        );
        assert!(result.split_whitespace().any(|s| s == "atproto"));
        assert!(result.contains("blob:*/*"));
    }

    #[test]
    fn test_intersect_no_atproto_request_stays_empty_when_uncovered() {
        assert_eq!(intersect_scopes("identity:*", "repo:* blob:*/*"), "");
    }

    #[test]
    fn test_intersect_exact_match() {
        assert_eq!(
            intersect_scopes("repo:*?action=create", "repo:*?action=create"),
            "repo:*?action=create"
        );
    }

    #[test]
    fn test_intersect_viewer_grant_keeps_atproto() {
        let requested = "atproto repo:*?action=create blob:*/* identity:*";
        assert_eq!(intersect_scopes(requested, ""), "atproto");
    }

    #[test]
    fn test_intersect_empty_grant_without_atproto_request_is_empty() {
        assert_eq!(intersect_scopes("repo:*?action=create", ""), "");
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
    fn test_intersect_partial_action_grant_narrows_actionless_request() {
        let result = intersect_scopes(
            "repo:app.bsky.feed.post",
            "repo:*?action=create&action=delete",
        );
        assert_eq!(
            result,
            "repo:app.bsky.feed.post?action=create&action=delete"
        );
    }

    #[test]
    fn test_intersect_keeps_collapsed_request_under_split_action_grant() {
        assert_eq!(
            intersect_scopes(
                "repo:io.atcr.manifest?action=create&action=delete",
                EDITOR_FULL_SCOPES
            ),
            "repo:io.atcr.manifest?action=create&action=delete"
        );
        assert_eq!(
            intersect_scopes(
                "repo:io.atcr.manifest?action=create&action=delete",
                "repo:*?action=create"
            ),
            "repo:io.atcr.manifest?action=create"
        );
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

    #[test]
    fn test_grant_coverage_full_and_withheld() {
        let granted = "atproto repo:* blob:*/* account:*?action=manage";
        assert_eq!(grant_coverage(granted, "atproto"), GrantCoverage::Full);
        assert_eq!(
            grant_coverage(granted, "repo:app.bsky.feed.post?action=create"),
            GrantCoverage::Full
        );
        assert_eq!(
            grant_coverage(granted, "identity:*"),
            GrantCoverage::Withheld
        );
        assert_eq!(grant_coverage("", "identity:*"), GrantCoverage::Withheld);
    }

    #[test]
    fn test_grant_coverage_narrowed_when_grant_is_a_strict_action_subset() {
        assert_eq!(
            grant_coverage(
                EDITOR_FULL_SCOPES,
                "repo:io.atcr.manifest?action=create&action=delete"
            ),
            GrantCoverage::Full
        );
        assert_eq!(
            grant_coverage(
                "atproto repo:*?action=create blob:*/*",
                "repo:io.atcr.manifest?action=create&action=delete"
            ),
            GrantCoverage::Narrowed("repo:io.atcr.manifest?action=create".to_string())
        );
    }
}
