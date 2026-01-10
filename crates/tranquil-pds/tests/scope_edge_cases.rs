use tranquil_pds::delegation::{intersect_scopes, scopes::validate_delegation_scopes};
use tranquil_pds::oauth::scopes::{
    AccountAction, IdentityAttr, ParsedScope, RepoAction, ScopePermissions, parse_scope,
    parse_scope_string,
};

#[test]
fn test_repo_star_defaults_to_all_actions() {
    let scope = parse_scope("repo:*");
    if let ParsedScope::Repo(repo) = scope {
        assert!(repo.actions.contains(&RepoAction::Create));
        assert!(repo.actions.contains(&RepoAction::Update));
        assert!(repo.actions.contains(&RepoAction::Delete));
        assert_eq!(repo.actions.len(), 3);
    } else {
        panic!("Expected Repo scope");
    }
}

#[test]
fn test_repo_collection_without_actions_defaults_to_all() {
    let scope = parse_scope("repo:app.bsky.feed.post");
    if let ParsedScope::Repo(repo) = scope {
        assert!(repo.actions.contains(&RepoAction::Create));
        assert!(repo.actions.contains(&RepoAction::Update));
        assert!(repo.actions.contains(&RepoAction::Delete));
    } else {
        panic!("Expected Repo scope");
    }
}

#[test]
fn test_repo_empty_string_after_colon() {
    let scope = parse_scope("repo:");
    if let ParsedScope::Repo(repo) = scope {
        assert!(repo.collection.is_none());
    } else {
        panic!("Expected Repo scope");
    }
}

#[test]
fn test_rpc_wildcard_aud_wildcard_forbidden() {
    let scope = parse_scope("rpc:*?aud=*");
    assert!(matches!(scope, ParsedScope::Unknown(_)));
}

#[test]
fn test_rpc_no_lxm_aud_wildcard_forbidden() {
    let scope = parse_scope("rpc?aud=*");
    assert!(matches!(scope, ParsedScope::Unknown(_)));
}

#[test]
fn test_rpc_specific_lxm_wildcard_aud_allowed() {
    let scope = parse_scope("rpc:app.bsky.feed.getTimeline?aud=*");
    assert!(matches!(scope, ParsedScope::Rpc(_)));
}

#[test]
fn test_rpc_wildcard_lxm_specific_aud_allowed() {
    let scope = parse_scope("rpc:*?aud=did:web:api.bsky.app");
    assert!(matches!(scope, ParsedScope::Rpc(_)));
}

#[test]
fn test_unknown_scope_preserved() {
    let scope = parse_scope("completely:made:up:scope");
    if let ParsedScope::Unknown(s) = scope {
        assert_eq!(s, "completely:made:up:scope");
    } else {
        panic!("Expected Unknown scope");
    }
}

#[test]
fn test_unknown_scope_with_params_preserved() {
    let scope = parse_scope("unknown:thing?param=value");
    if let ParsedScope::Unknown(s) = scope {
        assert_eq!(s, "unknown:thing?param=value");
    } else {
        panic!("Expected Unknown scope");
    }
}

#[test]
fn test_blob_empty_accept() {
    let scope = parse_scope("blob");
    if let ParsedScope::Blob(blob) = scope {
        assert!(blob.accept.is_empty());
        assert!(blob.matches_mime("anything/goes"));
    } else {
        panic!("Expected Blob scope");
    }
}

#[test]
fn test_blob_matches_wildcard() {
    let scope = parse_scope("blob:*/*");
    if let ParsedScope::Blob(blob) = scope {
        assert!(blob.matches_mime("image/png"));
        assert!(blob.matches_mime("video/mp4"));
        assert!(blob.matches_mime("application/json"));
    } else {
        panic!("Expected Blob scope");
    }
}

#[test]
fn test_blob_type_prefix_matching() {
    let scope = parse_scope("blob:image/*");
    if let ParsedScope::Blob(blob) = scope {
        assert!(blob.matches_mime("image/png"));
        assert!(blob.matches_mime("image/jpeg"));
        assert!(blob.matches_mime("image/gif"));
        assert!(!blob.matches_mime("video/mp4"));
        assert!(!blob.matches_mime("images/png"));
    } else {
        panic!("Expected Blob scope");
    }
}

#[test]
fn test_account_default_action_is_read() {
    let scope = parse_scope("account:email");
    if let ParsedScope::Account(a) = scope {
        assert_eq!(a.action, AccountAction::Read);
    } else {
        panic!("Expected Account scope");
    }
}

#[test]
fn test_multiple_scopes_parsing() {
    let scopes = parse_scope_string("atproto repo:* blob:*/* transition:generic");
    assert_eq!(scopes.len(), 4);
    assert!(matches!(scopes[0], ParsedScope::Atproto));
}

#[test]
fn test_permissions_null_scope_defaults_atproto() {
    let perms = ScopePermissions::from_scope_string(None);
    assert!(perms.has_full_access());
    assert!(perms.allows_repo(RepoAction::Create, "any.collection"));
    assert!(perms.allows_repo(RepoAction::Update, "any.collection"));
    assert!(perms.allows_repo(RepoAction::Delete, "any.collection"));
}

#[test]
fn test_permissions_empty_string_defaults_atproto() {
    let perms = ScopePermissions::from_scope_string(Some(""));
    assert!(!perms.has_full_access());
}

#[test]
fn test_permissions_whitespace_only() {
    let perms = ScopePermissions::from_scope_string(Some("   "));
    assert!(!perms.has_full_access());
}

#[test]
fn test_permissions_repo_collection_wildcard_prefix() {
    let perms = ScopePermissions::from_scope_string(Some("repo:app.bsky.*?action=create"));
    assert!(perms.allows_repo(RepoAction::Create, "app.bsky.feed.post"));
    assert!(perms.allows_repo(RepoAction::Create, "app.bsky.actor.profile"));
    assert!(!perms.allows_repo(RepoAction::Create, "com.atproto.repo.blob"));
    assert!(!perms.allows_repo(RepoAction::Update, "app.bsky.feed.post"));
}

#[test]
fn test_permissions_rpc_lxm_wildcard_prefix() {
    let perms =
        ScopePermissions::from_scope_string(Some("rpc:app.bsky.feed.*?aud=did:web:api.bsky.app"));
    assert!(perms.allows_rpc("did:web:api.bsky.app", "app.bsky.feed.getTimeline"));
    assert!(perms.allows_rpc("did:web:api.bsky.app", "app.bsky.feed.getAuthorFeed"));
    assert!(!perms.allows_rpc("did:web:api.bsky.app", "app.bsky.actor.getProfile"));
}

#[test]
fn test_delegation_intersect_params_behavior() {
    let result = intersect_scopes("repo:*?action=create", "repo:*?action=delete");

    assert!(
        result.is_empty() || result.contains("repo:*"),
        "Delegation intersection with different action params: '{}'",
        result
    );
}

#[test]
fn test_delegation_intersect_wildcard_vs_specific() {
    let result = intersect_scopes("repo:app.bsky.feed.post?action=create", "repo:*");
    assert!(result.contains("repo:"));
}

#[test]
fn test_delegation_validate_known_prefixes() {
    assert!(validate_delegation_scopes("atproto").is_ok());
    assert!(validate_delegation_scopes("repo:*").is_ok());
    assert!(validate_delegation_scopes("blob:*/*").is_ok());
    assert!(validate_delegation_scopes("rpc:*").is_ok());
    assert!(validate_delegation_scopes("account:email").is_ok());
    assert!(validate_delegation_scopes("identity:handle").is_ok());
    assert!(validate_delegation_scopes("transition:generic").is_ok());
}

#[test]
fn test_delegation_validate_unknown_prefixes() {
    assert!(validate_delegation_scopes("invalid:scope").is_err());
    assert!(validate_delegation_scopes("custom:something").is_err());
    assert!(validate_delegation_scopes("made:up").is_err());
}

#[test]
fn test_delegation_validate_empty() {
    assert!(validate_delegation_scopes("").is_ok());
}

#[test]
fn test_delegation_validate_multiple() {
    assert!(validate_delegation_scopes("atproto repo:* blob:*/*").is_ok());
    assert!(validate_delegation_scopes("atproto invalid:scope").is_err());
}

#[test]
fn test_delegation_intersect_empty_granted_returns_empty() {
    assert_eq!(intersect_scopes("atproto", ""), "");
    assert_eq!(intersect_scopes("repo:*", ""), "");
}

#[test]
fn test_delegation_intersect_no_overlap() {
    let result = intersect_scopes("repo:app.bsky.feed.post", "repo:com.atproto.something");
    assert!(result.is_empty());
}

#[test]
fn test_scope_with_multiple_params() {
    let scope = parse_scope("repo:*?action=create&action=delete");
    if let ParsedScope::Repo(repo) = scope {
        assert!(repo.actions.contains(&RepoAction::Create));
        assert!(repo.actions.contains(&RepoAction::Delete));
        assert!(!repo.actions.contains(&RepoAction::Update));
    } else {
        panic!("Expected Repo scope");
    }
}

#[test]
fn test_scope_invalid_action_ignored() {
    let scope = parse_scope("repo:*?action=invalid");
    if let ParsedScope::Repo(repo) = scope {
        assert!(repo.actions.contains(&RepoAction::Create));
        assert!(repo.actions.contains(&RepoAction::Update));
        assert!(repo.actions.contains(&RepoAction::Delete));
    } else {
        panic!("Expected Repo scope");
    }
}

#[test]
fn test_include_scope_parsing() {
    let scope = parse_scope("include:app.bsky.authFullApp?aud=did:web:api.bsky.app");
    if let ParsedScope::Include(inc) = scope {
        assert_eq!(inc.nsid, "app.bsky.authFullApp");
        assert_eq!(inc.aud, Some("did:web:api.bsky.app".to_string()));
    } else {
        panic!("Expected Include scope");
    }
}

#[test]
fn test_include_scope_no_aud() {
    let scope = parse_scope("include:com.example.authBasic");
    if let ParsedScope::Include(inc) = scope {
        assert_eq!(inc.nsid, "com.example.authBasic");
        assert!(inc.aud.is_none());
    } else {
        panic!("Expected Include scope");
    }
}

#[test]
fn test_identity_wildcard_vs_specific() {
    let wildcard = parse_scope("identity:*");
    let specific = parse_scope("identity:handle");

    assert!(matches!(wildcard, ParsedScope::Identity(i) if i.attr == IdentityAttr::Wildcard));
    assert!(matches!(specific, ParsedScope::Identity(i) if i.attr == IdentityAttr::Handle));
}

#[test]
fn test_identity_unknown_attr() {
    let scope = parse_scope("identity:unknown");
    assert!(matches!(scope, ParsedScope::Unknown(_)));
}

#[test]
fn test_transition_scopes_exact_match() {
    assert!(matches!(
        parse_scope("transition:generic"),
        ParsedScope::TransitionGeneric
    ));
    assert!(matches!(
        parse_scope("transition:chat.bsky"),
        ParsedScope::TransitionChat
    ));
    assert!(matches!(
        parse_scope("transition:email"),
        ParsedScope::TransitionEmail
    ));
    assert!(matches!(
        parse_scope("transition:unknown"),
        ParsedScope::Unknown(_)
    ));
}
