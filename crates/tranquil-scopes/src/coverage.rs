use crate::parser::{
    AccountAction, AccountAttr, AccountScope, BlobScope, IdentityAttr, IdentityScope, ParsedScope,
    RepoScope, RpcScope,
};

pub fn covers(granted: &ParsedScope, requested: &ParsedScope) -> bool {
    use ParsedScope::*;
    match (granted, requested) {
        (Atproto, Atproto) => true,
        (TransitionGeneric, TransitionGeneric) => true,
        (TransitionChat, TransitionChat) => true,
        (TransitionEmail, TransitionEmail) => true,
        (Repo(g), Repo(r)) => repo_covers(g, r),
        (Blob(g), Blob(r)) => blob_covers(g, r),
        (Rpc(g), Rpc(r)) => rpc_covers(g, r),
        (Account(g), Account(r)) => account_covers(g, r),
        (Identity(g), Identity(r)) => identity_covers(g, r),
        (Include(g), Include(r)) => g.nsid == r.nsid && g.aud == r.aud,
        (Unknown(g), Unknown(r)) => g == r,
        _ => false,
    }
}

fn repo_covers(g: &RepoScope, r: &RepoScope) -> bool {
    let collection_ok = match &g.collection {
        None => true,
        Some(gc) => match &r.collection {
            None => false,
            Some(rc) => match gc.strip_suffix(".*") {
                Some(prefix) => {
                    rc.starts_with(prefix) && rc.as_bytes().get(prefix.len()) == Some(&b'.')
                }
                None => gc == rc,
            },
        },
    };
    collection_ok && r.actions.is_subset(&g.actions)
}

fn blob_covers(g: &BlobScope, r: &BlobScope) -> bool {
    if g.accept.is_empty() || g.accept.contains("*/*") {
        return true;
    }
    !r.accept.is_empty() && r.accept.iter().all(|pat| g.matches_mime(pat))
}

fn rpc_covers(g: &RpcScope, r: &RpcScope) -> bool {
    let lxm_ok = match &g.lxm {
        None => true,
        Some(gl) if gl == "*" => true,
        Some(gl) => r.lxm.as_deref() == Some(gl.as_str()),
    };
    let aud_ok = match &g.aud {
        None => true,
        Some(ga) if ga == "*" => true,
        Some(ga) => r.aud.as_deref() == Some(ga.as_str()),
    };
    lxm_ok && aud_ok
}

fn account_covers(g: &AccountScope, r: &AccountScope) -> bool {
    let attr_ok = g.attr == AccountAttr::Wildcard || g.attr == r.attr;
    let action_ok = match (g.action, r.action) {
        (AccountAction::Manage, _) => true,
        (AccountAction::Read, AccountAction::Read) => true,
        (AccountAction::Read, AccountAction::Manage) => false,
    };
    attr_ok && action_ok
}

fn identity_covers(g: &IdentityScope, r: &IdentityScope) -> bool {
    g.attr == IdentityAttr::Wildcard || g.attr == r.attr
}

#[cfg(test)]
mod tests {
    use super::covers;
    use crate::parser::parse_scope;

    fn c(granted: &str, requested: &str) -> bool {
        covers(&parse_scope(granted), &parse_scope(requested))
    }

    #[test]
    fn repo_wildcard_covers_specific() {
        assert!(c("repo:*", "repo:app.bsky.feed.post"));
        assert!(c("repo:*", "repo:app.bsky.feed.post?action=create"));
    }

    #[test]
    fn repo_specific_does_not_cover_wildcard() {
        assert!(!c("repo:app.bsky.feed.post", "repo:*"));
    }

    #[test]
    fn repo_action_subset_required() {
        assert!(c("repo:*", "repo:*?action=create"));
        assert!(!c("repo:*?action=create", "repo:*?action=delete"));
        assert!(c(
            "repo:*?action=create&action=delete",
            "repo:*?action=create"
        ));
        assert!(!c(
            "repo:*?action=create",
            "repo:*?action=create&action=delete"
        ));
    }

    #[test]
    fn repo_partial_action_grant_does_not_cover_actionless_request() {
        assert!(!c(
            "repo:*?action=create&action=delete",
            "repo:app.bsky.feed.post"
        ));
    }

    #[test]
    fn repo_collection_prefix_wildcard() {
        assert!(c("repo:app.bsky.*", "repo:app.bsky.feed.post"));
        assert!(!c("repo:app.bsky.*", "repo:app.bsky"));
        assert!(!c("repo:app.bsky.*", "repo:com.example.foo"));
    }

    #[test]
    fn blob_wildcard_covers_all() {
        assert!(c("blob:*/*", "blob:image/png"));
        assert!(c("blob:*/*", "blob:*/*"));
    }

    #[test]
    fn blob_type_prefix() {
        assert!(c("blob:image/*", "blob:image/png"));
        assert!(!c("blob:image/*", "blob:video/mp4"));
    }

    #[test]
    fn rpc_wildcards() {
        assert!(c("rpc:*?aud=did:web:x", "rpc:app.bsky.getX?aud=did:web:x"));
        assert!(c(
            "rpc:app.bsky.getX?aud=*",
            "rpc:app.bsky.getX?aud=did:web:x"
        ));
        assert!(!c(
            "rpc:app.bsky.getX?aud=did:web:x",
            "rpc:app.bsky.getY?aud=did:web:x"
        ));
    }

    #[test]
    fn account_manage_covers_read_and_wildcard_attr() {
        assert!(c("account:*?action=manage", "account:email?action=read"));
        assert!(c("account:*?action=manage", "account:email?action=manage"));
        assert!(!c(
            "account:email?action=read",
            "account:email?action=manage"
        ));
    }

    #[test]
    fn identity_wildcard_covers_handle() {
        assert!(c("identity:*", "identity:handle"));
        assert!(!c("identity:handle", "identity:*"));
    }

    #[test]
    fn cross_type_never_covers() {
        assert!(!c("repo:*", "blob:*/*"));
        assert!(!c("blob:*/*", "repo:app.bsky.feed.post"));
    }

    #[test]
    fn atproto_and_transition_self_cover() {
        assert!(c("atproto", "atproto"));
        assert!(c("transition:generic", "transition:generic"));
        assert!(!c("transition:generic", "atproto"));
    }

    #[test]
    fn repo_prefix_wildcard_respects_dot_boundary() {
        assert!(!c("repo:app.bsky.*", "repo:app.bskyEXTRA"));
        assert!(c("repo:app.bsky.*", "repo:app.bsky.feed.post"));
        assert!(!c("repo:app.bsky.*", "repo:app.bsky"));
    }

    #[test]
    fn include_exact_match_only() {
        assert!(c("include:io.x.set", "include:io.x.set"));
        assert!(!c("include:io.x.set", "include:io.y.set"));
    }

    #[test]
    fn unknown_exact_match_only() {
        assert!(c("weird:token", "weird:token"));
        assert!(!c("weird:token", "other:token"));
    }
}
