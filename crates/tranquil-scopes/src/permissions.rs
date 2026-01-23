use super::error::ScopeError;
use super::parser::{
    AccountAction, AccountAttr, BlobScope, IdentityAttr, IdentityScope, ParsedScope, RepoAction,
    RepoScope, RpcScope, parse_scope_string,
};
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct ScopePermissions {
    scopes: HashSet<String>,
    parsed: Vec<ParsedScope>,
    has_transition_generic: bool,
    has_transition_chat: bool,
    has_transition_email: bool,
}

impl ScopePermissions {
    pub fn from_scope_string(scope: Option<&str>) -> Self {
        let scope_str = scope.unwrap_or("atproto");
        let scopes: HashSet<String> = scope_str
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();

        let parsed = parse_scope_string(scope_str);

        let has_atproto = parsed.iter().any(|p| matches!(p, ParsedScope::Atproto));
        let mut has_transition_generic = parsed
            .iter()
            .any(|p| matches!(p, ParsedScope::TransitionGeneric));
        let has_transition_chat = parsed
            .iter()
            .any(|p| matches!(p, ParsedScope::TransitionChat));
        let has_transition_email = parsed
            .iter()
            .any(|p| matches!(p, ParsedScope::TransitionEmail));

        let has_granular_scopes = parsed.iter().any(|p| {
            matches!(
                p,
                ParsedScope::Repo(_)
                    | ParsedScope::Blob(_)
                    | ParsedScope::Rpc(_)
                    | ParsedScope::Account(_)
                    | ParsedScope::Identity(_)
            )
        });

        if has_atproto && !has_granular_scopes {
            has_transition_generic = true;
        }

        Self {
            scopes,
            parsed,
            has_transition_generic,
            has_transition_chat,
            has_transition_email,
        }
    }

    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.contains(scope)
    }

    pub fn scopes(&self) -> &HashSet<String> {
        &self.scopes
    }

    pub fn has_full_access(&self) -> bool {
        self.has_transition_generic
    }

    fn find_repo_scopes(&self) -> impl Iterator<Item = &RepoScope> {
        self.parsed.iter().filter_map(|p| {
            if let ParsedScope::Repo(r) = p {
                Some(r)
            } else {
                None
            }
        })
    }

    fn find_blob_scopes(&self) -> impl Iterator<Item = &BlobScope> {
        self.parsed.iter().filter_map(|p| {
            if let ParsedScope::Blob(b) = p {
                Some(b)
            } else {
                None
            }
        })
    }

    fn find_rpc_scopes(&self) -> impl Iterator<Item = &RpcScope> {
        self.parsed.iter().filter_map(|p| {
            if let ParsedScope::Rpc(r) = p {
                Some(r)
            } else {
                None
            }
        })
    }

    fn find_account_scopes(&self) -> impl Iterator<Item = &super::parser::AccountScope> {
        self.parsed.iter().filter_map(|p| {
            if let ParsedScope::Account(a) = p {
                Some(a)
            } else {
                None
            }
        })
    }

    fn find_identity_scopes(&self) -> impl Iterator<Item = &IdentityScope> {
        self.parsed.iter().filter_map(|p| {
            if let ParsedScope::Identity(i) = p {
                Some(i)
            } else {
                None
            }
        })
    }

    pub fn assert_repo(&self, action: RepoAction, collection: &str) -> Result<(), ScopeError> {
        if self.has_transition_generic {
            return Ok(());
        }

        let has_repo_permission = self.find_repo_scopes().any(|repo_scope| {
            repo_scope.actions.contains(&action)
                && match &repo_scope.collection {
                    None => true,
                    Some(coll) if coll == collection => true,
                    Some(coll) if coll.ends_with(".*") => {
                        let prefix = coll.strip_suffix(".*").unwrap();
                        collection.starts_with(prefix)
                            && collection.chars().nth(prefix.len()) == Some('.')
                    }
                    _ => false,
                }
        });

        if has_repo_permission {
            Ok(())
        } else {
            Err(ScopeError::InsufficientScope {
                required: format!("repo:{}?action={}", collection, action_str(action)),
                message: format!(
                    "Insufficient scope to {} records in {}",
                    action_str(action),
                    collection
                ),
            })
        }
    }

    pub fn assert_blob(&self, mime: &str) -> Result<(), ScopeError> {
        if self.has_transition_generic {
            return Ok(());
        }

        if self
            .find_blob_scopes()
            .any(|blob_scope| blob_scope.matches_mime(mime))
        {
            Ok(())
        } else {
            Err(ScopeError::InsufficientScope {
                required: format!("blob:{}", mime),
                message: format!("Insufficient scope to upload blob with mime type {}", mime),
            })
        }
    }

    pub fn assert_rpc(&self, aud: &str, lxm: &str) -> Result<(), ScopeError> {
        if self.has_transition_generic {
            return Ok(());
        }

        if lxm.starts_with("chat.bsky.") && self.has_transition_chat {
            return Ok(());
        }

        let aud_base = aud.split('#').next().unwrap_or(aud);

        let has_permission = self.find_rpc_scopes().any(|rpc_scope| {
            let lxm_matches = match &rpc_scope.lxm {
                None => true,
                Some(scope_lxm) if scope_lxm == lxm => true,
                Some(scope_lxm) if scope_lxm.ends_with(".*") => {
                    let prefix = scope_lxm.strip_suffix(".*").unwrap();
                    lxm.starts_with(prefix) && lxm.chars().nth(prefix.len()) == Some('.')
                }
                _ => false,
            };

            let aud_matches = match &rpc_scope.aud {
                None => true,
                Some(scope_aud) if scope_aud == "*" => true,
                Some(scope_aud) => {
                    let scope_aud_base = scope_aud.split('#').next().unwrap_or(scope_aud);
                    scope_aud_base == aud_base
                }
            };

            lxm_matches && aud_matches
        });

        if has_permission {
            Ok(())
        } else {
            Err(ScopeError::InsufficientScope {
                required: format!("rpc:{}?aud={}", lxm, aud),
                message: format!("Insufficient scope to call {} on {}", lxm, aud),
            })
        }
    }

    pub fn assert_account(
        &self,
        attr: AccountAttr,
        action: AccountAction,
    ) -> Result<(), ScopeError> {
        if self.has_transition_generic {
            return Ok(());
        }

        if attr == AccountAttr::Email && action == AccountAction::Read && self.has_transition_email
        {
            return Ok(());
        }

        let has_permission = self.find_account_scopes().any(|account_scope| {
            (account_scope.attr == attr || account_scope.attr == AccountAttr::Wildcard)
                && (account_scope.action == action || account_scope.action == AccountAction::Manage)
        });

        if has_permission {
            Ok(())
        } else {
            Err(ScopeError::InsufficientScope {
                required: format!(
                    "account:{}?action={}",
                    attr_str(attr),
                    action_str_account(action)
                ),
                message: format!(
                    "Insufficient scope to {} account {}",
                    action_str_account(action),
                    attr_str(attr)
                ),
            })
        }
    }

    pub fn allows_email_read(&self) -> bool {
        self.has_transition_generic
            || self.has_transition_email
            || self
                .find_account_scopes()
                .any(|a| a.attr == AccountAttr::Email || a.attr == AccountAttr::Wildcard)
    }

    pub fn allows_repo(&self, action: RepoAction, collection: &str) -> bool {
        self.assert_repo(action, collection).is_ok()
    }

    pub fn allows_blob(&self, mime: &str) -> bool {
        self.assert_blob(mime).is_ok()
    }

    pub fn allows_rpc(&self, aud: &str, lxm: &str) -> bool {
        self.assert_rpc(aud, lxm).is_ok()
    }

    pub fn allows_account(&self, attr: AccountAttr, action: AccountAction) -> bool {
        self.assert_account(attr, action).is_ok()
    }

    pub fn assert_identity(&self, attr: IdentityAttr) -> Result<(), ScopeError> {
        if self.has_transition_generic {
            return Ok(());
        }

        let has_permission = self.find_identity_scopes().any(|identity_scope| {
            identity_scope.attr == IdentityAttr::Wildcard || identity_scope.attr == attr
        });

        if has_permission {
            Ok(())
        } else {
            Err(ScopeError::InsufficientScope {
                required: format!("identity:{}", identity_attr_str(attr)),
                message: format!(
                    "Insufficient scope to modify identity {}",
                    identity_attr_str(attr)
                ),
            })
        }
    }

    pub fn allows_identity(&self, attr: IdentityAttr) -> bool {
        self.assert_identity(attr).is_ok()
    }
}

fn action_str(action: RepoAction) -> &'static str {
    match action {
        RepoAction::Create => "create",
        RepoAction::Update => "update",
        RepoAction::Delete => "delete",
    }
}

fn attr_str(attr: AccountAttr) -> &'static str {
    match attr {
        AccountAttr::Email => "email",
        AccountAttr::Handle => "handle",
        AccountAttr::Repo => "repo",
        AccountAttr::Status => "status",
        AccountAttr::Wildcard => "*",
    }
}

fn identity_attr_str(attr: IdentityAttr) -> &'static str {
    match attr {
        IdentityAttr::Handle => "handle",
        IdentityAttr::Wildcard => "*",
    }
}

fn action_str_account(action: AccountAction) -> &'static str {
    match action {
        AccountAction::Read => "read",
        AccountAction::Manage => "manage",
    }
}

impl Default for ScopePermissions {
    fn default() -> Self {
        Self::from_scope_string(Some("atproto"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_atproto_scope_allows_everything() {
        let perms = ScopePermissions::from_scope_string(Some("atproto"));
        assert!(perms.has_full_access());
        assert!(perms.allows_repo(RepoAction::Create, "app.bsky.feed.post"));
        assert!(perms.allows_blob("image/png"));
        assert!(perms.allows_rpc("did:web:api.bsky.app", "app.bsky.feed.getTimeline"));
        assert!(perms.allows_account(AccountAttr::Email, AccountAction::Manage));
    }

    #[test]
    fn test_transition_generic_allows_everything() {
        let perms = ScopePermissions::from_scope_string(Some("transition:generic"));
        assert!(perms.allows_repo(RepoAction::Create, "app.bsky.feed.post"));
        assert!(perms.allows_blob("image/png"));
    }

    #[test]
    fn test_transition_chat_only_allows_chat() {
        let perms = ScopePermissions::from_scope_string(Some("transition:chat.bsky"));
        assert!(!perms.allows_repo(RepoAction::Create, "app.bsky.feed.post"));
        assert!(perms.allows_rpc("did:web:api.bsky.app", "chat.bsky.convo.getMessages"));
        assert!(!perms.allows_rpc("did:web:api.bsky.app", "app.bsky.feed.getTimeline"));
    }

    #[test]
    fn test_empty_scope_defaults_to_atproto() {
        let perms = ScopePermissions::from_scope_string(None);
        assert!(perms.has_full_access());
    }

    #[test]
    fn test_multiple_scopes() {
        let perms = ScopePermissions::from_scope_string(Some("atproto transition:chat.bsky"));
        assert!(perms.has_scope("atproto"));
        assert!(perms.has_scope("transition:chat.bsky"));
        assert!(!perms.has_scope("transition:generic"));
    }

    #[test]
    fn test_transition_email_allows_email_read() {
        let perms = ScopePermissions::from_scope_string(Some("transition:email"));
        assert!(perms.allows_email_read());
        assert!(perms.allows_account(AccountAttr::Email, AccountAction::Read));
        assert!(!perms.allows_account(AccountAttr::Email, AccountAction::Manage));
        assert!(!perms.allows_repo(RepoAction::Create, "app.bsky.feed.post"));
    }

    #[test]
    fn test_granular_repo_wildcard() {
        let perms =
            ScopePermissions::from_scope_string(Some("atproto repo:*?action=create blob:*/*"));
        assert!(perms.allows_repo(RepoAction::Create, "app.bsky.feed.post"));
        assert!(perms.allows_repo(RepoAction::Create, "any.collection"));
        assert!(perms.allows_blob("image/png"));
    }

    #[test]
    fn test_granular_repo_collection_specific() {
        let perms = ScopePermissions::from_scope_string(Some(
            "repo:app.bsky.feed.post?action=create&action=delete",
        ));
        assert!(perms.allows_repo(RepoAction::Create, "app.bsky.feed.post"));
        assert!(perms.allows_repo(RepoAction::Delete, "app.bsky.feed.post"));
        assert!(!perms.allows_repo(RepoAction::Update, "app.bsky.feed.post"));
        assert!(!perms.allows_repo(RepoAction::Create, "app.bsky.feed.like"));
    }

    #[test]
    fn test_granular_blob_specific_mime() {
        let perms = ScopePermissions::from_scope_string(Some("blob?accept=image/*&accept=video/*"));
        assert!(perms.allows_blob("image/png"));
        assert!(perms.allows_blob("image/jpeg"));
        assert!(perms.allows_blob("video/mp4"));
        assert!(!perms.allows_blob("text/plain"));
        assert!(!perms.allows_blob("application/json"));
    }

    #[test]
    fn test_granular_rpc() {
        let perms = ScopePermissions::from_scope_string(Some(
            "rpc:app.bsky.feed.getTimeline?aud=did:web:api.bsky.app",
        ));
        assert!(perms.allows_rpc("did:web:api.bsky.app", "app.bsky.feed.getTimeline"));
        assert!(!perms.allows_rpc("did:web:api.bsky.app", "app.bsky.feed.getAuthorFeed"));
        assert!(!perms.allows_rpc("did:web:other.service", "app.bsky.feed.getTimeline"));
    }

    #[test]
    fn test_granular_rpc_wildcard_aud() {
        let perms =
            ScopePermissions::from_scope_string(Some("rpc:app.bsky.feed.getTimeline?aud=*"));
        assert!(perms.allows_rpc("did:web:api.bsky.app", "app.bsky.feed.getTimeline"));
        assert!(perms.allows_rpc("did:web:any.service", "app.bsky.feed.getTimeline"));
        assert!(!perms.allows_rpc("did:web:api.bsky.app", "app.bsky.feed.getAuthorFeed"));
    }

    #[test]
    fn test_granular_account() {
        let perms = ScopePermissions::from_scope_string(Some("account:email?action=read"));
        assert!(perms.allows_account(AccountAttr::Email, AccountAction::Read));
        assert!(!perms.allows_account(AccountAttr::Email, AccountAction::Manage));
        assert!(!perms.allows_account(AccountAttr::Handle, AccountAction::Read));

        let perms2 = ScopePermissions::from_scope_string(Some("account:repo?action=manage"));
        assert!(perms2.allows_account(AccountAttr::Repo, AccountAction::Manage));
        assert!(perms2.allows_account(AccountAttr::Repo, AccountAction::Read));
    }

    #[test]
    fn test_granular_scopes_without_atproto() {
        let perms = ScopePermissions::from_scope_string(Some("repo:*?action=create"));
        assert!(!perms.has_full_access());
        assert!(perms.allows_repo(RepoAction::Create, "any.collection"));
        assert!(!perms.allows_repo(RepoAction::Update, "any.collection"));
        assert!(!perms.allows_repo(RepoAction::Delete, "any.collection"));
    }

    #[test]
    fn test_pdsls_style_scopes() {
        let perms = ScopePermissions::from_scope_string(Some(
            "atproto repo:*?action=create repo:*?action=update repo:*?action=delete blob:*/*",
        ));
        assert!(perms.allows_repo(RepoAction::Create, "any.collection"));
        assert!(perms.allows_repo(RepoAction::Update, "any.collection"));
        assert!(perms.allows_repo(RepoAction::Delete, "any.collection"));
        assert!(perms.allows_blob("image/png"));
        assert!(perms.allows_blob("video/mp4"));
    }

    #[test]
    fn test_identity_scope_handle() {
        let perms = ScopePermissions::from_scope_string(Some("identity:handle"));
        assert!(perms.allows_identity(IdentityAttr::Handle));
        assert!(!perms.allows_identity(IdentityAttr::Wildcard));
    }

    #[test]
    fn test_identity_scope_wildcard() {
        let perms = ScopePermissions::from_scope_string(Some("identity:*"));
        assert!(perms.allows_identity(IdentityAttr::Handle));
        assert!(perms.allows_identity(IdentityAttr::Wildcard));
    }

    #[test]
    fn test_identity_scope_with_atproto() {
        let perms = ScopePermissions::from_scope_string(Some("atproto"));
        assert!(perms.allows_identity(IdentityAttr::Handle));
        assert!(perms.allows_identity(IdentityAttr::Wildcard));
    }

    #[test]
    fn test_account_status_scope() {
        let perms = ScopePermissions::from_scope_string(Some("account:status?action=read"));
        assert!(perms.allows_account(AccountAttr::Status, AccountAction::Read));
        assert!(!perms.allows_account(AccountAttr::Status, AccountAction::Manage));
    }

    #[test]
    fn test_atproto_with_granular_scopes_uses_granular() {
        let perms =
            ScopePermissions::from_scope_string(Some("atproto repo:*?action=create blob:*/*"));
        assert!(!perms.has_full_access());
        assert!(perms.allows_repo(RepoAction::Create, "any.collection"));
        assert!(!perms.allows_repo(RepoAction::Delete, "any.collection"));
        assert!(!perms.allows_repo(RepoAction::Update, "any.collection"));
        assert!(perms.allows_blob("image/png"));
        assert!(!perms.allows_rpc("did:web:api.bsky.app", "app.bsky.feed.getTimeline"));
    }

    #[test]
    fn test_atproto_alone_has_full_access() {
        let perms = ScopePermissions::from_scope_string(Some("atproto"));
        assert!(perms.has_full_access());
        assert!(perms.allows_repo(RepoAction::Create, "any.collection"));
        assert!(perms.allows_repo(RepoAction::Delete, "any.collection"));
        assert!(perms.allows_repo(RepoAction::Update, "any.collection"));
        assert!(perms.allows_blob("image/png"));
        assert!(perms.allows_rpc("did:web:api.bsky.app", "app.bsky.feed.getTimeline"));
    }

    #[test]
    fn test_rpc_scope_with_did_fragment() {
        let perms = ScopePermissions::from_scope_string(Some(
            "rpc:app.bsky.feed.getAuthorFeed?aud=did:web:api.bsky.app#bsky_appview",
        ));
        assert!(perms.allows_rpc("did:web:api.bsky.app", "app.bsky.feed.getAuthorFeed"));
        assert!(perms.allows_rpc(
            "did:web:api.bsky.app#bsky_appview",
            "app.bsky.feed.getAuthorFeed"
        ));
        assert!(perms.allows_rpc(
            "did:web:api.bsky.app#other_service",
            "app.bsky.feed.getAuthorFeed"
        ));
        assert!(!perms.allows_rpc("did:web:other.app", "app.bsky.feed.getAuthorFeed"));
        assert!(!perms.allows_rpc("did:web:api.bsky.app", "app.bsky.feed.getTimeline"));
    }

    #[test]
    fn test_rpc_scope_without_fragment_matches_with_fragment() {
        let perms = ScopePermissions::from_scope_string(Some(
            "rpc:app.bsky.feed.getAuthorFeed?aud=did:web:api.bsky.app",
        ));
        assert!(perms.allows_rpc("did:web:api.bsky.app", "app.bsky.feed.getAuthorFeed"));
        assert!(perms.allows_rpc(
            "did:web:api.bsky.app#bsky_appview",
            "app.bsky.feed.getAuthorFeed"
        ));
    }
}
