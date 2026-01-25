use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedScope {
    Atproto,
    TransitionGeneric,
    TransitionChat,
    TransitionEmail,
    Repo(RepoScope),
    Blob(BlobScope),
    Rpc(RpcScope),
    Account(AccountScope),
    Identity(IdentityScope),
    Include(IncludeScope),
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncludeScope {
    pub nsid: String,
    pub aud: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoScope {
    pub collection: Option<String>,
    pub actions: HashSet<RepoAction>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RepoAction {
    Create,
    Update,
    Delete,
}

impl RepoAction {
    pub fn parse_str(s: &str) -> Option<Self> {
        match s {
            "create" => Some(Self::Create),
            "update" => Some(Self::Update),
            "delete" => Some(Self::Delete),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobScope {
    pub accept: HashSet<String>,
}

impl BlobScope {
    pub fn matches_mime(&self, mime: &str) -> bool {
        if self.accept.is_empty() || self.accept.contains("*/*") {
            return true;
        }
        self.accept.iter().any(|pattern| {
            pattern == mime
                || pattern.strip_suffix("/*").is_some_and(|prefix| {
                    mime.starts_with(prefix) && mime.chars().nth(prefix.len()) == Some('/')
                })
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcScope {
    pub lxm: Option<String>,
    pub aud: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountScope {
    pub attr: AccountAttr,
    pub action: AccountAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccountAttr {
    Email,
    Handle,
    Repo,
    Status,
    Wildcard,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityScope {
    pub attr: IdentityAttr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdentityAttr {
    Handle,
    Wildcard,
}

impl AccountAttr {
    pub fn parse_str(s: &str) -> Option<Self> {
        match s {
            "email" => Some(Self::Email),
            "handle" => Some(Self::Handle),
            "repo" => Some(Self::Repo),
            "status" => Some(Self::Status),
            "*" => Some(Self::Wildcard),
            _ => None,
        }
    }
}

impl IdentityAttr {
    pub fn parse_str(s: &str) -> Option<Self> {
        match s {
            "handle" => Some(Self::Handle),
            "*" => Some(Self::Wildcard),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccountAction {
    Read,
    Manage,
}

impl AccountAction {
    pub fn parse_str(s: &str) -> Option<Self> {
        match s {
            "read" => Some(Self::Read),
            "manage" => Some(Self::Manage),
            _ => None,
        }
    }
}

fn parse_query_params(query: &str) -> HashMap<String, Vec<String>> {
    query
        .split('&')
        .filter_map(|part| part.split_once('='))
        .fold(HashMap::new(), |mut acc, (key, value)| {
            acc.entry(key.to_string())
                .or_default()
                .push(value.to_string());
            acc
        })
}

pub fn parse_scope(scope: &str) -> ParsedScope {
    match scope {
        "atproto" => return ParsedScope::Atproto,
        "transition:generic" => return ParsedScope::TransitionGeneric,
        "transition:chat.bsky" => return ParsedScope::TransitionChat,
        "transition:email" => return ParsedScope::TransitionEmail,
        _ => {}
    }

    let (base, query) = scope.split_once('?').unwrap_or((scope, ""));
    let params = parse_query_params(query);

    if let Some(rest) = base.strip_prefix("repo:") {
        let collection = if rest == "*" || rest.is_empty() {
            None
        } else {
            Some(rest.to_string())
        };

        let actions: HashSet<RepoAction> = params
            .get("action")
            .map(|action_values| {
                action_values
                    .iter()
                    .filter_map(|s| RepoAction::parse_str(s))
                    .collect()
            })
            .filter(|set: &HashSet<RepoAction>| !set.is_empty())
            .unwrap_or_else(|| {
                [RepoAction::Create, RepoAction::Update, RepoAction::Delete]
                    .into_iter()
                    .collect()
            });

        return ParsedScope::Repo(RepoScope {
            collection,
            actions,
        });
    }

    if base == "repo" {
        let actions: HashSet<RepoAction> = params
            .get("action")
            .map(|action_values| {
                action_values
                    .iter()
                    .filter_map(|s| RepoAction::parse_str(s))
                    .collect()
            })
            .filter(|set: &HashSet<RepoAction>| !set.is_empty())
            .unwrap_or_else(|| {
                [RepoAction::Create, RepoAction::Update, RepoAction::Delete]
                    .into_iter()
                    .collect()
            });
        return ParsedScope::Repo(RepoScope {
            collection: None,
            actions,
        });
    }

    if base.starts_with("blob") {
        let positional = base.strip_prefix("blob:").unwrap_or("");
        let accept: HashSet<String> = std::iter::once(positional)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .chain(
                params
                    .get("accept")
                    .into_iter()
                    .flatten()
                    .map(String::clone),
            )
            .collect();

        return ParsedScope::Blob(BlobScope { accept });
    }

    if base.starts_with("rpc") {
        let lxm_positional = base.strip_prefix("rpc:").map(|s| s.to_string());
        let lxm = lxm_positional.or_else(|| params.get("lxm").and_then(|v| v.first().cloned()));
        let aud = params.get("aud").and_then(|v| v.first().cloned());

        let is_lxm_wildcard = lxm.as_deref() == Some("*") || lxm.is_none();
        let is_aud_wildcard = aud.as_deref() == Some("*");
        if is_lxm_wildcard && is_aud_wildcard {
            return ParsedScope::Unknown(scope.to_string());
        }

        return ParsedScope::Rpc(RpcScope { lxm, aud });
    }

    if let Some(attr_str) = base.strip_prefix("account:")
        && let Some(attr) = AccountAttr::parse_str(attr_str)
    {
        let action = params
            .get("action")
            .and_then(|v| v.first())
            .and_then(|s| AccountAction::parse_str(s))
            .unwrap_or(AccountAction::Read);

        return ParsedScope::Account(AccountScope { attr, action });
    }

    if let Some(attr_str) = base.strip_prefix("identity:")
        && let Some(attr) = IdentityAttr::parse_str(attr_str)
    {
        return ParsedScope::Identity(IdentityScope { attr });
    }

    if let Some(nsid) = base.strip_prefix("include:") {
        let aud = params.get("aud").and_then(|v| v.first().cloned());
        return ParsedScope::Include(IncludeScope {
            nsid: nsid.to_string(),
            aud,
        });
    }

    ParsedScope::Unknown(scope.to_string())
}

pub fn parse_scope_string(scope_str: &str) -> Vec<ParsedScope> {
    scope_str.split_whitespace().map(parse_scope).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_atproto() {
        assert_eq!(parse_scope("atproto"), ParsedScope::Atproto);
    }

    #[test]
    fn test_parse_transition_scopes() {
        assert_eq!(
            parse_scope("transition:generic"),
            ParsedScope::TransitionGeneric
        );
        assert_eq!(
            parse_scope("transition:chat.bsky"),
            ParsedScope::TransitionChat
        );
        assert_eq!(
            parse_scope("transition:email"),
            ParsedScope::TransitionEmail
        );
    }

    #[test]
    fn test_parse_repo_wildcard() {
        let scope = parse_scope("repo:*?action=create");
        match scope {
            ParsedScope::Repo(r) => {
                assert!(r.collection.is_none());
                assert!(r.actions.contains(&RepoAction::Create));
                assert!(!r.actions.contains(&RepoAction::Update));
            }
            _ => panic!("Expected Repo scope"),
        }
    }

    #[test]
    fn test_parse_repo_collection() {
        let scope = parse_scope("repo:app.bsky.feed.post?action=create&action=delete");
        match scope {
            ParsedScope::Repo(r) => {
                assert_eq!(r.collection, Some("app.bsky.feed.post".to_string()));
                assert!(r.actions.contains(&RepoAction::Create));
                assert!(r.actions.contains(&RepoAction::Delete));
                assert!(!r.actions.contains(&RepoAction::Update));
            }
            _ => panic!("Expected Repo scope"),
        }
    }

    #[test]
    fn test_parse_repo_no_actions_means_all() {
        let scope = parse_scope("repo:app.bsky.feed.post");
        match scope {
            ParsedScope::Repo(r) => {
                assert!(r.actions.contains(&RepoAction::Create));
                assert!(r.actions.contains(&RepoAction::Update));
                assert!(r.actions.contains(&RepoAction::Delete));
            }
            _ => panic!("Expected Repo scope"),
        }
    }

    #[test]
    fn test_parse_blob_wildcard() {
        let scope = parse_scope("blob:*/*");
        match scope {
            ParsedScope::Blob(b) => {
                assert!(b.accept.contains("*/*"));
                assert!(b.matches_mime("image/png"));
                assert!(b.matches_mime("video/mp4"));
            }
            _ => panic!("Expected Blob scope"),
        }
    }

    #[test]
    fn test_parse_blob_specific() {
        let scope = parse_scope("blob?accept=image/*&accept=video/*");
        match scope {
            ParsedScope::Blob(b) => {
                assert!(b.matches_mime("image/png"));
                assert!(b.matches_mime("image/jpeg"));
                assert!(b.matches_mime("video/mp4"));
                assert!(!b.matches_mime("text/plain"));
            }
            _ => panic!("Expected Blob scope"),
        }
    }

    #[test]
    fn test_parse_rpc() {
        let scope = parse_scope("rpc:app.bsky.feed.getTimeline?aud=did:web:api.bsky.app");
        match scope {
            ParsedScope::Rpc(r) => {
                assert_eq!(r.lxm, Some("app.bsky.feed.getTimeline".to_string()));
                assert_eq!(r.aud, Some("did:web:api.bsky.app".to_string()));
            }
            _ => panic!("Expected Rpc scope"),
        }
    }

    #[test]
    fn test_parse_account() {
        let scope = parse_scope("account:email?action=read");
        match scope {
            ParsedScope::Account(a) => {
                assert_eq!(a.attr, AccountAttr::Email);
                assert_eq!(a.action, AccountAction::Read);
            }
            _ => panic!("Expected Account scope"),
        }

        let scope2 = parse_scope("account:repo?action=manage");
        match scope2 {
            ParsedScope::Account(a) => {
                assert_eq!(a.attr, AccountAttr::Repo);
                assert_eq!(a.action, AccountAction::Manage);
            }
            _ => panic!("Expected Account scope"),
        }
    }

    #[test]
    fn test_parse_scope_string() {
        let scopes = parse_scope_string("atproto repo:*?action=create blob:*/*");
        assert_eq!(scopes.len(), 3);
        assert_eq!(scopes[0], ParsedScope::Atproto);
        match &scopes[1] {
            ParsedScope::Repo(_) => {}
            _ => panic!("Expected Repo"),
        }
        match &scopes[2] {
            ParsedScope::Blob(_) => {}
            _ => panic!("Expected Blob"),
        }
    }

    #[test]
    fn test_parse_include() {
        let scope = parse_scope("include:app.bsky.authFullApp?aud=did:web:api.bsky.app");
        match scope {
            ParsedScope::Include(i) => {
                assert_eq!(i.nsid, "app.bsky.authFullApp");
                assert_eq!(i.aud, Some("did:web:api.bsky.app".to_string()));
            }
            _ => panic!("Expected Include scope"),
        }

        let scope2 = parse_scope("include:com.example.authBasicFeatures");
        match scope2 {
            ParsedScope::Include(i) => {
                assert_eq!(i.nsid, "com.example.authBasicFeatures");
                assert_eq!(i.aud, None);
            }
            _ => panic!("Expected Include scope"),
        }
    }

    #[test]
    fn test_parse_identity() {
        let scope = parse_scope("identity:handle");
        match scope {
            ParsedScope::Identity(i) => {
                assert_eq!(i.attr, IdentityAttr::Handle);
            }
            _ => panic!("Expected Identity scope"),
        }

        let scope2 = parse_scope("identity:*");
        match scope2 {
            ParsedScope::Identity(i) => {
                assert_eq!(i.attr, IdentityAttr::Wildcard);
            }
            _ => panic!("Expected Identity scope"),
        }
    }

    #[test]
    fn test_parse_account_status() {
        let scope = parse_scope("account:status?action=read");
        match scope {
            ParsedScope::Account(a) => {
                assert_eq!(a.attr, AccountAttr::Status);
                assert_eq!(a.action, AccountAction::Read);
            }
            _ => panic!("Expected Account scope"),
        }
    }

    #[test]
    fn test_rpc_wildcard_aud_forbidden() {
        let scope = parse_scope("rpc:*?aud=*");
        assert!(matches!(scope, ParsedScope::Unknown(_)));

        let scope2 = parse_scope("rpc?aud=*");
        assert!(matches!(scope2, ParsedScope::Unknown(_)));

        let scope3 = parse_scope("rpc:app.bsky.feed.getTimeline?aud=*");
        assert!(matches!(scope3, ParsedScope::Rpc(_)));

        let scope4 = parse_scope("rpc:*?aud=did:web:api.bsky.app");
        assert!(matches!(scope4, ParsedScope::Rpc(_)));
    }
}
