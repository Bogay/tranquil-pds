use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use tracing::debug;
use tranquil_types::{Did, Nsid};

#[derive(Debug, thiserror::Error)]
pub enum ScopeExpansionError {
    #[error("Invalid NSID format: {0}")]
    InvalidNsid(String),
    #[error("Missing definition: {0}")]
    MissingDefinition(String),
    #[error("Unexpected lexicon type: {0}")]
    UnexpectedType(String),
    #[error("DNS resolution failed: {0}")]
    DnsResolution(String),
    #[error("HTTP request failed: {0}")]
    HttpFailed(String),
    #[error("DID resolution failed: {0}")]
    DidResolution(String),
    #[error("Lexicon record not found")]
    RecordNotFound,
    #[error("No valid permissions found in permission-set")]
    EmptyPermissions,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolveFailure {
    // Couldn't connect to PDS
    Unreachable,
    // Connected to PDS, but the lexicon record doesn't exist
    NotFound,
    // The NSID is malformed
    Malformed,
    // A lexicon exists, but it isn't a `permission-set` (e.g. a query or record type).
    NotAPermissionSet,
    // Lexicon doc was malformed (no main, no permissions)
    MalformedLexicon,
    // The doc is valid, but grants nothing usable (i.e. empty permissions, or permissions are from a different namespace)
    EmptyPermissions,
}

#[derive(Debug, Clone)]
pub struct FailedSet {
    // NSID and aud are left as strings to avoid issues from malformed requests.
    pub given_nsid: String,
    pub given_aud: Option<String>,
    pub reason: ResolveFailure,
}

#[derive(Debug, Clone)]
pub struct ResolvedSetGroup {
    pub nsid: Nsid,
    pub aud: Option<String>,
    pub title: Option<String>,
    pub detail: Option<String>,
    pub expanded: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ExpansionOutcome {
    pub passthrough: Vec<String>,
    pub sets: Vec<ResolvedSetGroup>,
    pub failures: Vec<FailedSet>,
}

impl ExpansionOutcome {
    pub fn flat_scopes(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for s in self
            .passthrough
            .iter()
            .chain(self.sets.iter().flat_map(|group| group.expanded.iter()))
        {
            if seen.insert(s.as_str()) {
                out.push(s.clone());
            }
        }
        out
    }

    pub fn to_scope_string(&self) -> String {
        self.flat_scopes().join(" ")
    }
}

#[derive(Debug, Deserialize)]
struct PlcDocument {
    service: Vec<PlcService>,
}

#[derive(Debug, Deserialize)]
struct PlcService {
    id: String,
    #[serde(rename = "serviceEndpoint")]
    service_endpoint: String,
}

#[derive(Debug, Deserialize)]
struct XrpcError {
    error: String,
}

#[derive(Debug, Deserialize)]
struct GetRecordResponse {
    value: LexiconDoc,
}

#[derive(Debug, Deserialize)]
struct LexiconDoc {
    defs: HashMap<String, LexiconDef>,
}

#[derive(Debug, Deserialize)]
struct LexiconDef {
    #[serde(rename = "type")]
    def_type: String,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    detail: Option<String>,
    permissions: Option<Vec<PermissionEntry>>,
}

#[derive(Debug, Deserialize)]
struct PermissionEntry {
    resource: String,
    action: Option<Vec<String>>,
    collection: Option<Vec<String>>,
    lxm: Option<Vec<String>>,
    aud: Option<String>,
}

pub fn parse_include_scope(rest: &str) -> (&str, Option<&str>) {
    rest.split_once('?')
        .map(|(nsid, params)| {
            let aud = params.split('&').find_map(|p| p.strip_prefix("aud="));
            (nsid, aud)
        })
        .unwrap_or((rest, None))
}

pub struct FetchedSet {
    pub expanded: String,
    pub title: Option<String>,
    pub detail: Option<String>,
}

pub async fn fetch_and_expand(
    nsid: &Nsid,
    aud: Option<&str>,
) -> Result<FetchedSet, ScopeExpansionError> {
    let lexicon = fetch_lexicon_via_atproto(nsid).await?;
    let main_def = lexicon
        .defs
        .get("main")
        .ok_or(ScopeExpansionError::MissingDefinition("main".to_string()))?;
    if main_def.def_type != "permission-set" {
        return Err(ScopeExpansionError::UnexpectedType(
            main_def.def_type.clone(),
        ));
    }
    let permissions =
        main_def
            .permissions
            .as_ref()
            .ok_or(ScopeExpansionError::MissingDefinition(
                "permissions".to_string(),
            ))?;
    let namespace_authority = extract_namespace_authority(nsid);
    let expanded = build_expanded_scopes(permissions, aud, &namespace_authority);
    if expanded.is_empty() {
        return Err(ScopeExpansionError::EmptyPermissions);
    }
    Ok(FetchedSet {
        expanded,
        title: main_def.title.clone(),
        detail: main_def.detail.clone(),
    })
}

async fn fetch_lexicon_via_atproto(nsid: &Nsid) -> Result<LexiconDoc, ScopeExpansionError> {
    let parts: Vec<&str> = nsid.split('.').collect();
    let authority = parts[..parts.len() - 1]
        .iter()
        .rev()
        .cloned()
        .collect::<Vec<_>>()
        .join(".");
    debug!(nsid = %nsid, authority = %authority, "Resolving lexicon DID authority via DNS");

    let did = resolve_lexicon_did_authority(&authority).await?;
    debug!(nsid = %nsid, did = %did, "Resolved lexicon DID authority");

    let pds_endpoint = resolve_did_to_pds(&did).await?;
    debug!(nsid = %nsid, pds = %pds_endpoint, "Resolved DID to PDS endpoint");

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| ScopeExpansionError::HttpFailed(e.to_string()))?;

    let url = format!(
        "{}/xrpc/com.atproto.repo.getRecord?repo={}&collection=com.atproto.lexicon.schema&rkey={}",
        pds_endpoint,
        urlencoding::encode(did.as_str()),
        urlencoding::encode(nsid.as_str())
    );
    debug!(nsid = %nsid, url = %url, "Fetching lexicon from PDS");

    let response = client
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| ScopeExpansionError::HttpFailed(e.to_string()))?;

    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| ScopeExpansionError::HttpFailed(e.to_string()))?;

    if !status.is_success() {
        let not_found = status == reqwest::StatusCode::NOT_FOUND
            || serde_json::from_str::<XrpcError>(&body)
                .map(|e| e.error.eq_ignore_ascii_case("RecordNotFound"))
                .unwrap_or(false);
        return Err(if not_found {
            ScopeExpansionError::RecordNotFound
        } else {
            ScopeExpansionError::HttpFailed(format!("HTTP {}", status))
        });
    }

    let record: GetRecordResponse =
        serde_json::from_str(&body).map_err(|e| ScopeExpansionError::HttpFailed(e.to_string()))?;

    Ok(record.value)
}

async fn resolve_lexicon_did_authority(authority: &str) -> Result<Did, ScopeExpansionError> {
    let resolver = TokioAsyncResolver::tokio_from_system_conf().unwrap_or_else(|e| {
        tracing::warn!("falling back to default DNS resolvers: {}", e);
        TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())
    });

    let dns_name = format!("_lexicon.{}", authority);
    debug!(dns_name = %dns_name, "Looking up DNS TXT record");

    let txt_records = resolver
        .txt_lookup(&dns_name)
        .await
        .map_err(|e| ScopeExpansionError::DnsResolution(format!("{}: {}", dns_name, e)))?;

    txt_records
        .iter()
        .flat_map(|record| record.iter())
        .find_map(|data| {
            let txt = String::from_utf8_lossy(data);
            txt.strip_prefix("did=")
                .and_then(|did| Did::new(did.trim()).ok())
        })
        .ok_or_else(|| {
            ScopeExpansionError::DnsResolution(format!(
                "No valid did= TXT record found at {}",
                dns_name
            ))
        })
}

async fn resolve_did_to_pds(did: &Did) -> Result<String, ScopeExpansionError> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| ScopeExpansionError::HttpFailed(e.to_string()))?;

    let url = if did.starts_with("did:plc:") {
        format!("https://plc.directory/{}", did)
    } else if did.starts_with("did:web:") {
        let domain = did.strip_prefix("did:web:").unwrap();
        format!("https://{}/.well-known/did.json", domain)
    } else {
        return Err(ScopeExpansionError::DidResolution(format!(
            "Unsupported DID method: {}",
            did
        )));
    };

    let response = client
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| ScopeExpansionError::DidResolution(e.to_string()))?;

    if !response.status().is_success() {
        return Err(ScopeExpansionError::DidResolution(format!(
            "HTTP {}",
            response.status()
        )));
    }

    let doc: PlcDocument = response
        .json()
        .await
        .map_err(|e| ScopeExpansionError::DidResolution(e.to_string()))?;

    doc.service
        .iter()
        .find(|s| s.id == "#atproto_pds")
        .map(|s| s.service_endpoint.clone())
        .ok_or(ScopeExpansionError::DidResolution(
            "No #atproto_pds service found in DID document".to_string(),
        ))
}

fn extract_namespace_authority(nsid: &Nsid) -> String {
    let parts: Vec<&str> = nsid.split('.').collect();
    parts[..parts.len() - 1].join(".")
}

fn is_under_authority(target_nsid: &str, authority: &str) -> bool {
    target_nsid.starts_with(authority)
        && target_nsid
            .chars()
            .nth(authority.len())
            .is_some_and(|c| c == '.')
}

const DEFAULT_ACTIONS: &[&str] = &["create", "update", "delete"];

fn action_rank(action: &str) -> usize {
    DEFAULT_ACTIONS
        .iter()
        .position(|known| *known == action)
        .unwrap_or(DEFAULT_ACTIONS.len())
}

fn build_expanded_scopes(
    permissions: &[PermissionEntry],
    default_aud: Option<&str>,
    namespace_authority: &str,
) -> String {
    // Key is `repo`, value is array of actions
    let mut ungrouped_repo_scopes: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut rpc_scopes: Vec<String> = Vec::new();

    permissions
        .iter()
        .for_each(|perm| match perm.resource.as_str() {
            "repo" => {
                if let Some(collections) = &perm.collection {
                    let actions: Vec<&str> = perm
                        .action
                        .as_ref()
                        .map(|a| a.iter().map(String::as_str).collect())
                        .unwrap_or_else(|| DEFAULT_ACTIONS.to_vec());

                    if !actions.is_empty() {
                        collections
                            .iter()
                            .filter(|coll| is_under_authority(coll, namespace_authority))
                            .for_each(|coll| {
                                let existing =
                                    ungrouped_repo_scopes.entry(coll.to_string()).or_default();

                                actions.iter().for_each(|action| {
                                    if !existing.iter().any(|seen| seen == action) {
                                        existing.push(action.to_string());
                                    }
                                });
                            });
                    }
                }
            }
            "rpc" => {
                if let Some(lxms) = &perm.lxm {
                    let perm_aud = perm.aud.as_deref().or(default_aud);

                    lxms.iter()
                        .filter(|lxm| is_under_authority(lxm, namespace_authority))
                        .for_each(|lxm| {
                            let scope = match perm_aud {
                                Some(aud) => format!("rpc:{}?aud={}", lxm, aud),
                                None => format!("rpc:{}", lxm),
                            };

                            if !rpc_scopes.contains(&scope) {
                                rpc_scopes.push(scope);
                            }
                        });
                }
            }
            _ => {}
        });

    let grouped_repo_scopes: Vec<String> = ungrouped_repo_scopes
        .iter()
        .map(|(repo, actions)| {
            let mut actions = actions.clone();
            actions.sort_by(|a, b| action_rank(a).cmp(&action_rank(b)).then_with(|| a.cmp(b)));

            format!("repo:{}?action={}", repo, actions.join("&action="))
        })
        .collect();

    let combined_repo_scopes = grouped_repo_scopes.join(" ");
    let combined_rpc_scopes = rpc_scopes.join(" ");

    format!("{} {}", combined_repo_scopes, combined_rpc_scopes)
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_include_scope() {
        let (nsid, aud) = parse_include_scope("io.atcr.authFullApp");
        assert_eq!(nsid, "io.atcr.authFullApp");
        assert_eq!(aud, None);

        let (nsid, aud) = parse_include_scope("io.atcr.authFullApp?aud=did:web:api.bsky.app");
        assert_eq!(nsid, "io.atcr.authFullApp");
        assert_eq!(aud, Some("did:web:api.bsky.app"));
    }

    #[test]
    fn test_parse_include_scope_with_multiple_params() {
        let (nsid, aud) =
            parse_include_scope("io.atcr.authFullApp?foo=bar&aud=did:web:example.com&baz=qux");
        assert_eq!(nsid, "io.atcr.authFullApp");
        assert_eq!(aud, Some("did:web:example.com"));
    }

    fn nsid(s: &str) -> Nsid {
        s.parse().unwrap()
    }

    #[test]
    fn test_extract_namespace_authority() {
        assert_eq!(
            extract_namespace_authority(&nsid("io.atcr.authFullApp")),
            "io.atcr"
        );
        assert_eq!(
            extract_namespace_authority(&nsid("app.bsky.authFullApp")),
            "app.bsky"
        );
    }

    #[test]
    fn test_extract_namespace_authority_deep_nesting() {
        assert_eq!(
            extract_namespace_authority(&nsid("io.atcr.sailor.star.collection")),
            "io.atcr.sailor.star"
        );
    }

    #[test]
    fn test_is_under_authority() {
        assert!(is_under_authority("io.atcr.manifest", "io.atcr"));
        assert!(is_under_authority("io.atcr.sailor.star", "io.atcr"));
        assert!(!is_under_authority("app.bsky.feed.post", "io.atcr"));
        assert!(!is_under_authority("io.atcr", "io.atcr"));
    }

    #[test]
    fn test_is_under_authority_prefix_collision() {
        assert!(!is_under_authority("io.atcritical.something", "io.atcr"));
        assert!(is_under_authority("io.atcr.something", "io.atcr"));
    }

    #[test]
    fn test_build_expanded_scopes_repo() {
        let permissions = vec![PermissionEntry {
            resource: "repo".to_string(),
            action: Some(vec!["create".to_string(), "delete".to_string()]),
            collection: Some(vec![
                "io.atcr.manifest".to_string(),
                "io.atcr.sailor.star".to_string(),
                "app.bsky.feed.post".to_string(),
            ]),
            lxm: None,
            aud: None,
        }];

        let expanded = build_expanded_scopes(&permissions, None, "io.atcr");
        assert_eq!(
            expanded,
            "repo:io.atcr.manifest?action=create&action=delete \
             repo:io.atcr.sailor.star?action=create&action=delete"
        );
    }

    #[test]
    fn test_build_expanded_scopes_repo_default_actions() {
        let permissions = vec![PermissionEntry {
            resource: "repo".to_string(),
            action: None,
            collection: Some(vec!["io.atcr.manifest".to_string()]),
            lxm: None,
            aud: None,
        }];

        let expanded = build_expanded_scopes(&permissions, None, "io.atcr");
        assert_eq!(
            expanded,
            "repo:io.atcr.manifest?action=create&action=update&action=delete"
        );
    }

    #[test]
    fn test_build_expanded_scopes_repo_omitted_action_grants_all() {
        let permissions = vec![PermissionEntry {
            resource: "repo".to_string(),
            action: None,
            collection: Some(vec!["io.atcr.manifest".to_string()]),
            lxm: None,
            aud: None,
        }];

        let expanded = build_expanded_scopes(&permissions, None, "io.atcr");
        assert_eq!(
            expanded, "repo:io.atcr.manifest?action=create&action=update&action=delete",
            "an omitted action list means all actions"
        );
    }

    #[test]
    fn test_build_expanded_scopes_repo_empty_action_list_skips_entry() {
        let permissions = vec![PermissionEntry {
            resource: "repo".to_string(),
            action: Some(vec![]),
            collection: Some(vec!["io.atcr.manifest".to_string()]),
            lxm: None,
            aud: None,
        }];

        let expanded = build_expanded_scopes(&permissions, None, "io.atcr");
        assert!(
            expanded.is_empty(),
            "an explicitly empty action list is invalid, so the entry is skipped rather \
             than expanded to all actions or emitted as a bare `?action=`, got: {expanded}"
        );
    }

    #[test]
    fn test_build_expanded_scopes_is_deterministic() {
        let permissions = vec![
            PermissionEntry {
                resource: "repo".to_string(),
                action: Some(vec!["create".to_string()]),
                collection: Some(vec![
                    "io.atcr.sailor.star".to_string(),
                    "io.atcr.manifest".to_string(),
                    "io.atcr.blob".to_string(),
                ]),
                lxm: None,
                aud: None,
            },
            PermissionEntry {
                resource: "rpc".to_string(),
                action: None,
                collection: None,
                lxm: Some(vec![
                    "io.atcr.getManifest".to_string(),
                    "io.atcr.listTags".to_string(),
                ]),
                aud: Some("*".to_string()),
            },
        ];

        let first = build_expanded_scopes(&permissions, None, "io.atcr");
        assert_eq!(
            first,
            "repo:io.atcr.blob?action=create repo:io.atcr.manifest?action=create \
             repo:io.atcr.sailor.star?action=create \
             rpc:io.atcr.getManifest?aud=* rpc:io.atcr.listTags?aud=*"
        );

        for _ in 0..16 {
            assert_eq!(build_expanded_scopes(&permissions, None, "io.atcr"), first);
        }
    }

    #[test]
    fn test_build_expanded_scopes_dedupes_and_canonicalizes_actions() {
        let permissions = vec![
            PermissionEntry {
                resource: "repo".to_string(),
                action: Some(vec!["delete".to_string(), "create".to_string()]),
                collection: Some(vec!["io.atcr.manifest".to_string()]),
                lxm: None,
                aud: None,
            },
            PermissionEntry {
                resource: "repo".to_string(),
                action: Some(vec!["create".to_string(), "update".to_string()]),
                collection: Some(vec!["io.atcr.manifest".to_string()]),
                lxm: None,
                aud: None,
            },
            PermissionEntry {
                resource: "rpc".to_string(),
                action: None,
                collection: None,
                lxm: Some(vec![
                    "io.atcr.getManifest".to_string(),
                    "io.atcr.getManifest".to_string(),
                ]),
                aud: Some("*".to_string()),
            },
        ];

        let expanded = build_expanded_scopes(&permissions, None, "io.atcr");
        assert_eq!(
            expanded,
            "repo:io.atcr.manifest?action=create&action=update&action=delete \
             rpc:io.atcr.getManifest?aud=*"
        );
    }

    #[test]
    fn test_build_expanded_scopes_rpc() {
        let permissions = vec![PermissionEntry {
            resource: "rpc".to_string(),
            action: None,
            collection: None,
            lxm: Some(vec![
                "io.atcr.getManifest".to_string(),
                "com.atproto.repo.getRecord".to_string(),
            ]),
            aud: Some("*".to_string()),
        }];

        let expanded = build_expanded_scopes(&permissions, None, "io.atcr");
        assert!(expanded.contains("rpc:io.atcr.getManifest?aud=*"));
        assert!(!expanded.contains("com.atproto.repo.getRecord"));
    }

    #[test]
    fn test_build_expanded_scopes_rpc_with_default_aud() {
        let permissions = vec![PermissionEntry {
            resource: "rpc".to_string(),
            action: None,
            collection: None,
            lxm: Some(vec!["io.atcr.getManifest".to_string()]),
            aud: None,
        }];

        let expanded =
            build_expanded_scopes(&permissions, Some("did:web:api.example.com"), "io.atcr");
        assert!(expanded.contains("rpc:io.atcr.getManifest?aud=did:web:api.example.com"));
    }

    #[test]
    fn test_build_expanded_scopes_rpc_no_aud() {
        let permissions = vec![PermissionEntry {
            resource: "rpc".to_string(),
            action: None,
            collection: None,
            lxm: Some(vec!["io.atcr.getManifest".to_string()]),
            aud: None,
        }];

        let expanded = build_expanded_scopes(&permissions, None, "io.atcr");
        assert_eq!(expanded, "rpc:io.atcr.getManifest");
    }

    #[test]
    fn test_build_expanded_scopes_mixed_permissions() {
        let permissions = vec![
            PermissionEntry {
                resource: "repo".to_string(),
                action: Some(vec!["create".to_string()]),
                collection: Some(vec!["io.atcr.manifest".to_string()]),
                lxm: None,
                aud: None,
            },
            PermissionEntry {
                resource: "rpc".to_string(),
                action: None,
                collection: None,
                lxm: Some(vec!["com.atproto.repo.getRecord".to_string()]),
                aud: Some("*".to_string()),
            },
        ];

        let expanded = build_expanded_scopes(&permissions, None, "io.atcr");
        assert!(expanded.contains("repo:io.atcr.manifest?action=create"));
        assert!(!expanded.contains("com.atproto.repo.getRecord"));
    }

    #[test]
    fn test_build_expanded_scopes_rpc_cannot_escape_namespace() {
        let permissions = vec![PermissionEntry {
            resource: "rpc".to_string(),
            action: None,
            collection: None,
            lxm: Some(vec![
                "com.atproto.repo.deleteRecord".to_string(),
                "chat.bsky.convo.sendMessage".to_string(),
                "io.atcrEVIL.getManifest".to_string(),
            ]),
            aud: Some("*".to_string()),
        }];

        let expanded = build_expanded_scopes(&permissions, None, "io.atcr");
        assert!(
            expanded.is_empty(),
            "cross-namespace lxm values must all be dropped, got: {expanded}"
        );
    }

    #[test]
    fn test_build_expanded_scopes_rpc_allows_child_namespace() {
        let permissions = vec![PermissionEntry {
            resource: "rpc".to_string(),
            action: None,
            collection: None,
            lxm: Some(vec!["io.atcr.sailor.star.getThing".to_string()]),
            aud: None,
        }];

        let expanded = build_expanded_scopes(&permissions, None, "io.atcr");
        assert_eq!(expanded, "rpc:io.atcr.sailor.star.getThing");
    }

    #[test]
    fn test_build_expanded_scopes_unknown_resource_ignored() {
        let permissions = vec![PermissionEntry {
            resource: "unknown".to_string(),
            action: None,
            collection: Some(vec!["io.atcr.manifest".to_string()]),
            lxm: None,
            aud: None,
        }];

        let expanded = build_expanded_scopes(&permissions, None, "io.atcr");
        assert!(expanded.is_empty());
    }

    #[test]
    fn test_build_expanded_scopes_empty_permissions() {
        let permissions: Vec<PermissionEntry> = vec![];
        let expanded = build_expanded_scopes(&permissions, None, "io.atcr");
        assert!(expanded.is_empty());
    }

    fn dns_authority(nsid: &str) -> String {
        let parts: Vec<&str> = nsid.split('.').collect();
        parts[..parts.len() - 1]
            .iter()
            .rev()
            .cloned()
            .collect::<Vec<_>>()
            .join(".")
    }

    #[test]
    fn test_nsid_authority_extraction_for_dns() {
        assert_eq!(dns_authority("io.atcr.authFullApp"), "atcr.io");
        assert_eq!(dns_authority("app.bsky.feed.post"), "feed.bsky.app");
        assert_eq!(
            dns_authority("community.lexicon.bookmarks.authManageBookmarks"),
            "bookmarks.lexicon.community"
        );
    }

    #[test]
    fn expansion_outcome_flat_scopes_and_string() {
        let out = ExpansionOutcome {
            passthrough: vec!["atproto".into()],
            sets: vec![ResolvedSetGroup {
                nsid: Nsid::new("io.atcr.authFullApp").unwrap(),
                aud: None,
                title: Some("T".into()),
                detail: None,
                expanded: vec![
                    "repo:io.atcr.manifest?action=create".into(),
                    "rpc:io.atcr.getManifest".into(),
                ],
            }],
            failures: vec![FailedSet {
                given_nsid: "nonexistent.fake.permissionSet".into(),
                given_aud: None,
                reason: ResolveFailure::NotFound,
            }],
        };
        let flat = out.flat_scopes();
        assert_eq!(
            flat,
            vec![
                "atproto",
                "repo:io.atcr.manifest?action=create",
                "rpc:io.atcr.getManifest"
            ]
        );
        assert_eq!(
            out.to_scope_string(),
            "atproto repo:io.atcr.manifest?action=create rpc:io.atcr.getManifest"
        );
    }

    #[test]
    fn flat_scopes_dedupes() {
        let out = ExpansionOutcome {
            passthrough: vec!["repo:x".into()],
            sets: vec![ResolvedSetGroup {
                nsid: Nsid::new("io.atcr.authFullApp").unwrap(),
                aud: None,
                title: None,
                detail: None,
                expanded: vec!["repo:x".into(), "rpc:io.atcr.getManifest".into()],
            }],
            failures: vec![],
        };
        let flat = out.flat_scopes();
        assert_eq!(flat, vec!["repo:x", "rpc:io.atcr.getManifest"]);
        assert_eq!(out.to_scope_string(), "repo:x rpc:io.atcr.getManifest");
    }

    #[test]
    fn test_lexicon_def_captures_title_and_detail() {
        let json = serde_json::json!({
            "defs": { "main": {
                "type": "permission-set",
                "title": "Basic App",
                "detail": "Posts and interactions",
                "permissions": [{ "resource": "repo", "collection": ["io.atcr.manifest"] }]
            }}
        });
        let doc: LexiconDoc = serde_json::from_value(json).unwrap();
        let main = doc.defs.get("main").unwrap();
        assert_eq!(main.title.as_deref(), Some("Basic App"));
        assert_eq!(main.detail.as_deref(), Some("Posts and interactions"));
    }
}
