use hickory_resolver::TokioAsyncResolver;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::LazyLock;
use tokio::sync::RwLock;
use tracing::{debug, warn};

static LEXICON_CACHE: LazyLock<RwLock<HashMap<String, CachedLexicon>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

#[derive(Clone)]
struct CachedLexicon {
    expanded_scope: String,
    cached_at: std::time::Instant,
}

const CACHE_TTL_SECS: u64 = 3600;

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

pub async fn expand_include_scopes(scope_string: &str) -> String {
    let futures: Vec<_> = scope_string
        .split_whitespace()
        .map(|scope| async move {
            match scope.strip_prefix("include:") {
                Some(rest) => {
                    let (nsid_base, aud) = parse_include_scope(rest);
                    expand_permission_set(nsid_base, aud)
                        .await
                        .unwrap_or_else(|e| {
                            warn!(nsid = nsid_base, error = %e, "Failed to expand permission set, keeping original");
                            scope.to_string()
                        })
                }
                None => scope.to_string(),
            }
        })
        .collect();

    futures::future::join_all(futures).await.join(" ")
}

fn parse_include_scope(rest: &str) -> (&str, Option<&str>) {
    rest.split_once('?')
        .map(|(nsid, params)| {
            let aud = params.split('&').find_map(|p| p.strip_prefix("aud="));
            (nsid, aud)
        })
        .unwrap_or((rest, None))
}

async fn expand_permission_set(nsid: &str, aud: Option<&str>) -> Result<String, String> {
    let cache_key = match aud {
        Some(a) => format!("{}?aud={}", nsid, a),
        None => nsid.to_string(),
    };

    {
        let cache = LEXICON_CACHE.read().await;
        if let Some(cached) = cache.get(&cache_key)
            && cached.cached_at.elapsed().as_secs() < CACHE_TTL_SECS
        {
            debug!(nsid, "Using cached permission set expansion");
            return Ok(cached.expanded_scope.clone());
        }
    }

    let lexicon = fetch_lexicon_via_atproto(nsid).await?;

    let main_def = lexicon
        .defs
        .get("main")
        .ok_or("Missing 'main' definition in lexicon")?;

    if main_def.def_type != "permission-set" {
        return Err(format!(
            "Expected permission-set type, got: {}",
            main_def.def_type
        ));
    }

    let permissions = main_def
        .permissions
        .as_ref()
        .ok_or("Missing permissions in permission-set")?;

    let namespace_authority = extract_namespace_authority(nsid);
    let expanded = build_expanded_scopes(permissions, aud, &namespace_authority);

    if expanded.is_empty() {
        return Err("No valid permissions found in permission-set".to_string());
    }

    {
        let mut cache = LEXICON_CACHE.write().await;
        cache.insert(
            cache_key,
            CachedLexicon {
                expanded_scope: expanded.clone(),
                cached_at: std::time::Instant::now(),
            },
        );
    }

    debug!(nsid, expanded = %expanded, "Successfully expanded permission set");
    Ok(expanded)
}

async fn fetch_lexicon_via_atproto(nsid: &str) -> Result<LexiconDoc, String> {
    let parts: Vec<&str> = nsid.split('.').collect();
    if parts.len() < 3 {
        return Err(format!("Invalid NSID format: {}", nsid));
    }

    let authority = parts[..2]
        .iter()
        .rev()
        .cloned()
        .collect::<Vec<_>>()
        .join(".");
    debug!(nsid, authority = %authority, "Resolving lexicon DID authority via DNS");

    let did = resolve_lexicon_did_authority(&authority).await?;
    debug!(nsid, did = %did, "Resolved lexicon DID authority");

    let pds_endpoint = resolve_did_to_pds(&did).await?;
    debug!(nsid, pds = %pds_endpoint, "Resolved DID to PDS endpoint");

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    let url = format!(
        "{}/xrpc/com.atproto.repo.getRecord?repo={}&collection=com.atproto.lexicon.schema&rkey={}",
        pds_endpoint,
        urlencoding::encode(&did),
        urlencoding::encode(nsid)
    );
    debug!(nsid, url = %url, "Fetching lexicon from PDS");

    let response = client
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| format!("Failed to fetch lexicon: {}", e))?;

    if !response.status().is_success() {
        return Err(format!(
            "Failed to fetch lexicon: HTTP {}",
            response.status()
        ));
    }

    let record: GetRecordResponse = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse lexicon response: {}", e))?;

    Ok(record.value)
}

async fn resolve_lexicon_did_authority(authority: &str) -> Result<String, String> {
    let resolver = TokioAsyncResolver::tokio_from_system_conf()
        .map_err(|e| format!("Failed to create DNS resolver: {}", e))?;

    let dns_name = format!("_lexicon.{}", authority);
    debug!(dns_name = %dns_name, "Looking up DNS TXT record");

    let txt_records = resolver
        .txt_lookup(&dns_name)
        .await
        .map_err(|e| format!("DNS lookup failed for {}: {}", dns_name, e))?;

    txt_records
        .iter()
        .flat_map(|record| record.iter())
        .find_map(|data| {
            let txt = String::from_utf8_lossy(data);
            txt.strip_prefix("did=").map(|did| did.to_string())
        })
        .ok_or_else(|| format!("No valid did= TXT record found at {}", dns_name))
}

async fn resolve_did_to_pds(did: &str) -> Result<String, String> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    let url = if did.starts_with("did:plc:") {
        format!("https://plc.directory/{}", did)
    } else if did.starts_with("did:web:") {
        let domain = did.strip_prefix("did:web:").unwrap();
        format!("https://{}/.well-known/did.json", domain)
    } else {
        return Err(format!("Unsupported DID method: {}", did));
    };

    let response = client
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| format!("Failed to resolve DID: {}", e))?;

    if !response.status().is_success() {
        return Err(format!("Failed to resolve DID: HTTP {}", response.status()));
    }

    let doc: PlcDocument = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse DID document: {}", e))?;

    doc.service
        .iter()
        .find(|s| s.id == "#atproto_pds")
        .map(|s| s.service_endpoint.clone())
        .ok_or_else(|| "No #atproto_pds service found in DID document".to_string())
}

fn extract_namespace_authority(nsid: &str) -> String {
    let parts: Vec<&str> = nsid.split('.').collect();
    if parts.len() >= 2 {
        parts[..parts.len() - 1].join(".")
    } else {
        nsid.to_string()
    }
}

fn is_under_authority(target_nsid: &str, authority: &str) -> bool {
    target_nsid.starts_with(authority)
        && target_nsid
            .chars()
            .nth(authority.len())
            .is_some_and(|c| c == '.')
}

const DEFAULT_ACTIONS: &[&str] = &["create", "update", "delete"];

fn build_expanded_scopes(
    permissions: &[PermissionEntry],
    default_aud: Option<&str>,
    namespace_authority: &str,
) -> String {
    let mut scopes: Vec<String> = Vec::new();

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

                    collections
                        .iter()
                        .filter(|coll| is_under_authority(coll, namespace_authority))
                        .for_each(|coll| {
                            actions.iter().for_each(|action| {
                                scopes.push(format!("repo:{}?action={}", coll, action));
                            });
                        });
                }
            }
            "rpc" => {
                if let Some(lxms) = &perm.lxm {
                    let perm_aud = perm.aud.as_deref().or(default_aud);

                    lxms.iter().for_each(|lxm| {
                        let scope = match perm_aud {
                            Some(aud) => format!("rpc:{}?aud={}", lxm, aud),
                            None => format!("rpc:{}", lxm),
                        };
                        scopes.push(scope);
                    });
                }
            }
            _ => {}
        });

    scopes.join(" ")
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

    #[test]
    fn test_extract_namespace_authority() {
        assert_eq!(
            extract_namespace_authority("io.atcr.authFullApp"),
            "io.atcr"
        );
        assert_eq!(
            extract_namespace_authority("app.bsky.authFullApp"),
            "app.bsky"
        );
    }

    #[test]
    fn test_extract_namespace_authority_deep_nesting() {
        assert_eq!(
            extract_namespace_authority("io.atcr.sailor.star.collection"),
            "io.atcr.sailor.star"
        );
    }

    #[test]
    fn test_extract_namespace_authority_single_segment() {
        assert_eq!(extract_namespace_authority("single"), "single");
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
        assert!(expanded.contains("repo:io.atcr.manifest?action=create"));
        assert!(expanded.contains("repo:io.atcr.manifest?action=delete"));
        assert!(expanded.contains("repo:io.atcr.sailor.star?action=create"));
        assert!(!expanded.contains("app.bsky.feed.post"));
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
        assert!(expanded.contains("repo:io.atcr.manifest?action=create"));
        assert!(expanded.contains("repo:io.atcr.manifest?action=update"));
        assert!(expanded.contains("repo:io.atcr.manifest?action=delete"));
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
        assert!(expanded.contains("rpc:com.atproto.repo.getRecord?aud=*"));
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
        assert!(expanded.contains("rpc:com.atproto.repo.getRecord?aud=*"));
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

    #[tokio::test]
    async fn test_expand_include_scopes_passthrough_non_include() {
        let result = expand_include_scopes("atproto transition:generic").await;
        assert_eq!(result, "atproto transition:generic");
    }

    #[tokio::test]
    async fn test_expand_include_scopes_mixed_with_regular() {
        let result = expand_include_scopes("atproto repo:app.bsky.feed.post?action=create").await;
        assert!(result.contains("atproto"));
        assert!(result.contains("repo:app.bsky.feed.post?action=create"));
    }

    #[tokio::test]
    async fn test_cache_population_and_retrieval() {
        let cache_key = "test.cached.scope";
        let cached_value = "repo:test.cached.collection?action=create";

        {
            let mut cache = LEXICON_CACHE.write().await;
            cache.insert(
                cache_key.to_string(),
                CachedLexicon {
                    expanded_scope: cached_value.to_string(),
                    cached_at: std::time::Instant::now(),
                },
            );
        }

        let result = expand_permission_set(cache_key, None).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), cached_value);

        {
            let mut cache = LEXICON_CACHE.write().await;
            cache.remove(cache_key);
        }
    }

    #[tokio::test]
    async fn test_cache_with_aud_parameter() {
        let nsid = "test.aud.scope";
        let aud = "did:web:example.com";
        let cache_key = format!("{}?aud={}", nsid, aud);
        let cached_value = "rpc:test.aud.method?aud=did:web:example.com";

        {
            let mut cache = LEXICON_CACHE.write().await;
            cache.insert(
                cache_key.clone(),
                CachedLexicon {
                    expanded_scope: cached_value.to_string(),
                    cached_at: std::time::Instant::now(),
                },
            );
        }

        let result = expand_permission_set(nsid, Some(aud)).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), cached_value);

        {
            let mut cache = LEXICON_CACHE.write().await;
            cache.remove(&cache_key);
        }
    }

    #[tokio::test]
    async fn test_expired_cache_triggers_refresh() {
        let cache_key = "test.expired.scope";

        {
            let mut cache = LEXICON_CACHE.write().await;
            cache.insert(
                cache_key.to_string(),
                CachedLexicon {
                    expanded_scope: "old_value".to_string(),
                    cached_at: std::time::Instant::now()
                        - std::time::Duration::from_secs(CACHE_TTL_SECS + 1),
                },
            );
        }

        let result = expand_permission_set(cache_key, None).await;
        assert!(result.is_err());

        {
            let mut cache = LEXICON_CACHE.write().await;
            cache.remove(cache_key);
        }
    }

    #[test]
    fn test_nsid_authority_extraction_for_dns() {
        let nsid = "io.atcr.authFullApp";
        let parts: Vec<&str> = nsid.split('.').collect();
        let authority = parts[..2]
            .iter()
            .rev()
            .cloned()
            .collect::<Vec<_>>()
            .join(".");
        assert_eq!(authority, "atcr.io");

        let nsid2 = "app.bsky.feed.post";
        let parts2: Vec<&str> = nsid2.split('.').collect();
        let authority2 = parts2[..2]
            .iter()
            .rev()
            .cloned()
            .collect::<Vec<_>>()
            .join(".");
        assert_eq!(authority2, "bsky.app");
    }
}
