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
    collection: Option<Vec<String>>,
}

pub async fn expand_include_scopes(scope_string: &str) -> String {
    let futures: Vec<_> = scope_string
        .split_whitespace()
        .map(|scope| async move {
            match scope.strip_prefix("include:") {
                Some(nsid) => {
                    let nsid_base = nsid.split('?').next().unwrap_or(nsid);
                    expand_permission_set(nsid_base).await.unwrap_or_else(|e| {
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

async fn expand_permission_set(nsid: &str) -> Result<String, String> {
    {
        let cache = LEXICON_CACHE.read().await;
        if let Some(cached) = cache.get(nsid)
            && cached.cached_at.elapsed().as_secs() < CACHE_TTL_SECS
        {
            debug!(nsid, "Using cached permission set expansion");
            return Ok(cached.expanded_scope.clone());
        }
    }

    let parts: Vec<&str> = nsid.split('.').collect();
    if parts.len() < 3 {
        return Err(format!("Invalid NSID format: {}", nsid));
    }

    let domain_parts: Vec<&str> = parts[..2].iter().rev().cloned().collect();
    let domain = domain_parts.join(".");
    let path = parts[2..].join("/");

    let url = format!("https://{}/lexicons/{}.json", domain, path);
    debug!(nsid, url = %url, "Fetching permission set lexicon");

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

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

    let lexicon: LexiconDoc = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse lexicon: {}", e))?;

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

    let mut collections: Vec<String> = permissions
        .iter()
        .filter(|perm| perm.resource == "repo")
        .filter_map(|perm| perm.collection.as_ref())
        .flatten()
        .cloned()
        .collect();

    if collections.is_empty() {
        return Err("No repo collections found in permission-set".to_string());
    }

    collections.sort();

    let collection_params: Vec<String> = collections
        .iter()
        .map(|c| format!("collection={}", c))
        .collect();

    let expanded = format!("repo?{}", collection_params.join("&"));

    {
        let mut cache = LEXICON_CACHE.write().await;
        cache.insert(
            nsid.to_string(),
            CachedLexicon {
                expanded_scope: expanded.clone(),
                cached_at: std::time::Instant::now(),
            },
        );
    }

    debug!(nsid, expanded = %expanded, "Successfully expanded permission set");
    Ok(expanded)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_nsid_to_url() {
        let nsid = "io.atcr.authFullApp";
        let parts: Vec<&str> = nsid.split('.').collect();
        let domain_parts: Vec<&str> = parts[..2].iter().rev().cloned().collect();
        let domain = domain_parts.join(".");
        let path = parts[2..].join("/");

        assert_eq!(domain, "atcr.io");
        assert_eq!(path, "authFullApp");
    }
}
