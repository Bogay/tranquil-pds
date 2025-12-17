use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidDocument {
    pub id: String,
    #[serde(default)]
    pub service: Vec<DidService>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DidService {
    pub id: String,
    #[serde(rename = "type")]
    pub service_type: String,
    pub service_endpoint: String,
}

#[derive(Clone)]
struct CachedAppView {
    url: String,
    did: String,
    resolved_at: Instant,
}

pub struct AppViewRegistry {
    namespace_to_did: HashMap<String, String>,
    did_cache: RwLock<HashMap<String, CachedAppView>>,
    client: Client,
    cache_ttl: Duration,
    plc_directory_url: String,
}

impl Clone for AppViewRegistry {
    fn clone(&self) -> Self {
        Self {
            namespace_to_did: self.namespace_to_did.clone(),
            did_cache: RwLock::new(HashMap::new()),
            client: self.client.clone(),
            cache_ttl: self.cache_ttl,
            plc_directory_url: self.plc_directory_url.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedAppView {
    pub url: String,
    pub did: String,
}

impl AppViewRegistry {
    pub fn new() -> Self {
        let mut namespace_to_did = HashMap::new();

        let bsky_did = std::env::var("APPVIEW_DID_BSKY")
            .unwrap_or_else(|_| "did:web:api.bsky.app".to_string());
        namespace_to_did.insert("app.bsky".to_string(), bsky_did.clone());
        namespace_to_did.insert("com.atproto".to_string(), bsky_did);

        for (key, value) in std::env::vars() {
            if let Some(namespace) = key.strip_prefix("APPVIEW_DID_") {
                let namespace = namespace.to_lowercase().replace('_', ".");
                if namespace != "bsky" {
                    namespace_to_did.insert(namespace, value);
                }
            }
        }

        let cache_ttl_secs: u64 = std::env::var("APPVIEW_CACHE_TTL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(300);

        let plc_directory_url = std::env::var("PLC_DIRECTORY_URL")
            .unwrap_or_else(|_| "https://plc.directory".to_string());

        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .pool_max_idle_per_host(10)
            .build()
            .unwrap_or_else(|_| Client::new());

        info!(
            "AppView registry initialized with {} namespace mappings",
            namespace_to_did.len()
        );
        for (ns, did) in &namespace_to_did {
            debug!("  {} -> {}", ns, did);
        }

        Self {
            namespace_to_did,
            did_cache: RwLock::new(HashMap::new()),
            client,
            cache_ttl: Duration::from_secs(cache_ttl_secs),
            plc_directory_url,
        }
    }

    pub fn register_namespace(&mut self, namespace: &str, did: &str) {
        info!("Registering AppView: {} -> {}", namespace, did);
        self.namespace_to_did
            .insert(namespace.to_string(), did.to_string());
    }

    pub async fn get_appview_for_method(&self, method: &str) -> Option<ResolvedAppView> {
        let namespace = self.extract_namespace(method)?;
        self.get_appview_for_namespace(&namespace).await
    }

    pub async fn get_appview_for_namespace(&self, namespace: &str) -> Option<ResolvedAppView> {
        let did = self.get_did_for_namespace(namespace)?;
        self.resolve_appview_did(&did).await
    }

    pub fn get_did_for_namespace(&self, namespace: &str) -> Option<String> {
        if let Some(did) = self.namespace_to_did.get(namespace) {
            return Some(did.clone());
        }

        let mut parts: Vec<&str> = namespace.split('.').collect();
        while !parts.is_empty() {
            let prefix = parts.join(".");
            if let Some(did) = self.namespace_to_did.get(&prefix) {
                return Some(did.clone());
            }
            parts.pop();
        }

        None
    }

    pub async fn resolve_appview_did(&self, did: &str) -> Option<ResolvedAppView> {
        {
            let cache = self.did_cache.read().await;
            if let Some(cached) = cache.get(did) {
                if cached.resolved_at.elapsed() < self.cache_ttl {
                    return Some(ResolvedAppView {
                        url: cached.url.clone(),
                        did: cached.did.clone(),
                    });
                }
            }
        }

        let resolved = self.resolve_did_internal(did).await?;

        {
            let mut cache = self.did_cache.write().await;
            cache.insert(
                did.to_string(),
                CachedAppView {
                    url: resolved.url.clone(),
                    did: resolved.did.clone(),
                    resolved_at: Instant::now(),
                },
            );
        }

        Some(resolved)
    }

    async fn resolve_did_internal(&self, did: &str) -> Option<ResolvedAppView> {
        let did_doc = if did.starts_with("did:web:") {
            self.resolve_did_web(did).await
        } else if did.starts_with("did:plc:") {
            self.resolve_did_plc(did).await
        } else {
            warn!("Unsupported DID method: {}", did);
            return None;
        };

        let doc = match did_doc {
            Ok(doc) => doc,
            Err(e) => {
                error!("Failed to resolve DID {}: {}", did, e);
                return None;
            }
        };

        self.extract_appview_endpoint(&doc)
    }

    async fn resolve_did_web(&self, did: &str) -> Result<DidDocument, String> {
        let host = did
            .strip_prefix("did:web:")
            .ok_or("Invalid did:web format")?;

        let (host, path) = if host.contains(':') {
            let decoded = host.replace("%3A", ":");
            let parts: Vec<&str> = decoded.splitn(2, '/').collect();
            if parts.len() > 1 {
                (parts[0].to_string(), format!("/{}", parts[1]))
            } else {
                (decoded, String::new())
            }
        } else {
            let parts: Vec<&str> = host.splitn(2, ':').collect();
            if parts.len() > 1 && parts[1].contains('/') {
                let path_parts: Vec<&str> = parts[1].splitn(2, '/').collect();
                if path_parts.len() > 1 {
                    (
                        format!("{}:{}", parts[0], path_parts[0]),
                        format!("/{}", path_parts[1]),
                    )
                } else {
                    (host.to_string(), String::new())
                }
            } else {
                (host.to_string(), String::new())
            }
        };

        let scheme =
            if host.starts_with("localhost") || host.starts_with("127.0.0.1") || host.contains(':')
            {
                "http"
            } else {
                "https"
            };

        let url = if path.is_empty() {
            format!("{}://{}/.well-known/did.json", scheme, host)
        } else {
            format!("{}://{}{}/did.json", scheme, host, path)
        };

        debug!("Resolving did:web {} via {}", did, url);

        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("HTTP request failed: {}", e))?;

        if !resp.status().is_success() {
            return Err(format!("HTTP {}", resp.status()));
        }

        resp.json::<DidDocument>()
            .await
            .map_err(|e| format!("Failed to parse DID document: {}", e))
    }

    async fn resolve_did_plc(&self, did: &str) -> Result<DidDocument, String> {
        let url = format!("{}/{}", self.plc_directory_url, urlencoding::encode(did));

        debug!("Resolving did:plc {} via {}", did, url);

        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("HTTP request failed: {}", e))?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err("DID not found".to_string());
        }

        if !resp.status().is_success() {
            return Err(format!("HTTP {}", resp.status()));
        }

        resp.json::<DidDocument>()
            .await
            .map_err(|e| format!("Failed to parse DID document: {}", e))
    }

    fn extract_appview_endpoint(&self, doc: &DidDocument) -> Option<ResolvedAppView> {
        for service in &doc.service {
            if service.service_type == "AtprotoAppView"
                || service.id.contains("atproto_appview")
                || service.id.ends_with("#bsky_appview")
            {
                return Some(ResolvedAppView {
                    url: service.service_endpoint.clone(),
                    did: doc.id.clone(),
                });
            }
        }

        for service in &doc.service {
            if service.service_type.contains("AppView") || service.id.contains("appview") {
                return Some(ResolvedAppView {
                    url: service.service_endpoint.clone(),
                    did: doc.id.clone(),
                });
            }
        }

        if let Some(service) = doc.service.first() {
            if service.service_endpoint.starts_with("http") {
                warn!(
                    "No explicit AppView service found for {}, using first service: {}",
                    doc.id, service.service_endpoint
                );
                return Some(ResolvedAppView {
                    url: service.service_endpoint.clone(),
                    did: doc.id.clone(),
                });
            }
        }

        if doc.id.starts_with("did:web:") {
            let host = doc.id.strip_prefix("did:web:")?;
            let decoded_host = host.replace("%3A", ":");
            let base_host = decoded_host.split('/').next()?;
            let scheme = if base_host.starts_with("localhost")
                || base_host.starts_with("127.0.0.1")
                || base_host.contains(':')
            {
                "http"
            } else {
                "https"
            };
            warn!(
                "No service found for {}, deriving URL from DID: {}://{}",
                doc.id, scheme, base_host
            );
            return Some(ResolvedAppView {
                url: format!("{}://{}", scheme, base_host),
                did: doc.id.clone(),
            });
        }

        None
    }

    fn extract_namespace(&self, method: &str) -> Option<String> {
        let parts: Vec<&str> = method.split('.').collect();
        if parts.len() >= 2 {
            Some(format!("{}.{}", parts[0], parts[1]))
        } else {
            None
        }
    }

    pub fn list_namespaces(&self) -> Vec<(String, String)> {
        self.namespace_to_did
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    pub async fn invalidate_cache(&self, did: &str) {
        let mut cache = self.did_cache.write().await;
        cache.remove(did);
    }

    pub async fn invalidate_all_cache(&self) {
        let mut cache = self.did_cache.write().await;
        cache.clear();
    }
}

impl Default for AppViewRegistry {
    fn default() -> Self {
        Self::new()
    }
}

pub async fn get_appview_url_for_method(registry: &AppViewRegistry, method: &str) -> Option<String> {
    registry.get_appview_for_method(method).await.map(|r| r.url)
}

pub async fn get_appview_did_for_method(registry: &AppViewRegistry, method: &str) -> Option<String> {
    registry.get_appview_for_method(method).await.map(|r| r.did)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_namespace() {
        let registry = AppViewRegistry::new();
        assert_eq!(
            registry.extract_namespace("app.bsky.actor.getProfile"),
            Some("app.bsky".to_string())
        );
        assert_eq!(
            registry.extract_namespace("com.atproto.repo.createRecord"),
            Some("com.atproto".to_string())
        );
        assert_eq!(
            registry.extract_namespace("com.whtwnd.blog.getPost"),
            Some("com.whtwnd".to_string())
        );
        assert_eq!(registry.extract_namespace("invalid"), None);
    }

    #[test]
    fn test_get_did_for_namespace() {
        let mut registry = AppViewRegistry::new();
        registry.register_namespace("com.whtwnd", "did:web:whtwnd.com");

        assert!(registry.get_did_for_namespace("app.bsky").is_some());
        assert_eq!(
            registry.get_did_for_namespace("com.whtwnd"),
            Some("did:web:whtwnd.com".to_string())
        );
        assert!(registry.get_did_for_namespace("unknown.namespace").is_none());
    }
}
