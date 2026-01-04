use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
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
struct CachedDid {
    url: String,
    did: String,
    resolved_at: Instant,
}

#[derive(Clone)]
struct CachedDidDocument {
    document: serde_json::Value,
    resolved_at: Instant,
}

#[derive(Debug, Clone)]
pub struct ResolvedService {
    pub url: String,
    pub did: String,
}

#[derive(Clone)]
pub struct DidResolver {
    did_cache: Arc<RwLock<HashMap<String, CachedDid>>>,
    did_doc_cache: Arc<RwLock<HashMap<String, CachedDidDocument>>>,
    client: Client,
    cache_ttl: Duration,
    plc_directory_url: String,
}

impl DidResolver {
    pub fn new() -> Self {
        let cache_ttl_secs: u64 = std::env::var("DID_CACHE_TTL_SECS")
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

        info!("DID resolver initialized");

        Self {
            did_cache: Arc::new(RwLock::new(HashMap::new())),
            did_doc_cache: Arc::new(RwLock::new(HashMap::new())),
            client,
            cache_ttl: Duration::from_secs(cache_ttl_secs),
            plc_directory_url,
        }
    }

    fn build_did_web_url(did: &str) -> Result<String, String> {
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

        Ok(url)
    }

    pub async fn resolve_did(&self, did: &str) -> Option<ResolvedService> {
        {
            let cache = self.did_cache.read().await;
            if let Some(cached) = cache.get(did)
                && cached.resolved_at.elapsed() < self.cache_ttl
            {
                return Some(ResolvedService {
                    url: cached.url.clone(),
                    did: cached.did.clone(),
                });
            }
        }

        let resolved = self.resolve_did_internal(did).await?;

        {
            let mut cache = self.did_cache.write().await;
            cache.insert(
                did.to_string(),
                CachedDid {
                    url: resolved.url.clone(),
                    did: resolved.did.clone(),
                    resolved_at: Instant::now(),
                },
            );
        }

        Some(resolved)
    }

    pub async fn refresh_did(&self, did: &str) -> Option<ResolvedService> {
        {
            let mut cache = self.did_cache.write().await;
            cache.remove(did);
        }
        self.resolve_did(did).await
    }

    async fn resolve_did_internal(&self, did: &str) -> Option<ResolvedService> {
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

        self.extract_service_endpoint(&doc)
    }

    async fn resolve_did_web(&self, did: &str) -> Result<DidDocument, String> {
        let url = Self::build_did_web_url(did)?;

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

    fn extract_service_endpoint(&self, doc: &DidDocument) -> Option<ResolvedService> {
        for service in &doc.service {
            if service.service_type == "AtprotoAppView"
                || service.id.contains("atproto_appview")
                || service.id.ends_with("#bsky_appview")
            {
                return Some(ResolvedService {
                    url: service.service_endpoint.clone(),
                    did: doc.id.clone(),
                });
            }
        }

        for service in &doc.service {
            if service.service_type.contains("AppView") || service.id.contains("appview") {
                return Some(ResolvedService {
                    url: service.service_endpoint.clone(),
                    did: doc.id.clone(),
                });
            }
        }

        if let Some(service) = doc.service.first()
            && service.service_endpoint.starts_with("http")
        {
            warn!(
                "No explicit AppView service found for {}, using first service: {}",
                doc.id, service.service_endpoint
            );
            return Some(ResolvedService {
                url: service.service_endpoint.clone(),
                did: doc.id.clone(),
            });
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
            return Some(ResolvedService {
                url: format!("{}://{}", scheme, base_host),
                did: doc.id.clone(),
            });
        }

        None
    }

    pub async fn resolve_did_document(&self, did: &str) -> Option<serde_json::Value> {
        {
            let cache = self.did_doc_cache.read().await;
            if let Some(cached) = cache.get(did)
                && cached.resolved_at.elapsed() < self.cache_ttl
            {
                return Some(cached.document.clone());
            }
        }

        let result = if did.starts_with("did:web:") {
            self.fetch_did_document_web(did).await
        } else if did.starts_with("did:plc:") {
            self.fetch_did_document_plc(did).await
        } else {
            warn!("Unsupported DID method for document resolution: {}", did);
            return None;
        };

        match result {
            Ok(doc) => {
                let mut cache = self.did_doc_cache.write().await;
                cache.insert(
                    did.to_string(),
                    CachedDidDocument {
                        document: doc.clone(),
                        resolved_at: Instant::now(),
                    },
                );
                Some(doc)
            }
            Err(e) => {
                warn!("Failed to resolve DID document for {}: {}", did, e);
                None
            }
        }
    }

    async fn fetch_did_document_web(&self, did: &str) -> Result<serde_json::Value, String> {
        let url = Self::build_did_web_url(did)?;

        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("HTTP request failed: {}", e))?;

        if !resp.status().is_success() {
            return Err(format!("HTTP {}", resp.status()));
        }

        resp.json::<serde_json::Value>()
            .await
            .map_err(|e| format!("Failed to parse DID document: {}", e))
    }

    async fn fetch_did_document_plc(&self, did: &str) -> Result<serde_json::Value, String> {
        let url = format!("{}/{}", self.plc_directory_url, urlencoding::encode(did));

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

        resp.json::<serde_json::Value>()
            .await
            .map_err(|e| format!("Failed to parse DID document: {}", e))
    }

    pub async fn invalidate_cache(&self, did: &str) {
        let mut cache = self.did_cache.write().await;
        cache.remove(did);
        drop(cache);
        let mut doc_cache = self.did_doc_cache.write().await;
        doc_cache.remove(did);
    }
}

impl Default for DidResolver {
    fn default() -> Self {
        Self::new()
    }
}

pub fn create_did_resolver() -> Arc<DidResolver> {
    Arc::new(DidResolver::new())
}
