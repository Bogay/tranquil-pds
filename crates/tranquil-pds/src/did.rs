use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

#[derive(Debug, thiserror::Error)]
pub enum DidResolutionError {
    #[error("Unsupported DID method: \"{0}\". Only did:web and did:plc are allowed in atproto")]
    UnsupportedDidMethod(String),
    #[error("Invalid did:web format")]
    InvalidDidWeb,
    #[error("HTTP request failed: {0}")]
    HttpFailed(String),
    #[error("Invalid DID document: {0}")]
    InvalidDocument(String),
    #[error("DID not found")]
    NotFound,
}

#[derive(Debug, thiserror::Error)]
pub enum ServiceResolutionError {
    #[error("DID resolution failed: {0}")]
    DidResolutionFailed(#[from] DidResolutionError),
    #[error("Service ID \"{0}\" not found in DID doc")]
    ServiceIdNotFound(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidDocument {
    pub id: String,
    #[serde(default)]
    #[serde(rename = "service")]
    pub services: Vec<DidService>,
    #[serde(default)]
    #[serde(rename = "alsoKnownAs")]
    pub also_known_as: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DidService {
    pub id: String,
    #[serde(rename = "type")]
    pub service_type: String,
    pub service_endpoint: String,
}

#[derive(Debug, Clone)]
pub struct ResolvedService {
    pub url: String,
    pub did: String,
    pub service_id: String,
}

type TimedCache<T> = RwLock<HashMap<Box<str>, (Instant, Arc<T>)>>;

pub struct DidResolver {
    did_doc_cache: TimedCache<serde_json::Value>,
    parsed_did_doc_cache: TimedCache<DidDocument>,
    service_cache: TimedCache<ResolvedService>,
    client: Client,
    cache_ttl: Duration,
    plc_directory_url: String,
}

impl DidResolver {
    pub fn new() -> Self {
        let cfg = tranquil_config::get();
        let cache_ttl_secs = cfg.plc.did_cache_ttl_secs;

        let plc_directory_url = cfg.plc.directory_url.clone();

        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .pool_max_idle_per_host(10)
            .build()
            .unwrap_or_else(|_| Client::new());

        info!("DID resolver initialized");

        Self {
            did_doc_cache: RwLock::new(HashMap::new()),
            parsed_did_doc_cache: RwLock::new(HashMap::new()),
            service_cache: RwLock::new(HashMap::new()),
            client,
            cache_ttl: Duration::from_secs(cache_ttl_secs),
            plc_directory_url,
        }
    }

    pub async fn resolve_service(
        &self,
        did: &str,
        service_id: &str,
    ) -> Result<Arc<ResolvedService>, ServiceResolutionError> {
        {
            let cache = self.service_cache.read().await;
            if let Some(cached) = cache.get(&*format!("{did}#{service_id}"))
                && cached.0.elapsed() < self.cache_ttl
            {
                return Ok(cached.1.clone());
            }
        }

        let did_doc = self.resolve_did(did).await?;
        let Some(service) = did_doc
            .services
            .iter()
            .find(|s| s.id.ends_with(&format!("#{service_id}")))
        else {
            return Err(ServiceResolutionError::ServiceIdNotFound(service_id.into()));
        };

        let resolved = Arc::new(ResolvedService {
            url: service.service_endpoint.clone(),
            did: did.into(),
            service_id: service_id.into(),
        });

        {
            let mut cache = self.service_cache.write().await;
            cache.insert(
                format!("{did}#{service_id}").into(),
                (Instant::now(), resolved.clone()),
            );
        }

        Ok(resolved)
    }

    pub async fn resolve_did(&self, did: &str) -> Result<Arc<DidDocument>, DidResolutionError> {
        {
            let cache = self.parsed_did_doc_cache.read().await;
            if let Some(cached) = cache.get(did)
                && cached.0.elapsed() < self.cache_ttl
            {
                return Ok(cached.1.clone());
            }
        }

        let resolved = Arc::new(self.resolve_did_uncached(did).await?);

        {
            let mut cache = self.parsed_did_doc_cache.write().await;
            cache.insert(did.into(), (Instant::now(), resolved.clone()));
        }

        Ok(resolved)
    }

    pub async fn refresh_did(&self, did: &str) -> Result<Arc<DidDocument>, DidResolutionError> {
        {
            let mut cache = self.parsed_did_doc_cache.write().await;
            cache.remove(did);
            let mut cache = self.service_cache.write().await;
            cache.retain(|k, _| !k.starts_with(did));
        }
        self.resolve_did(did).await
    }

    async fn resolve_did_uncached(&self, did: &str) -> Result<DidDocument, DidResolutionError> {
        if did.starts_with("did:web:") {
            self.resolve_did_web(did).await
        } else if did.starts_with("did:plc:") {
            self.resolve_did_plc(did).await
        } else {
            warn!("Unsupported DID method: {}", did);
            Err(DidResolutionError::UnsupportedDidMethod(did.into()))
        }
    }

    async fn resolve_did_web(&self, did: &str) -> Result<DidDocument, DidResolutionError> {
        let url = build_did_web_url(did)?;

        debug!("Resolving did:web {} via {}", did, url);

        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| DidResolutionError::HttpFailed(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(DidResolutionError::HttpFailed(format!(
                "HTTP {}",
                resp.status()
            )));
        }

        resp.json::<DidDocument>()
            .await
            .map_err(|e| DidResolutionError::InvalidDocument(e.to_string()))
    }

    async fn resolve_did_plc(&self, did: &str) -> Result<DidDocument, DidResolutionError> {
        let url = format!("{}/{}", self.plc_directory_url, urlencoding::encode(did));

        debug!("Resolving did:plc {} via {}", did, url);

        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| DidResolutionError::HttpFailed(e.to_string()))?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(DidResolutionError::NotFound);
        }

        if !resp.status().is_success() {
            return Err(DidResolutionError::HttpFailed(format!(
                "HTTP {}",
                resp.status()
            )));
        }

        resp.json::<DidDocument>()
            .await
            .map_err(|e| DidResolutionError::InvalidDocument(e.to_string()))
    }

    pub async fn fetch_did_document(
        &self,
        did: &str,
    ) -> Result<Arc<serde_json::Value>, DidResolutionError> {
        {
            let cache = self.did_doc_cache.read().await;
            if let Some(cached) = cache.get(did)
                && cached.0.elapsed() < self.cache_ttl
            {
                return Ok(cached.1.clone());
            }
        }

        let resolved = Arc::new(self.fetch_did_document_uncached(did).await?);

        {
            let mut cache = self.did_doc_cache.write().await;
            cache.insert(did.into(), (Instant::now(), resolved.clone()));
        }

        Ok(resolved)
    }

    // TODO: make cached version
    async fn fetch_did_document_uncached(
        &self,
        did: &str,
    ) -> Result<serde_json::Value, DidResolutionError> {
        if did.starts_with("did:web:") {
            self.fetch_did_document_web(did).await
        } else if did.starts_with("did:plc:") {
            self.fetch_did_document_plc(did).await
        } else {
            warn!("Unsupported DID method: {}", did);
            Err(DidResolutionError::UnsupportedDidMethod(did.into()))
        }
    }

    async fn fetch_did_document_web(
        &self,
        did: &str,
    ) -> Result<serde_json::Value, DidResolutionError> {
        let url = build_did_web_url(did)?;

        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| DidResolutionError::HttpFailed(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(DidResolutionError::HttpFailed(format!(
                "HTTP {}",
                resp.status()
            )));
        }

        resp.json::<serde_json::Value>()
            .await
            .map_err(|e| DidResolutionError::InvalidDocument(e.to_string()))
    }

    async fn fetch_did_document_plc(
        &self,
        did: &str,
    ) -> Result<serde_json::Value, DidResolutionError> {
        let url = format!("{}/{}", self.plc_directory_url, urlencoding::encode(did));

        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| DidResolutionError::HttpFailed(e.to_string()))?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(DidResolutionError::NotFound);
        }

        if !resp.status().is_success() {
            return Err(DidResolutionError::HttpFailed(format!(
                "HTTP {}",
                resp.status()
            )));
        }

        resp.json::<serde_json::Value>()
            .await
            .map_err(|e| DidResolutionError::InvalidDocument(e.to_string()))
    }

    pub async fn invalidate_cache(&self, did: &str) {
        let mut doc_cache = self.parsed_did_doc_cache.write().await;
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

fn build_did_web_url(did: &str) -> Result<String, DidResolutionError> {
    let host = did
        .strip_prefix("did:web:")
        .ok_or(DidResolutionError::InvalidDidWeb)?;

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
        if host.starts_with("localhost") || host.starts_with("127.0.0.1") || host.contains(':') {
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
