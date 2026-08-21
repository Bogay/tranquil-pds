use crate::cache::Cache;
use crate::types::Did;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

#[derive(Debug, thiserror::Error)]
pub enum DidResolutionError {
    #[error("Unsupported DID method: \"{0}\". Only did:web and did:plc are allowed in atproto")]
    UnsupportedDidMethod(String),
    #[error("Invalid did:web format")]
    InvalidDidWeb,
    #[error("did:web host {0} is outside the allowed host reach")]
    DidWebHostRejected(String),
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
    pub id: Did,
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
    pub did: Did,
}

pub struct DidResolver {
    cache: Arc<dyn Cache>,
    client: Client,
    cache_ttl: Duration,
    plc_directory_url: String,
    fetch_policy: tranquil_types::ReachPolicy,
}

impl DidResolver {
    pub fn new(cache: Arc<dyn Cache>) -> Self {
        let cfg = tranquil_config::get();

        let fetch_policy =
            tranquil_types::ReachPolicy::from_private_fetch(cfg.server.allow_private_fetch);
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .pool_max_idle_per_host(10)
            .redirect(tranquil_types::redirect_policy(fetch_policy))
            .dns_resolver(tranquil_types::dns_guard(fetch_policy))
            .build()
            .expect("failed to build DID resolver HTTP client");

        info!("DID resolver initialized");

        Self {
            cache,
            client,
            cache_ttl: Duration::from_secs(cfg.plc.did_cache_ttl_secs),
            plc_directory_url: cfg.plc.directory_url.clone(),
            fetch_policy,
        }
    }

    fn doc_cache_key(did: &Did) -> Result<String, DidResolutionError> {
        match (did.is_plc(), did.is_web()) {
            (true, _) => Ok(crate::cache_keys::plc_doc_key(did)),
            (_, true) => Ok(crate::cache_keys::did_web_doc_key(did)),
            _ => {
                warn!("Unsupported DID method: {}", did);
                Err(DidResolutionError::UnsupportedDidMethod(did.to_string()))
            }
        }
    }

    pub async fn resolve_service(
        &self,
        did: &Did,
        service_id: &str,
    ) -> Result<ResolvedService, ServiceResolutionError> {
        let did_doc = self.resolve_did(did).await?;
        let suffix = format!("#{service_id}");
        did_doc
            .services
            .iter()
            .find(|s| s.id.ends_with(&suffix))
            .map(|service| ResolvedService {
                url: service.service_endpoint.clone(),
                did: did.clone(),
            })
            .ok_or_else(|| ServiceResolutionError::ServiceIdNotFound(service_id.into()))
    }

    pub async fn resolve_did(&self, did: &Did) -> Result<DidDocument, DidResolutionError> {
        self.cached_did_document(did).await
    }

    pub async fn refresh_did(&self, did: &Did) -> Result<DidDocument, DidResolutionError> {
        let _ = self.cache.delete(&Self::doc_cache_key(did)?).await;
        self.resolve_did(did).await
    }

    pub async fn fetch_did_document(
        &self,
        did: &Did,
    ) -> Result<serde_json::Value, DidResolutionError> {
        self.cached_did_document(did).await
    }

    async fn cached_did_document<T: serde::de::DeserializeOwned>(
        &self,
        did: &Did,
    ) -> Result<T, DidResolutionError> {
        let cache_key = Self::doc_cache_key(did)?;
        let doc =
            crate::cache::cached_json(self.cache.as_ref(), &cache_key, self.cache_ttl, || async {
                match did.is_plc() {
                    true => self.fetch_did_document_plc(did).await,
                    false => self.fetch_did_document_web(did).await,
                }
            })
            .await?;
        serde_json::from_value(doc).map_err(|e| DidResolutionError::InvalidDocument(e.to_string()))
    }

    async fn fetch_did_document_web(
        &self,
        did: &Did,
    ) -> Result<serde_json::Value, DidResolutionError> {
        let url = build_did_web_url(did, self.fetch_policy)?;

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

        resp.json::<serde_json::Value>()
            .await
            .map_err(|e| DidResolutionError::InvalidDocument(e.to_string()))
    }

    async fn fetch_did_document_plc(
        &self,
        did: &Did,
    ) -> Result<serde_json::Value, DidResolutionError> {
        let url = format!(
            "{}/{}",
            self.plc_directory_url,
            urlencoding::encode(did.as_str())
        );

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

        resp.json::<serde_json::Value>()
            .await
            .map_err(|e| DidResolutionError::InvalidDocument(e.to_string()))
    }
}

fn build_did_web_url(
    did: &Did,
    policy: tranquil_types::ReachPolicy,
) -> Result<String, DidResolutionError> {
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

    let https = if path.is_empty() {
        format!("https://{}/.well-known/did.json", host)
    } else {
        format!("https://{}{}/did.json", host, path)
    };

    let mut url = reqwest::Url::parse(&https).map_err(|_| DidResolutionError::InvalidDidWeb)?;
    if tranquil_types::url_reach(&url) == Some(tranquil_types::HostReach::Loopback) {
        let _ = url.set_scheme("http");
    }
    match tranquil_types::url_reach_permits(&url, policy) {
        true => Ok(url.to_string()),
        false => Err(DidResolutionError::DidWebHostRejected(host)),
    }
}
