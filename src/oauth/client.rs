use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::OAuthError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientMetadata {
    pub client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub grant_types: Vec<String>,
    #[serde(default)]
    pub response_types: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_bound_access_tokens: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_type: Option<String>,
}

impl Default for ClientMetadata {
    fn default() -> Self {
        Self {
            client_id: String::new(),
            client_name: None,
            client_uri: None,
            logo_uri: None,
            redirect_uris: Vec::new(),
            grant_types: vec!["authorization_code".to_string()],
            response_types: vec!["code".to_string()],
            scope: None,
            token_endpoint_auth_method: Some("none".to_string()),
            dpop_bound_access_tokens: None,
            jwks: None,
            jwks_uri: None,
            application_type: None,
        }
    }
}

#[derive(Clone)]
pub struct ClientMetadataCache {
    cache: Arc<RwLock<HashMap<String, CachedMetadata>>>,
    http_client: Client,
    cache_ttl_secs: u64,
}

struct CachedMetadata {
    metadata: ClientMetadata,
    cached_at: std::time::Instant,
}

impl ClientMetadataCache {
    pub fn new(cache_ttl_secs: u64) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            http_client: Client::new(),
            cache_ttl_secs,
        }
    }

    pub async fn get(&self, client_id: &str) -> Result<ClientMetadata, OAuthError> {
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.get(client_id) {
                if cached.cached_at.elapsed().as_secs() < self.cache_ttl_secs {
                    return Ok(cached.metadata.clone());
                }
            }
        }

        let metadata = self.fetch_metadata(client_id).await?;

        {
            let mut cache = self.cache.write().await;
            cache.insert(
                client_id.to_string(),
                CachedMetadata {
                    metadata: metadata.clone(),
                    cached_at: std::time::Instant::now(),
                },
            );
        }

        Ok(metadata)
    }

    async fn fetch_metadata(&self, client_id: &str) -> Result<ClientMetadata, OAuthError> {
        if !client_id.starts_with("http://") && !client_id.starts_with("https://") {
            return Err(OAuthError::InvalidClient(
                "client_id must be a URL".to_string(),
            ));
        }

        if client_id.starts_with("http://")
            && !client_id.contains("localhost")
            && !client_id.contains("127.0.0.1")
        {
            return Err(OAuthError::InvalidClient(
                "Non-localhost client_id must use https".to_string(),
            ));
        }

        let response = self
            .http_client
            .get(client_id)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| OAuthError::InvalidClient(format!("Failed to fetch client metadata: {}", e)))?;

        if !response.status().is_success() {
            return Err(OAuthError::InvalidClient(format!(
                "Failed to fetch client metadata: HTTP {}",
                response.status()
            )));
        }

        let mut metadata: ClientMetadata = response
            .json()
            .await
            .map_err(|e| OAuthError::InvalidClient(format!("Invalid client metadata JSON: {}", e)))?;

        if metadata.client_id.is_empty() {
            metadata.client_id = client_id.to_string();
        } else if metadata.client_id != client_id {
            return Err(OAuthError::InvalidClient(
                "client_id in metadata does not match request".to_string(),
            ));
        }

        self.validate_metadata(&metadata)?;

        Ok(metadata)
    }

    fn validate_metadata(&self, metadata: &ClientMetadata) -> Result<(), OAuthError> {
        if metadata.redirect_uris.is_empty() {
            return Err(OAuthError::InvalidClient(
                "redirect_uris is required".to_string(),
            ));
        }

        for uri in &metadata.redirect_uris {
            self.validate_redirect_uri_format(uri)?;
        }

        if !metadata.grant_types.is_empty()
            && !metadata.grant_types.contains(&"authorization_code".to_string())
        {
            return Err(OAuthError::InvalidClient(
                "authorization_code grant type is required".to_string(),
            ));
        }

        if !metadata.response_types.is_empty()
            && !metadata.response_types.contains(&"code".to_string())
        {
            return Err(OAuthError::InvalidClient(
                "code response type is required".to_string(),
            ));
        }

        Ok(())
    }

    pub fn validate_redirect_uri(
        &self,
        metadata: &ClientMetadata,
        redirect_uri: &str,
    ) -> Result<(), OAuthError> {
        if !metadata.redirect_uris.contains(&redirect_uri.to_string()) {
            return Err(OAuthError::InvalidRequest(
                "redirect_uri not registered for client".to_string(),
            ));
        }
        Ok(())
    }

    fn validate_redirect_uri_format(&self, uri: &str) -> Result<(), OAuthError> {
        if uri.contains('#') {
            return Err(OAuthError::InvalidClient(
                "redirect_uri must not contain a fragment".to_string(),
            ));
        }

        let parsed = reqwest::Url::parse(uri).map_err(|_| {
            OAuthError::InvalidClient(format!("Invalid redirect_uri: {}", uri))
        })?;

        let scheme = parsed.scheme();

        if scheme == "http" {
            let host = parsed.host_str().unwrap_or("");
            if host != "localhost" && host != "127.0.0.1" && host != "[::1]" {
                return Err(OAuthError::InvalidClient(
                    "http redirect_uri only allowed for localhost".to_string(),
                ));
            }
        } else if scheme == "https" {
        } else if scheme.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '+' || c == '.' || c == '-') {
            if !scheme.chars().next().map(|c| c.is_ascii_lowercase()).unwrap_or(false) {
                return Err(OAuthError::InvalidClient(format!(
                    "Invalid redirect_uri scheme: {}",
                    scheme
                )));
            }
        } else {
            return Err(OAuthError::InvalidClient(format!(
                "Invalid redirect_uri scheme: {}",
                scheme
            )));
        }

        Ok(())
    }
}

impl ClientMetadata {
    pub fn requires_dpop(&self) -> bool {
        self.dpop_bound_access_tokens.unwrap_or(false)
    }

    pub fn auth_method(&self) -> &str {
        self.token_endpoint_auth_method
            .as_deref()
            .unwrap_or("none")
    }
}

pub fn verify_client_auth(
    metadata: &ClientMetadata,
    client_auth: &super::ClientAuth,
) -> Result<(), OAuthError> {
    let expected_method = metadata.auth_method();

    match (expected_method, client_auth) {
        ("none", super::ClientAuth::None) => Ok(()),

        ("none", _) => Err(OAuthError::InvalidClient(
            "Client is configured for no authentication, but credentials were provided".to_string(),
        )),

        ("private_key_jwt", super::ClientAuth::PrivateKeyJwt { client_assertion }) => {
            verify_private_key_jwt(metadata, client_assertion)
        }

        ("private_key_jwt", _) => Err(OAuthError::InvalidClient(
            "Client requires private_key_jwt authentication".to_string(),
        )),

        ("client_secret_post", super::ClientAuth::SecretPost { .. }) => {
            Err(OAuthError::InvalidClient(
                "client_secret_post is not supported for ATProto OAuth".to_string(),
            ))
        }

        ("client_secret_basic", super::ClientAuth::SecretBasic { .. }) => {
            Err(OAuthError::InvalidClient(
                "client_secret_basic is not supported for ATProto OAuth".to_string(),
            ))
        }

        (method, _) => Err(OAuthError::InvalidClient(format!(
            "Unsupported or mismatched authentication method: {}",
            method
        ))),
    }
}

fn verify_private_key_jwt(
    metadata: &ClientMetadata,
    client_assertion: &str,
) -> Result<(), OAuthError> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    let parts: Vec<&str> = client_assertion.split('.').collect();
    if parts.len() != 3 {
        return Err(OAuthError::InvalidClient("Invalid client_assertion format".to_string()));
    }

    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| OAuthError::InvalidClient("Invalid assertion header encoding".to_string()))?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|_| OAuthError::InvalidClient("Invalid assertion header JSON".to_string()))?;

    let alg = header.get("alg").and_then(|a| a.as_str()).ok_or_else(|| {
        OAuthError::InvalidClient("Missing alg in client_assertion".to_string())
    })?;

    if !matches!(alg, "ES256" | "ES384" | "RS256" | "RS384" | "RS512" | "EdDSA") {
        return Err(OAuthError::InvalidClient(format!(
            "Unsupported client_assertion algorithm: {}",
            alg
        )));
    }

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| OAuthError::InvalidClient("Invalid assertion payload encoding".to_string()))?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|_| OAuthError::InvalidClient("Invalid assertion payload JSON".to_string()))?;

    let iss = payload.get("iss").and_then(|i| i.as_str()).ok_or_else(|| {
        OAuthError::InvalidClient("Missing iss in client_assertion".to_string())
    })?;
    if iss != metadata.client_id {
        return Err(OAuthError::InvalidClient(
            "client_assertion iss does not match client_id".to_string(),
        ));
    }

    let sub = payload.get("sub").and_then(|s| s.as_str()).ok_or_else(|| {
        OAuthError::InvalidClient("Missing sub in client_assertion".to_string())
    })?;
    if sub != metadata.client_id {
        return Err(OAuthError::InvalidClient(
            "client_assertion sub does not match client_id".to_string(),
        ));
    }

    let exp = payload.get("exp").and_then(|e| e.as_i64()).ok_or_else(|| {
        OAuthError::InvalidClient("Missing exp in client_assertion".to_string())
    })?;
    let now = chrono::Utc::now().timestamp();
    if exp < now {
        return Err(OAuthError::InvalidClient("client_assertion has expired".to_string()));
    }

    let iat = payload.get("iat").and_then(|i| i.as_i64());
    if let Some(iat) = iat {
        if iat > now + 60 {
            return Err(OAuthError::InvalidClient(
                "client_assertion iat is in the future".to_string(),
            ));
        }
    }

    if metadata.jwks.is_none() && metadata.jwks_uri.is_none() {
        return Err(OAuthError::InvalidClient(
            "Client using private_key_jwt must have jwks or jwks_uri".to_string(),
        ));
    }

    Err(OAuthError::InvalidClient(
        "private_key_jwt signature verification not yet implemented - use 'none' auth method".to_string(),
    ))
}
