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
    jwks_cache: Arc<RwLock<HashMap<String, CachedJwks>>>,
    http_client: Client,
    cache_ttl_secs: u64,
}

struct CachedMetadata {
    metadata: ClientMetadata,
    cached_at: std::time::Instant,
}

struct CachedJwks {
    jwks: serde_json::Value,
    cached_at: std::time::Instant,
}

impl ClientMetadataCache {
    pub fn new(cache_ttl_secs: u64) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            jwks_cache: Arc::new(RwLock::new(HashMap::new())),
            http_client: Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .connect_timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_else(|_| Client::new()),
            cache_ttl_secs,
        }
    }

    fn is_loopback_client(client_id: &str) -> bool {
        if let Ok(url) = reqwest::Url::parse(client_id) {
            url.scheme() == "http" && url.host_str() == Some("localhost") && url.port().is_none()
        } else {
            false
        }
    }

    fn build_loopback_metadata(client_id: &str) -> Result<ClientMetadata, OAuthError> {
        let url = reqwest::Url::parse(client_id)
            .map_err(|_| OAuthError::InvalidClient("Invalid loopback client_id URL".to_string()))?;
        let mut redirect_uris = Vec::new();
        for (key, value) in url.query_pairs() {
            if key == "redirect_uri" {
                redirect_uris.push(value.to_string());
            }
        }
        if redirect_uris.is_empty() {
            redirect_uris.push("http://127.0.0.1/callback".to_string());
            redirect_uris.push("http://localhost/callback".to_string());
        }
        let scope = Some("atproto transition:generic transition:chat.bsky".to_string());
        Ok(ClientMetadata {
            client_id: client_id.to_string(),
            client_name: Some("Loopback Client".to_string()),
            client_uri: None,
            logo_uri: None,
            redirect_uris,
            grant_types: vec![
                "authorization_code".to_string(),
                "refresh_token".to_string(),
            ],
            response_types: vec!["code".to_string()],
            scope,
            token_endpoint_auth_method: Some("none".to_string()),
            dpop_bound_access_tokens: Some(false),
            jwks: None,
            jwks_uri: None,
            application_type: Some("native".to_string()),
        })
    }

    pub async fn get(&self, client_id: &str) -> Result<ClientMetadata, OAuthError> {
        if Self::is_loopback_client(client_id) {
            return Self::build_loopback_metadata(client_id);
        }
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.get(client_id)
                && cached.cached_at.elapsed().as_secs() < self.cache_ttl_secs
            {
                return Ok(cached.metadata.clone());
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

    pub async fn get_jwks(
        &self,
        metadata: &ClientMetadata,
    ) -> Result<serde_json::Value, OAuthError> {
        if let Some(jwks) = &metadata.jwks {
            return Ok(jwks.clone());
        }
        let jwks_uri = metadata.jwks_uri.as_ref().ok_or_else(|| {
            OAuthError::InvalidClient(
                "Client using private_key_jwt must have jwks or jwks_uri".to_string(),
            )
        })?;
        {
            let cache = self.jwks_cache.read().await;
            if let Some(cached) = cache.get(jwks_uri)
                && cached.cached_at.elapsed().as_secs() < self.cache_ttl_secs
            {
                return Ok(cached.jwks.clone());
            }
        }
        let jwks = self.fetch_jwks(jwks_uri).await?;
        {
            let mut cache = self.jwks_cache.write().await;
            cache.insert(
                jwks_uri.clone(),
                CachedJwks {
                    jwks: jwks.clone(),
                    cached_at: std::time::Instant::now(),
                },
            );
        }
        Ok(jwks)
    }

    async fn fetch_jwks(&self, jwks_uri: &str) -> Result<serde_json::Value, OAuthError> {
        if !jwks_uri.starts_with("https://")
            && (!jwks_uri.starts_with("http://")
                || (!jwks_uri.contains("localhost") && !jwks_uri.contains("127.0.0.1")))
        {
            return Err(OAuthError::InvalidClient(
                "jwks_uri must use https (except for localhost)".to_string(),
            ));
        }
        let response = self
            .http_client
            .get(jwks_uri)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| {
                OAuthError::InvalidClient(format!("Failed to fetch JWKS from {}: {}", jwks_uri, e))
            })?;
        if !response.status().is_success() {
            return Err(OAuthError::InvalidClient(format!(
                "Failed to fetch JWKS: HTTP {}",
                response.status()
            )));
        }
        let jwks: serde_json::Value = response
            .json()
            .await
            .map_err(|e| OAuthError::InvalidClient(format!("Invalid JWKS JSON: {}", e)))?;
        if jwks.get("keys").and_then(|k| k.as_array()).is_none() {
            return Err(OAuthError::InvalidClient(
                "JWKS must contain a 'keys' array".to_string(),
            ));
        }
        Ok(jwks)
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
            .map_err(|e| {
                OAuthError::InvalidClient(format!("Failed to fetch client metadata: {}", e))
            })?;
        if !response.status().is_success() {
            return Err(OAuthError::InvalidClient(format!(
                "Failed to fetch client metadata: HTTP {}",
                response.status()
            )));
        }
        let mut metadata: ClientMetadata = response.json().await.map_err(|e| {
            OAuthError::InvalidClient(format!("Invalid client metadata JSON: {}", e))
        })?;
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
            && !metadata
                .grant_types
                .contains(&"authorization_code".to_string())
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
        if metadata.redirect_uris.contains(&redirect_uri.to_string()) {
            return Ok(());
        }
        if Self::is_loopback_client(&metadata.client_id)
            && let Ok(req_url) = reqwest::Url::parse(redirect_uri)
        {
            let req_host = req_url.host_str().unwrap_or("");
            let is_loopback_redirect = req_url.scheme() == "http"
                && (req_host == "localhost" || req_host == "127.0.0.1" || req_host == "[::1]");
            if is_loopback_redirect {
                for registered in &metadata.redirect_uris {
                    if let Ok(reg_url) = reqwest::Url::parse(registered) {
                        let reg_host = reg_url.host_str().unwrap_or("");
                        let hosts_match = (req_host == "localhost" && reg_host == "localhost")
                            || (req_host == "127.0.0.1" && reg_host == "127.0.0.1")
                            || (req_host == "[::1]" && reg_host == "[::1]")
                            || (req_host == "localhost" && reg_host == "127.0.0.1")
                            || (req_host == "127.0.0.1" && reg_host == "localhost");
                        if hosts_match && req_url.path() == reg_url.path() {
                            return Ok(());
                        }
                    }
                }
            }
        }
        Err(OAuthError::InvalidRequest(
            "redirect_uri not registered for client".to_string(),
        ))
    }

    fn validate_redirect_uri_format(&self, uri: &str) -> Result<(), OAuthError> {
        if uri.contains('#') {
            return Err(OAuthError::InvalidClient(
                "redirect_uri must not contain a fragment".to_string(),
            ));
        }
        let parsed = reqwest::Url::parse(uri)
            .map_err(|_| OAuthError::InvalidClient(format!("Invalid redirect_uri: {}", uri)))?;
        let scheme = parsed.scheme();
        if scheme == "http" {
            let host = parsed.host_str().unwrap_or("");
            if host != "localhost" && host != "127.0.0.1" && host != "[::1]" {
                return Err(OAuthError::InvalidClient(
                    "http redirect_uri only allowed for localhost".to_string(),
                ));
            }
        } else if scheme == "https" {
        } else if scheme.chars().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || c == '+' || c == '.' || c == '-'
        }) {
            if !scheme
                .chars()
                .next()
                .map(|c| c.is_ascii_lowercase())
                .unwrap_or(false)
            {
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
        self.token_endpoint_auth_method.as_deref().unwrap_or("none")
    }
}

pub async fn verify_client_auth(
    cache: &ClientMetadataCache,
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
            verify_private_key_jwt_async(cache, metadata, client_assertion).await
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

async fn verify_private_key_jwt_async(
    cache: &ClientMetadataCache,
    metadata: &ClientMetadata,
    client_assertion: &str,
) -> Result<(), OAuthError> {
    use base64::{
        Engine as _,
        engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    };
    let parts: Vec<&str> = client_assertion.split('.').collect();
    if parts.len() != 3 {
        return Err(OAuthError::InvalidClient(
            "Invalid client_assertion format".to_string(),
        ));
    }
    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .or_else(|_| STANDARD.decode(parts[0]))
        .map_err(|_| OAuthError::InvalidClient("Invalid assertion header encoding".to_string()))?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|_| OAuthError::InvalidClient("Invalid assertion header JSON".to_string()))?;
    let alg = header
        .get("alg")
        .and_then(|a| a.as_str())
        .ok_or_else(|| OAuthError::InvalidClient("Missing alg in client_assertion".to_string()))?;
    if !matches!(
        alg,
        "ES256" | "ES384" | "RS256" | "RS384" | "RS512" | "EdDSA"
    ) {
        return Err(OAuthError::InvalidClient(format!(
            "Unsupported client_assertion algorithm: {}",
            alg
        )));
    }
    let kid = header.get("kid").and_then(|k| k.as_str());
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .or_else(|_| STANDARD.decode(parts[1]))
        .map_err(|e| {
            tracing::warn!(error = %e, payload_part = parts[1], "Invalid assertion payload encoding");
            OAuthError::InvalidClient("Invalid assertion payload encoding".to_string())
        })?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|_| OAuthError::InvalidClient("Invalid assertion payload JSON".to_string()))?;
    let iss = payload
        .get("iss")
        .and_then(|i| i.as_str())
        .ok_or_else(|| OAuthError::InvalidClient("Missing iss in client_assertion".to_string()))?;
    if iss != metadata.client_id {
        return Err(OAuthError::InvalidClient(
            "client_assertion iss does not match client_id".to_string(),
        ));
    }
    let sub = payload
        .get("sub")
        .and_then(|s| s.as_str())
        .ok_or_else(|| OAuthError::InvalidClient("Missing sub in client_assertion".to_string()))?;
    if sub != metadata.client_id {
        return Err(OAuthError::InvalidClient(
            "client_assertion sub does not match client_id".to_string(),
        ));
    }
    let now = chrono::Utc::now().timestamp();
    let exp = payload.get("exp").and_then(|e| e.as_i64());
    let iat = payload.get("iat").and_then(|i| i.as_i64());
    if let Some(exp) = exp {
        if exp < now {
            return Err(OAuthError::InvalidClient(
                "client_assertion has expired".to_string(),
            ));
        }
    } else if let Some(iat) = iat {
        let max_age_secs = 300;
        if now - iat > max_age_secs {
            tracing::warn!(
                iat = iat,
                now = now,
                "client_assertion too old (no exp, using iat)"
            );
            return Err(OAuthError::InvalidClient(
                "client_assertion is too old".to_string(),
            ));
        }
    } else {
        return Err(OAuthError::InvalidClient(
            "client_assertion must have exp or iat claim".to_string(),
        ));
    }
    if let Some(iat) = iat
        && iat > now + 60
    {
        return Err(OAuthError::InvalidClient(
            "client_assertion iat is in the future".to_string(),
        ));
    }
    let jwks = cache.get_jwks(metadata).await?;
    let keys = jwks
        .get("keys")
        .and_then(|k| k.as_array())
        .ok_or_else(|| OAuthError::InvalidClient("Invalid JWKS: missing keys array".to_string()))?;
    let matching_keys: Vec<&serde_json::Value> = if let Some(kid) = kid {
        keys.iter()
            .filter(|k| k.get("kid").and_then(|v| v.as_str()) == Some(kid))
            .collect()
    } else {
        keys.iter().collect()
    };
    if matching_keys.is_empty() {
        return Err(OAuthError::InvalidClient(
            "No matching key found in client JWKS".to_string(),
        ));
    }
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| OAuthError::InvalidClient("Invalid signature encoding".to_string()))?;
    for key in matching_keys {
        let key_alg = key.get("alg").and_then(|a| a.as_str());
        if key_alg.is_some() && key_alg != Some(alg) {
            continue;
        }
        let kty = key.get("kty").and_then(|k| k.as_str()).unwrap_or("");
        let verified = match (alg, kty) {
            ("ES256", "EC") => verify_es256(key, &signing_input, &signature_bytes),
            ("ES384", "EC") => verify_es384(key, &signing_input, &signature_bytes),
            ("RS256" | "RS384" | "RS512", "RSA") => {
                verify_rsa(alg, key, &signing_input, &signature_bytes)
            }
            ("EdDSA", "OKP") => verify_eddsa(key, &signing_input, &signature_bytes),
            _ => continue,
        };
        if verified.is_ok() {
            return Ok(());
        }
    }
    Err(OAuthError::InvalidClient(
        "client_assertion signature verification failed".to_string(),
    ))
}

fn verify_es256(
    key: &serde_json::Value,
    signing_input: &str,
    signature: &[u8],
) -> Result<(), OAuthError> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use p256::EncodedPoint;
    use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
    let x = key
        .get("x")
        .and_then(|v| v.as_str())
        .ok_or_else(|| OAuthError::InvalidClient("Missing x coordinate in EC key".to_string()))?;
    let y = key
        .get("y")
        .and_then(|v| v.as_str())
        .ok_or_else(|| OAuthError::InvalidClient("Missing y coordinate in EC key".to_string()))?;
    let x_bytes = URL_SAFE_NO_PAD
        .decode(x)
        .map_err(|_| OAuthError::InvalidClient("Invalid x coordinate encoding".to_string()))?;
    let y_bytes = URL_SAFE_NO_PAD
        .decode(y)
        .map_err(|_| OAuthError::InvalidClient("Invalid y coordinate encoding".to_string()))?;
    let mut point_bytes = vec![0x04];
    point_bytes.extend_from_slice(&x_bytes);
    point_bytes.extend_from_slice(&y_bytes);
    let point = EncodedPoint::from_bytes(&point_bytes)
        .map_err(|_| OAuthError::InvalidClient("Invalid EC point".to_string()))?;
    let verifying_key = VerifyingKey::from_encoded_point(&point)
        .map_err(|_| OAuthError::InvalidClient("Invalid EC key".to_string()))?;
    let sig = Signature::from_slice(signature)
        .map_err(|_| OAuthError::InvalidClient("Invalid ES256 signature format".to_string()))?;
    verifying_key
        .verify(signing_input.as_bytes(), &sig)
        .map_err(|_| OAuthError::InvalidClient("ES256 signature verification failed".to_string()))
}

fn verify_es384(
    key: &serde_json::Value,
    signing_input: &str,
    signature: &[u8],
) -> Result<(), OAuthError> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use p384::EncodedPoint;
    use p384::ecdsa::{Signature, VerifyingKey, signature::Verifier};
    let x = key
        .get("x")
        .and_then(|v| v.as_str())
        .ok_or_else(|| OAuthError::InvalidClient("Missing x coordinate in EC key".to_string()))?;
    let y = key
        .get("y")
        .and_then(|v| v.as_str())
        .ok_or_else(|| OAuthError::InvalidClient("Missing y coordinate in EC key".to_string()))?;
    let x_bytes = URL_SAFE_NO_PAD
        .decode(x)
        .map_err(|_| OAuthError::InvalidClient("Invalid x coordinate encoding".to_string()))?;
    let y_bytes = URL_SAFE_NO_PAD
        .decode(y)
        .map_err(|_| OAuthError::InvalidClient("Invalid y coordinate encoding".to_string()))?;
    let mut point_bytes = vec![0x04];
    point_bytes.extend_from_slice(&x_bytes);
    point_bytes.extend_from_slice(&y_bytes);
    let point = EncodedPoint::from_bytes(&point_bytes)
        .map_err(|_| OAuthError::InvalidClient("Invalid EC point".to_string()))?;
    let verifying_key = VerifyingKey::from_encoded_point(&point)
        .map_err(|_| OAuthError::InvalidClient("Invalid EC key".to_string()))?;
    let sig = Signature::from_slice(signature)
        .map_err(|_| OAuthError::InvalidClient("Invalid ES384 signature format".to_string()))?;
    verifying_key
        .verify(signing_input.as_bytes(), &sig)
        .map_err(|_| OAuthError::InvalidClient("ES384 signature verification failed".to_string()))
}

fn verify_rsa(
    _alg: &str,
    _key: &serde_json::Value,
    _signing_input: &str,
    _signature: &[u8],
) -> Result<(), OAuthError> {
    Err(OAuthError::InvalidClient(
        "RSA signature verification not yet supported - use EC keys".to_string(),
    ))
}

fn verify_eddsa(
    key: &serde_json::Value,
    signing_input: &str,
    signature: &[u8],
) -> Result<(), OAuthError> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let crv = key.get("crv").and_then(|c| c.as_str()).unwrap_or("");
    if crv != "Ed25519" {
        return Err(OAuthError::InvalidClient(format!(
            "Unsupported EdDSA curve: {}",
            crv
        )));
    }
    let x = key
        .get("x")
        .and_then(|v| v.as_str())
        .ok_or_else(|| OAuthError::InvalidClient("Missing x in OKP key".to_string()))?;
    let x_bytes = URL_SAFE_NO_PAD
        .decode(x)
        .map_err(|_| OAuthError::InvalidClient("Invalid x encoding".to_string()))?;
    let key_bytes: [u8; 32] = x_bytes
        .try_into()
        .map_err(|_| OAuthError::InvalidClient("Invalid Ed25519 key length".to_string()))?;
    let verifying_key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| OAuthError::InvalidClient("Invalid Ed25519 key".to_string()))?;
    let sig_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| OAuthError::InvalidClient("Invalid EdDSA signature length".to_string()))?;
    let sig = Signature::from_bytes(&sig_bytes);
    verifying_key
        .verify(signing_input.as_bytes(), &sig)
        .map_err(|_| OAuthError::InvalidClient("EdDSA signature verification failed".to_string()))
}
