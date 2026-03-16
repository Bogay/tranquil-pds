use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::SigningKey;
use rand::rngs::OsRng;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tranquil_oauth::{
    AuthorizationServerMetadata, ClientMetadata, compute_es256_jkt, compute_pkce_challenge,
    create_dpop_proof,
};
use tranquil_types::Did;

use crate::cache::Cache;

#[derive(Error, Debug)]
pub enum CrossPdsError {
    #[error("failed to fetch OAuth metadata: {0}")]
    MetadataFetch(String),
    #[error("controller PDS has no PAR endpoint")]
    NoParEndpoint,
    #[error("PAR request failed: {0}")]
    ParFailed(String),
    #[error("token exchange failed: {0}")]
    TokenExchangeFailed(String),
    #[error("invalid token response: {0}")]
    InvalidTokenResponse(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossPdsAuthState {
    pub original_request_uri: String,
    pub controller_did: Did,
    pub controller_pds_url: String,
    pub code_verifier: String,
    pub dpop_private_key_der: String,
    pub delegated_did: Did,
    pub expected_issuer: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParResult {
    pub request_uri: String,
    pub authorize_url: String,
}

pub struct DelegationOAuthUrls {
    pub client_id: String,
    pub redirect_uri: String,
}

pub fn delegation_oauth_urls(hostname: &str) -> DelegationOAuthUrls {
    DelegationOAuthUrls {
        client_id: format!("https://{}/oauth/delegation/client-metadata", hostname),
        redirect_uri: format!("https://{}/oauth/delegation/callback", hostname),
    }
}

pub struct CrossPdsOAuthClient {
    http: Client,
    cache: Arc<dyn Cache>,
}

impl CrossPdsOAuthClient {
    pub fn new(cache: Arc<dyn Cache>) -> Self {
        let http = Client::builder()
            .timeout(Duration::from_secs(15))
            .connect_timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_else(|_| Client::new());
        Self { http, cache }
    }

    pub async fn store_auth_state(
        &self,
        state_key: &str,
        auth_state: &CrossPdsAuthState,
    ) -> Result<(), CrossPdsError> {
        let cache_key = format!("cross_pds_state:{}", state_key);
        let json_bytes = serde_json::to_vec(auth_state)
            .map_err(|e| CrossPdsError::ParFailed(format!("serialize auth state: {}", e)))?;
        let encrypted = crate::config::encrypt_key(&json_bytes)
            .map_err(|e| CrossPdsError::ParFailed(format!("encrypt auth state: {}", e)))?;
        self.cache
            .set_bytes(&cache_key, &encrypted, Duration::from_secs(600))
            .await
            .map_err(|e| CrossPdsError::ParFailed(format!("cache auth state: {}", e)))
    }

    pub async fn retrieve_auth_state(
        &self,
        state_key: &str,
    ) -> Result<CrossPdsAuthState, CrossPdsError> {
        let cache_key = format!("cross_pds_state:{}", state_key);
        let encrypted_bytes = self
            .cache
            .get_bytes(&cache_key)
            .await
            .ok_or_else(|| CrossPdsError::TokenExchangeFailed("auth state expired or not found".into()))?;
        let _ = self.cache.delete(&cache_key).await;
        let decrypted = crate::config::decrypt_key(
            &encrypted_bytes,
            Some(crate::config::ENCRYPTION_VERSION),
        )
        .map_err(|e| CrossPdsError::TokenExchangeFailed(format!("decrypt auth state: {}", e)))?;
        serde_json::from_slice(&decrypted)
            .map_err(|e| CrossPdsError::TokenExchangeFailed(format!("deserialize auth state: {}", e)))
    }

    pub async fn check_remote_is_delegated(&self, pds_url: &str, did: &str) -> Option<bool> {
        let url = format!(
            "{}/oauth/security-status?identifier={}",
            pds_url.trim_end_matches('/'),
            urlencoding::encode(did)
        );
        let resp = self.http.get(&url).send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct RemoteSecurityStatus {
            is_delegated: Option<bool>,
        }
        resp.json::<RemoteSecurityStatus>()
            .await
            .ok()
            .and_then(|s| s.is_delegated)
    }

    async fn send_with_dpop_retry(
        &self,
        signing_key: &SigningKey,
        method: &str,
        url: &str,
        params: &[(&str, String)],
        access_token_hash: Option<&str>,
    ) -> Result<reqwest::Response, String> {
        let make_proof = |nonce: Option<&str>| {
            create_dpop_proof(signing_key, method, url, nonce, access_token_hash)
                .map_err(|e| format!("{:?}", e))
        };

        let resp = self.http.post(url).header("DPoP", &make_proof(None)?).form(params)
            .send().await.map_err(|e| e.to_string())?;

        let nonce = resp.headers().get("dpop-nonce")
            .and_then(|v| v.to_str().ok()).map(|s| s.to_string());
        let needs_retry = matches!(
            resp.status(),
            reqwest::StatusCode::BAD_REQUEST | reqwest::StatusCode::UNAUTHORIZED
        );

        if needs_retry && nonce.is_some() {
            return self.http.post(url).header("DPoP", &make_proof(nonce.as_deref())?)
                .form(params).send().await.map_err(|e| e.to_string());
        }
        Ok(resp)
    }

    fn require_https(url: &str, label: &str) -> Result<(), CrossPdsError> {
        if !url.starts_with("https://") {
            return Err(CrossPdsError::MetadataFetch(format!(
                "{} must use HTTPS, got: {}",
                label, url
            )));
        }
        Ok(())
    }

    async fn resolve_authorization_server(&self, pds_url: &str) -> Result<String, CrossPdsError> {
        Self::require_https(pds_url, "PDS URL")?;

        let resource_url = format!(
            "{}/.well-known/oauth-protected-resource",
            pds_url.trim_end_matches('/')
        );
        if let Ok(resp) = self.http.get(&resource_url).send().await
            && resp.status().is_success()
        {
            #[derive(Deserialize)]
            struct ProtectedResource {
                authorization_servers: Option<Vec<String>>,
            }
            if let Ok(pr) = resp.json::<ProtectedResource>().await
                && let Some(server) = pr.authorization_servers.and_then(|s| s.into_iter().next())
            {
                Self::require_https(&server, "Authorization server")?;
                return Ok(server);
            }
        }
        Ok(pds_url.trim_end_matches('/').to_string())
    }

    pub async fn fetch_server_metadata(
        &self,
        pds_url: &str,
    ) -> Result<AuthorizationServerMetadata, CrossPdsError> {
        let cache_key = format!("cross_pds_oauth_meta:{}", pds_url);
        if let Some(cached) = self.cache.get(&cache_key).await
            && let Ok(meta) = serde_json::from_str(&cached)
        {
            return Ok(meta);
        }

        let auth_server = self.resolve_authorization_server(pds_url).await?;

        let url = format!("{}/.well-known/oauth-authorization-server", auth_server);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| CrossPdsError::MetadataFetch(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(CrossPdsError::MetadataFetch(format!(
                "HTTP {} from {}",
                resp.status(),
                url
            )));
        }

        let meta: AuthorizationServerMetadata = resp
            .json()
            .await
            .map_err(|e| CrossPdsError::MetadataFetch(e.to_string()))?;

        if let Ok(json_str) = serde_json::to_string(&meta) {
            let _ = self
                .cache
                .set(&cache_key, &json_str, Duration::from_secs(300))
                .await;
        }

        Ok(meta)
    }

    pub async fn initiate_par(
        &self,
        pds_url: &str,
        urls: &DelegationOAuthUrls,
        login_hint: Option<&str>,
        original_request_uri: &str,
        controller_did: &Did,
        delegated_did: &Did,
    ) -> Result<(ParResult, CrossPdsAuthState, String), CrossPdsError> {
        let meta = self.fetch_server_metadata(pds_url).await?;
        let par_endpoint = meta
            .pushed_authorization_request_endpoint
            .as_deref()
            .ok_or(CrossPdsError::NoParEndpoint)?;

        let code_verifier = crate::util::generate_random_token();
        let code_challenge = compute_pkce_challenge(&code_verifier);
        let state = crate::util::generate_random_token();

        let signing_key = SigningKey::random(&mut OsRng);
        let dpop_key_der = URL_SAFE_NO_PAD.encode(signing_key.to_bytes());

        let dpop_jkt = compute_es256_jkt(&signing_key)
            .map_err(|e| CrossPdsError::ParFailed(format!("{:?}", e)))?;

        let mut params = vec![
            ("response_type", "code".to_string()),
            ("client_id", urls.client_id.clone()),
            ("redirect_uri", urls.redirect_uri.clone()),
            ("scope", "atproto".to_string()),
            ("state", state.clone()),
            ("code_challenge", code_challenge),
            ("code_challenge_method", "S256".to_string()),
            ("dpop_jkt", dpop_jkt),
        ];
        if let Some(hint) = login_hint {
            params.push(("login_hint", hint.to_string()));
        }

        let resp = self
            .send_with_dpop_retry(&signing_key, "POST", par_endpoint, &params, None)
            .await
            .map_err(|e| CrossPdsError::ParFailed(e.to_string()))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(CrossPdsError::ParFailed(format!("PAR rejected: {}", body)));
        }

        #[derive(Deserialize)]
        struct ParResp {
            request_uri: String,
        }

        let par_resp: ParResp = resp
            .json()
            .await
            .map_err(|e| CrossPdsError::ParFailed(e.to_string()))?;

        let authorize_url = format!(
            "{}?request_uri={}&client_id={}",
            meta.authorization_endpoint,
            urlencoding::encode(&par_resp.request_uri),
            urlencoding::encode(&urls.client_id)
        );

        let auth_state = CrossPdsAuthState {
            original_request_uri: original_request_uri.to_string(),
            controller_did: controller_did.clone(),
            controller_pds_url: pds_url.to_string(),
            code_verifier,
            dpop_private_key_der: dpop_key_der,
            delegated_did: delegated_did.clone(),
            expected_issuer: Some(meta.issuer.clone()),
        };

        Ok((
            ParResult {
                request_uri: par_resp.request_uri,
                authorize_url,
            },
            auth_state,
            state,
        ))
    }

    pub async fn exchange_code(
        &self,
        auth_state: &CrossPdsAuthState,
        code: &str,
        client_id: &str,
        redirect_uri: &str,
    ) -> Result<String, CrossPdsError> {
        let meta = self
            .fetch_server_metadata(&auth_state.controller_pds_url)
            .await?;

        let key_bytes = URL_SAFE_NO_PAD
            .decode(&auth_state.dpop_private_key_der)
            .map_err(|e| CrossPdsError::TokenExchangeFailed(e.to_string()))?;
        let signing_key = SigningKey::from_bytes((&key_bytes[..]).into())
            .map_err(|e| CrossPdsError::TokenExchangeFailed(e.to_string()))?;

        let params = vec![
            ("grant_type", "authorization_code".to_string()),
            ("code", code.to_string()),
            ("redirect_uri", redirect_uri.to_string()),
            ("code_verifier", auth_state.code_verifier.clone()),
            ("client_id", client_id.to_string()),
        ];

        let resp = self
            .send_with_dpop_retry(&signing_key, "POST", &meta.token_endpoint, &params, None)
            .await
            .map_err(CrossPdsError::TokenExchangeFailed)?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(CrossPdsError::TokenExchangeFailed(format!(
                "Token exchange rejected: {}",
                body
            )));
        }

        #[derive(Deserialize)]
        struct TokenResp {
            sub: Option<String>,
            token_type: Option<String>,
            error: Option<String>,
            error_description: Option<String>,
        }

        let token_resp: TokenResp = resp
            .json()
            .await
            .map_err(|e| CrossPdsError::InvalidTokenResponse(e.to_string()))?;

        if let Some(ref err) = token_resp.error {
            let desc = token_resp.error_description.as_deref().unwrap_or("unknown");
            return Err(CrossPdsError::TokenExchangeFailed(format!(
                "{}: {}",
                err, desc
            )));
        }

        if let Some(ref tt) = token_resp.token_type
            && !tt.eq_ignore_ascii_case("DPoP")
        {
            return Err(CrossPdsError::InvalidTokenResponse(format!(
                "expected token_type DPoP, got {}",
                tt
            )));
        }

        token_resp
            .sub
            .ok_or_else(|| CrossPdsError::InvalidTokenResponse("missing sub claim".to_string()))
    }
}

pub fn build_client_metadata(hostname: &str) -> ClientMetadata {
    let urls = delegation_oauth_urls(hostname);
    ClientMetadata {
        client_id: urls.client_id,
        client_name: Some(hostname.to_string()),
        client_uri: Some(format!("https://{}", hostname)),
        redirect_uris: vec![urls.redirect_uri],
        grant_types: vec!["authorization_code".to_string()],
        response_types: vec!["code".to_string()],
        scope: Some("atproto".to_string()),
        dpop_bound_access_tokens: Some(true),
        token_endpoint_auth_method: Some("none".to_string()),
        application_type: Some("web".to_string()),
        ..ClientMetadata::default()
    }
}
