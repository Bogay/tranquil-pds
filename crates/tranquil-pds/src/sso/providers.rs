use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, jwk::JwkSet};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::{OnceCell, RwLock};
use tranquil_db_traits::SsoProviderType;

use super::config::{AppleProviderConfig, ProviderConfig, SsoConfig};

const SSO_HTTP_TIMEOUT: Duration = Duration::from_secs(15);

fn create_http_client() -> Client {
    Client::builder()
        .timeout(SSO_HTTP_TIMEOUT)
        .connect_timeout(Duration::from_secs(5))
        .build()
        .expect("Failed to create HTTP client")
}

#[derive(Debug, Error)]
pub enum SsoError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Provider error: {0}")]
    Provider(String),

    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    #[error("OIDC discovery failed: {0}")]
    Discovery(String),

    #[error("JWT validation failed: {0}")]
    JwtValidation(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoTokenResponse {
    pub access_token: String,
    pub token_type: Option<String>,
    pub id_token: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SsoUserInfo {
    pub provider_user_id: String,
    pub username: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
}

pub struct AuthUrlResult {
    pub url: String,
    pub code_verifier: Option<String>,
}

#[async_trait]
pub trait SsoProvider: Send + Sync {
    fn provider_type(&self) -> SsoProviderType;
    fn display_name(&self) -> &str;
    fn icon_name(&self) -> &str;

    async fn build_auth_url(
        &self,
        state: &str,
        redirect_uri: &str,
        nonce: Option<&str>,
    ) -> Result<AuthUrlResult, SsoError>;

    async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
        code_verifier: Option<&str>,
    ) -> Result<SsoTokenResponse, SsoError>;

    async fn get_user_info(
        &self,
        access_token: &str,
        id_token: Option<&str>,
        expected_nonce: Option<&str>,
    ) -> Result<SsoUserInfo, SsoError>;
}

pub struct GitHubProvider {
    client_id: String,
    client_secret: String,
    http_client: Client,
}

impl GitHubProvider {
    pub fn new(config: &ProviderConfig) -> Self {
        Self {
            client_id: config.client_id.clone(),
            client_secret: config.client_secret.clone(),
            http_client: create_http_client(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct GitHubTokenResponse {
    access_token: String,
    token_type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubUser {
    id: i64,
    login: String,
}

#[derive(Debug, Deserialize)]
struct GitHubEmail {
    email: String,
    primary: bool,
    verified: bool,
}

#[async_trait]
impl SsoProvider for GitHubProvider {
    fn provider_type(&self) -> SsoProviderType {
        SsoProviderType::Github
    }

    fn display_name(&self) -> &str {
        "GitHub"
    }

    fn icon_name(&self) -> &str {
        "github"
    }

    async fn build_auth_url(
        &self,
        state: &str,
        redirect_uri: &str,
        _nonce: Option<&str>,
    ) -> Result<AuthUrlResult, SsoError> {
        let url = format!(
            "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&state={}&scope=read:user%20user:email",
            urlencoding::encode(&self.client_id),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(state),
        );
        Ok(AuthUrlResult {
            url,
            code_verifier: None,
        })
    }

    async fn exchange_code(
        &self,
        code: &str,
        _redirect_uri: &str,
        _code_verifier: Option<&str>,
    ) -> Result<SsoTokenResponse, SsoError> {
        let resp = self
            .http_client
            .post("https://github.com/login/oauth/access_token")
            .header("Accept", "application/json")
            .form(&[
                ("client_id", &self.client_id),
                ("client_secret", &self.client_secret),
                ("code", &code.to_string()),
            ])
            .send()
            .await?;

        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(SsoError::Provider(format!("GitHub token error: {}", text)));
        }

        let data: GitHubTokenResponse = resp.json().await?;
        Ok(SsoTokenResponse {
            access_token: data.access_token,
            token_type: data.token_type,
            id_token: None,
        })
    }

    async fn get_user_info(
        &self,
        access_token: &str,
        _id_token: Option<&str>,
        _expected_nonce: Option<&str>,
    ) -> Result<SsoUserInfo, SsoError> {
        let user: GitHubUser = self
            .http_client
            .get("https://api.github.com/user")
            .header("Authorization", format!("Bearer {}", access_token))
            .header("User-Agent", "tranquil-pds")
            .send()
            .await?
            .json()
            .await?;

        let emails_result: Result<Vec<GitHubEmail>, _> = self
            .http_client
            .get("https://api.github.com/user/emails")
            .header("Authorization", format!("Bearer {}", access_token))
            .header("User-Agent", "tranquil-pds")
            .send()
            .await?
            .json()
            .await;

        let emails = match emails_result {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(
                    github_user_id = %user.id,
                    error = %e,
                    "Failed to fetch GitHub user emails, continuing without email"
                );
                Vec::new()
            }
        };

        let primary_email = emails
            .iter()
            .find(|e| e.primary && e.verified)
            .or_else(|| emails.iter().find(|e| e.verified))
            .map(|e| e.email.clone());

        Ok(SsoUserInfo {
            provider_user_id: user.id.to_string(),
            username: Some(user.login),
            email: primary_email,
            email_verified: Some(true),
        })
    }
}

pub struct DiscordProvider {
    client_id: String,
    client_secret: String,
    http_client: Client,
}

impl DiscordProvider {
    pub fn new(config: &ProviderConfig) -> Self {
        Self {
            client_id: config.client_id.clone(),
            client_secret: config.client_secret.clone(),
            http_client: create_http_client(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct DiscordTokenResponse {
    access_token: String,
    token_type: String,
}

#[derive(Debug, Deserialize)]
struct DiscordUser {
    id: String,
    username: String,
    email: Option<String>,
    verified: Option<bool>,
}

#[async_trait]
impl SsoProvider for DiscordProvider {
    fn provider_type(&self) -> SsoProviderType {
        SsoProviderType::Discord
    }

    fn display_name(&self) -> &str {
        "Discord"
    }

    fn icon_name(&self) -> &str {
        "discord"
    }

    async fn build_auth_url(
        &self,
        state: &str,
        redirect_uri: &str,
        _nonce: Option<&str>,
    ) -> Result<AuthUrlResult, SsoError> {
        let url = format!(
            "https://discord.com/api/oauth2/authorize?client_id={}&redirect_uri={}&state={}&response_type=code&scope=identify%20email",
            urlencoding::encode(&self.client_id),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(state),
        );
        Ok(AuthUrlResult {
            url,
            code_verifier: None,
        })
    }

    async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
        _code_verifier: Option<&str>,
    ) -> Result<SsoTokenResponse, SsoError> {
        let resp = self
            .http_client
            .post("https://discord.com/api/oauth2/token")
            .form(&[
                ("client_id", &self.client_id),
                ("client_secret", &self.client_secret),
                ("code", &code.to_string()),
                ("grant_type", &"authorization_code".to_string()),
                ("redirect_uri", &redirect_uri.to_string()),
            ])
            .send()
            .await?;

        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(SsoError::Provider(format!("Discord token error: {}", text)));
        }

        let data: DiscordTokenResponse = resp.json().await?;
        Ok(SsoTokenResponse {
            access_token: data.access_token,
            token_type: Some(data.token_type),
            id_token: None,
        })
    }

    async fn get_user_info(
        &self,
        access_token: &str,
        _id_token: Option<&str>,
        _expected_nonce: Option<&str>,
    ) -> Result<SsoUserInfo, SsoError> {
        let user: DiscordUser = self
            .http_client
            .get("https://discord.com/api/users/@me")
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await?
            .json()
            .await?;

        Ok(SsoUserInfo {
            provider_user_id: user.id,
            username: Some(user.username),
            email: user.email,
            email_verified: user.verified,
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct OidcDiscoveryConfig {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: Option<String>,
    pub jwks_uri: Option<String>,
}

struct OidcDiscoveryCache {
    config: OidcDiscoveryConfig,
    jwks: Option<JwkSet>,
}

pub struct OidcProvider {
    provider_type: SsoProviderType,
    client_id: String,
    client_secret: String,
    issuer: String,
    display_name: String,
    http_client: Client,
    discovery_cache: OnceCell<OidcDiscoveryCache>,
}

impl OidcProvider {
    pub fn new(
        provider_type: SsoProviderType,
        config: &ProviderConfig,
        default_issuer: Option<&str>,
        default_name: &str,
    ) -> Option<Self> {
        let issuer = config
            .issuer
            .clone()
            .or_else(|| default_issuer.map(String::from))?;

        Some(Self {
            provider_type,
            client_id: config.client_id.clone(),
            client_secret: config.client_secret.clone(),
            issuer,
            display_name: config
                .display_name
                .clone()
                .unwrap_or_else(|| default_name.to_string()),
            http_client: create_http_client(),
            discovery_cache: OnceCell::new(),
        })
    }

    async fn get_discovery(&self) -> Result<&OidcDiscoveryCache, SsoError> {
        self.discovery_cache
            .get_or_try_init(|| async {
                let discovery_url = format!(
                    "{}/.well-known/openid-configuration",
                    self.issuer.trim_end_matches('/')
                );

                tracing::debug!(
                    provider = %self.provider_type.as_str(),
                    url = %discovery_url,
                    "Fetching OIDC discovery document"
                );

                let resp = self
                    .http_client
                    .get(&discovery_url)
                    .send()
                    .await
                    .map_err(|e| SsoError::Discovery(e.to_string()))?;

                if !resp.status().is_success() {
                    return Err(SsoError::Discovery(format!(
                        "Discovery endpoint returned {}",
                        resp.status()
                    )));
                }

                let config: OidcDiscoveryConfig = resp
                    .json()
                    .await
                    .map_err(|e| SsoError::Discovery(e.to_string()))?;

                let jwks = match &config.jwks_uri {
                    Some(jwks_uri) => {
                        tracing::debug!(
                            provider = %self.provider_type.as_str(),
                            url = %jwks_uri,
                            "Fetching JWKS"
                        );
                        let jwks_resp =
                            self.http_client.get(jwks_uri).send().await.map_err(|e| {
                                SsoError::Discovery(format!("JWKS fetch failed: {}", e))
                            })?;

                        if jwks_resp.status().is_success() {
                            Some(jwks_resp.json::<JwkSet>().await.map_err(|e| {
                                SsoError::Discovery(format!("JWKS parse failed: {}", e))
                            })?)
                        } else {
                            tracing::warn!(
                                provider = %self.provider_type.as_str(),
                                status = %jwks_resp.status(),
                                "JWKS fetch returned non-success status"
                            );
                            None
                        }
                    }
                    None => None,
                };

                Ok(OidcDiscoveryCache { config, jwks })
            })
            .await
    }

    fn generate_pkce() -> (String, String) {
        use rand::RngCore;
        let mut verifier_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut verifier_bytes);
        let verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);

        use sha2::{Digest, Sha256};
        let challenge_bytes = Sha256::digest(verifier.as_bytes());
        let challenge = URL_SAFE_NO_PAD.encode(challenge_bytes);

        (verifier, challenge)
    }

    fn validate_id_token(
        &self,
        id_token: &str,
        jwks: &JwkSet,
        expected_nonce: Option<&str>,
    ) -> Result<IdTokenClaims, SsoError> {
        let header = jsonwebtoken::decode_header(id_token)
            .map_err(|e| SsoError::JwtValidation(format!("Invalid JWT header: {}", e)))?;

        let kid = header
            .kid
            .as_ref()
            .ok_or_else(|| SsoError::JwtValidation("JWT missing kid header".to_string()))?;

        let jwk = jwks
            .find(kid)
            .ok_or_else(|| SsoError::JwtValidation(format!("No matching JWK for kid: {}", kid)))?;

        let decoding_key = DecodingKey::from_jwk(jwk)
            .map_err(|e| SsoError::JwtValidation(format!("Invalid JWK: {}", e)))?;

        let algorithm = match header.alg {
            jsonwebtoken::Algorithm::RS256 => Algorithm::RS256,
            jsonwebtoken::Algorithm::RS384 => Algorithm::RS384,
            jsonwebtoken::Algorithm::RS512 => Algorithm::RS512,
            jsonwebtoken::Algorithm::ES256 => Algorithm::ES256,
            jsonwebtoken::Algorithm::ES384 => Algorithm::ES384,
            alg => {
                return Err(SsoError::JwtValidation(format!(
                    "Unsupported algorithm: {:?}",
                    alg
                )));
            }
        };

        let mut validation = Validation::new(algorithm);
        validation.set_audience(&[&self.client_id]);
        validation.set_issuer(&[&self.issuer]);

        let token_data =
            jsonwebtoken::decode::<IdTokenClaims>(id_token, &decoding_key, &validation)
                .map_err(|e| SsoError::JwtValidation(format!("JWT validation failed: {}", e)))?;

        if let Some(expected) = expected_nonce {
            match &token_data.claims.nonce {
                Some(actual) if actual == expected => {}
                Some(actual) => {
                    return Err(SsoError::JwtValidation(format!(
                        "Nonce mismatch: expected {}, got {}",
                        expected, actual
                    )));
                }
                None => {
                    return Err(SsoError::JwtValidation(
                        "Missing nonce in id_token".to_string(),
                    ));
                }
            }
        }

        Ok(token_data.claims)
    }
}

#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    sub: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    email_verified: Option<bool>,
    #[serde(default)]
    preferred_username: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
}

#[async_trait]
impl SsoProvider for OidcProvider {
    fn provider_type(&self) -> SsoProviderType {
        self.provider_type
    }

    fn display_name(&self) -> &str {
        &self.display_name
    }

    fn icon_name(&self) -> &str {
        self.provider_type.icon_name()
    }

    async fn build_auth_url(
        &self,
        state: &str,
        redirect_uri: &str,
        nonce: Option<&str>,
    ) -> Result<AuthUrlResult, SsoError> {
        let (verifier, challenge) = Self::generate_pkce();

        let auth_endpoint = match self.provider_type {
            SsoProviderType::Google => "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
            SsoProviderType::Gitlab => {
                format!("{}/oauth/authorize", self.issuer.trim_end_matches('/'))
            }
            _ => {
                let discovery = self.get_discovery().await?;
                discovery.config.authorization_endpoint.clone()
            }
        };

        let mut url = format!(
            "{}?client_id={}&redirect_uri={}&state={}&response_type=code&scope=openid%20email%20profile&code_challenge={}&code_challenge_method=S256",
            auth_endpoint,
            urlencoding::encode(&self.client_id),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(state),
            urlencoding::encode(&challenge),
        );

        if let Some(n) = nonce {
            url.push_str(&format!("&nonce={}", urlencoding::encode(n)));
        }

        Ok(AuthUrlResult {
            url,
            code_verifier: Some(verifier),
        })
    }

    async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
        code_verifier: Option<&str>,
    ) -> Result<SsoTokenResponse, SsoError> {
        let token_endpoint = match self.provider_type {
            SsoProviderType::Google => "https://oauth2.googleapis.com/token".to_string(),
            SsoProviderType::Gitlab => format!("{}/oauth/token", self.issuer.trim_end_matches('/')),
            _ => {
                let discovery = self.get_discovery().await?;
                discovery.config.token_endpoint.clone()
            }
        };

        let mut params: HashMap<&str, &str> = HashMap::new();
        params.insert("client_id", &self.client_id);
        params.insert("client_secret", &self.client_secret);
        params.insert("code", code);
        params.insert("redirect_uri", redirect_uri);
        params.insert("grant_type", "authorization_code");

        if let Some(verifier) = code_verifier {
            params.insert("code_verifier", verifier);
        }

        let resp = self
            .http_client
            .post(&token_endpoint)
            .form(&params)
            .send()
            .await?;

        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(SsoError::Provider(format!("OIDC token error: {}", text)));
        }

        #[derive(Deserialize)]
        struct TokenResp {
            access_token: String,
            token_type: Option<String>,
            id_token: Option<String>,
        }

        let data: TokenResp = resp.json().await?;
        Ok(SsoTokenResponse {
            access_token: data.access_token,
            token_type: data.token_type,
            id_token: data.id_token,
        })
    }

    async fn get_user_info(
        &self,
        access_token: &str,
        id_token: Option<&str>,
        expected_nonce: Option<&str>,
    ) -> Result<SsoUserInfo, SsoError> {
        if let Some(token) = id_token {
            let discovery = self.get_discovery().await?;
            if let Some(ref jwks) = discovery.jwks {
                match self.validate_id_token(token, jwks, expected_nonce) {
                    Ok(claims) => {
                        tracing::debug!(
                            provider = %self.provider_type.as_str(),
                            sub = %claims.sub,
                            "Successfully validated id_token"
                        );
                        return Ok(SsoUserInfo {
                            provider_user_id: claims.sub,
                            username: claims.preferred_username.or(claims.name),
                            email: claims.email,
                            email_verified: claims.email_verified,
                        });
                    }
                    Err(e) => {
                        tracing::warn!(
                            provider = %self.provider_type.as_str(),
                            error = %e,
                            "id_token validation failed, falling back to userinfo endpoint"
                        );
                    }
                }
            }
        }

        let userinfo_endpoint = match self.provider_type {
            SsoProviderType::Google => {
                "https://openidconnect.googleapis.com/v1/userinfo".to_string()
            }
            SsoProviderType::Gitlab => {
                format!("{}/oauth/userinfo", self.issuer.trim_end_matches('/'))
            }
            _ => {
                let discovery = self.get_discovery().await?;
                discovery
                    .config
                    .userinfo_endpoint
                    .clone()
                    .ok_or_else(|| SsoError::Discovery("No userinfo endpoint".to_string()))?
            }
        };

        let resp = self
            .http_client
            .get(&userinfo_endpoint)
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await?;

        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(SsoError::Provider(format!("Userinfo error: {}", text)));
        }

        #[derive(Deserialize)]
        struct UserInfo {
            sub: String,
            preferred_username: Option<String>,
            name: Option<String>,
            email: Option<String>,
            email_verified: Option<bool>,
        }

        let info: UserInfo = resp.json().await?;
        Ok(SsoUserInfo {
            provider_user_id: info.sub,
            username: info.preferred_username.or(info.name),
            email: info.email,
            email_verified: info.email_verified,
        })
    }
}

struct CachedClientSecret {
    secret: String,
    expires_at: u64,
}

pub struct AppleProvider {
    client_id: String,
    team_id: String,
    key_id: String,
    private_key_pem: String,
    http_client: Client,
    client_secret_cache: RwLock<Option<CachedClientSecret>>,
    jwks_cache: OnceCell<JwkSet>,
}

impl AppleProvider {
    pub fn new(config: &AppleProviderConfig) -> Result<Self, SsoError> {
        let key_pem = config.private_key_pem.replace("\\n", "\n");

        jsonwebtoken::EncodingKey::from_ec_pem(key_pem.as_bytes())
            .map_err(|e| SsoError::Provider(format!("Invalid Apple private key: {}", e)))?;

        Ok(Self {
            client_id: config.client_id.clone(),
            team_id: config.team_id.clone(),
            key_id: config.key_id.clone(),
            private_key_pem: key_pem,
            http_client: create_http_client(),
            client_secret_cache: RwLock::new(None),
            jwks_cache: OnceCell::new(),
        })
    }

    fn generate_client_secret(&self) -> Result<(String, u64), SsoError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let exp = now + (150 * 24 * 60 * 60);

        #[derive(Serialize)]
        struct AppleClientSecretClaims {
            iss: String,
            iat: u64,
            exp: u64,
            aud: String,
            sub: String,
        }

        let claims = AppleClientSecretClaims {
            iss: self.team_id.clone(),
            iat: now,
            exp,
            aud: "https://appleid.apple.com".to_string(),
            sub: self.client_id.clone(),
        };

        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.key_id.clone());

        let encoding_key =
            EncodingKey::from_ec_pem(self.private_key_pem.as_bytes()).map_err(|e| {
                SsoError::Provider(format!("Invalid Apple private key for encoding: {}", e))
            })?;

        let token = jsonwebtoken::encode(&header, &claims, &encoding_key).map_err(|e| {
            SsoError::Provider(format!("Failed to generate Apple client secret: {}", e))
        })?;

        Ok((token, exp))
    }

    async fn get_client_secret(&self) -> Result<String, SsoError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        {
            let cache = self.client_secret_cache.read().await;
            if let Some(ref cached) = *cache
                && cached.expires_at > now + 3600 {
                    return Ok(cached.secret.clone());
                }
        }

        let (secret, expires_at) = self.generate_client_secret()?;

        {
            let mut cache = self.client_secret_cache.write().await;
            *cache = Some(CachedClientSecret {
                secret: secret.clone(),
                expires_at,
            });
        }

        Ok(secret)
    }

    async fn get_jwks(&self) -> Result<&JwkSet, SsoError> {
        self.jwks_cache
            .get_or_try_init(|| async {
                tracing::debug!("Fetching Apple JWKS");
                let resp = self
                    .http_client
                    .get("https://appleid.apple.com/auth/keys")
                    .send()
                    .await
                    .map_err(|e| SsoError::Discovery(format!("Apple JWKS fetch failed: {}", e)))?;

                if !resp.status().is_success() {
                    return Err(SsoError::Discovery(format!(
                        "Apple JWKS returned {}",
                        resp.status()
                    )));
                }

                resp.json::<JwkSet>()
                    .await
                    .map_err(|e| SsoError::Discovery(format!("Apple JWKS parse failed: {}", e)))
            })
            .await
    }

    fn validate_id_token(
        &self,
        id_token: &str,
        jwks: &JwkSet,
        expected_nonce: Option<&str>,
    ) -> Result<AppleIdTokenClaims, SsoError> {
        let header = jsonwebtoken::decode_header(id_token)
            .map_err(|e| SsoError::JwtValidation(format!("Invalid JWT header: {}", e)))?;

        let kid = header
            .kid
            .as_ref()
            .ok_or_else(|| SsoError::JwtValidation("JWT missing kid header".to_string()))?;

        let jwk = jwks
            .find(kid)
            .ok_or_else(|| SsoError::JwtValidation(format!("No matching JWK for kid: {}", kid)))?;

        let decoding_key = DecodingKey::from_jwk(jwk)
            .map_err(|e| SsoError::JwtValidation(format!("Invalid JWK: {}", e)))?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[&self.client_id]);
        validation.set_issuer(&["https://appleid.apple.com"]);

        let token_data =
            jsonwebtoken::decode::<AppleIdTokenClaims>(id_token, &decoding_key, &validation)
                .map_err(|e| SsoError::JwtValidation(format!("JWT validation failed: {}", e)))?;

        if let Some(expected) = expected_nonce {
            match &token_data.claims.nonce {
                Some(actual) if actual == expected => {}
                Some(actual) => {
                    return Err(SsoError::JwtValidation(format!(
                        "Nonce mismatch: expected {}, got {}",
                        expected, actual
                    )));
                }
                None => {
                    return Err(SsoError::JwtValidation(
                        "Missing nonce in id_token".to_string(),
                    ));
                }
            }
        }

        Ok(token_data.claims)
    }
}

#[derive(Debug, Deserialize)]
struct AppleIdTokenClaims {
    sub: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    email_verified: Option<bool>,
    #[serde(default)]
    nonce: Option<String>,
}

#[async_trait]
impl SsoProvider for AppleProvider {
    fn provider_type(&self) -> SsoProviderType {
        SsoProviderType::Apple
    }

    fn display_name(&self) -> &str {
        "Apple"
    }

    fn icon_name(&self) -> &str {
        "apple"
    }

    async fn build_auth_url(
        &self,
        state: &str,
        redirect_uri: &str,
        nonce: Option<&str>,
    ) -> Result<AuthUrlResult, SsoError> {
        let mut url = format!(
            "https://appleid.apple.com/auth/authorize?client_id={}&redirect_uri={}&state={}&response_type=code&scope=name%20email&response_mode=form_post",
            urlencoding::encode(&self.client_id),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(state),
        );

        if let Some(n) = nonce {
            url.push_str(&format!("&nonce={}", urlencoding::encode(n)));
        }

        Ok(AuthUrlResult {
            url,
            code_verifier: None,
        })
    }

    async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
        _code_verifier: Option<&str>,
    ) -> Result<SsoTokenResponse, SsoError> {
        let client_secret = self.get_client_secret().await?;

        let resp = self
            .http_client
            .post("https://appleid.apple.com/auth/token")
            .form(&[
                ("client_id", &self.client_id),
                ("client_secret", &client_secret),
                ("code", &code.to_string()),
                ("grant_type", &"authorization_code".to_string()),
                ("redirect_uri", &redirect_uri.to_string()),
            ])
            .send()
            .await?;

        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(SsoError::Provider(format!("Apple token error: {}", text)));
        }

        #[derive(Deserialize)]
        struct AppleTokenResp {
            access_token: String,
            token_type: Option<String>,
            id_token: Option<String>,
        }

        let data: AppleTokenResp = resp.json().await?;
        Ok(SsoTokenResponse {
            access_token: data.access_token,
            token_type: data.token_type,
            id_token: data.id_token,
        })
    }

    async fn get_user_info(
        &self,
        _access_token: &str,
        id_token: Option<&str>,
        expected_nonce: Option<&str>,
    ) -> Result<SsoUserInfo, SsoError> {
        let id_token = id_token.ok_or_else(|| {
            SsoError::InvalidResponse("Apple did not return an id_token".to_string())
        })?;

        let jwks = self.get_jwks().await?;
        let claims = self.validate_id_token(id_token, jwks, expected_nonce)?;

        tracing::debug!(
            sub = %claims.sub,
            email = ?claims.email,
            "Successfully validated Apple id_token"
        );

        Ok(SsoUserInfo {
            provider_user_id: claims.sub,
            username: None,
            email: claims.email,
            email_verified: claims.email_verified,
        })
    }
}

#[derive(Clone)]
pub struct SsoManager {
    providers: HashMap<SsoProviderType, Arc<dyn SsoProvider>>,
}

impl SsoManager {
    pub fn from_config(config: &SsoConfig) -> Self {
        let mut providers: HashMap<SsoProviderType, Arc<dyn SsoProvider>> = HashMap::new();

        if let Some(ref cfg) = config.github {
            providers.insert(SsoProviderType::Github, Arc::new(GitHubProvider::new(cfg)));
        }

        if let Some(ref cfg) = config.discord {
            providers.insert(
                SsoProviderType::Discord,
                Arc::new(DiscordProvider::new(cfg)),
            );
        }

        if let Some(ref cfg) = config.google
            && let Some(provider) = OidcProvider::new(
                SsoProviderType::Google,
                cfg,
                Some("https://accounts.google.com"),
                "Google",
            ) {
                providers.insert(SsoProviderType::Google, Arc::new(provider));
            }

        if let Some(ref cfg) = config.gitlab
            && let Some(provider) = OidcProvider::new(SsoProviderType::Gitlab, cfg, None, "GitLab")
            {
                providers.insert(SsoProviderType::Gitlab, Arc::new(provider));
            }

        if let Some(ref cfg) = config.oidc
            && let Some(provider) = OidcProvider::new(
                SsoProviderType::Oidc,
                cfg,
                None,
                cfg.display_name.as_deref().unwrap_or("SSO"),
            ) {
                providers.insert(SsoProviderType::Oidc, Arc::new(provider));
            }

        if let Some(ref cfg) = config.apple {
            match AppleProvider::new(cfg) {
                Ok(provider) => {
                    providers.insert(SsoProviderType::Apple, Arc::new(provider));
                }
                Err(e) => {
                    tracing::error!(error = %e, "Failed to initialize Apple SSO provider");
                }
            }
        }

        Self { providers }
    }

    pub fn get_provider(&self, provider_type: SsoProviderType) -> Option<Arc<dyn SsoProvider>> {
        self.providers.get(&provider_type).cloned()
    }

    pub fn enabled_providers(&self) -> Vec<(SsoProviderType, &str, &str)> {
        self.providers
            .iter()
            .map(|(t, p)| (*t, p.display_name(), p.icon_name()))
            .collect()
    }

    pub fn is_any_enabled(&self) -> bool {
        !self.providers.is_empty()
    }
}

impl Default for SsoManager {
    fn default() -> Self {
        Self::from_config(SsoConfig::get())
    }
}
