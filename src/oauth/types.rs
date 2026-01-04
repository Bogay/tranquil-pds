use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestId(pub String);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenId(pub String);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceId(pub String);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionId(pub String);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Code(pub String);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshToken(pub String);

impl RequestId {
    pub fn generate() -> Self {
        Self(format!(
            "urn:ietf:params:oauth:request_uri:{}",
            uuid::Uuid::new_v4()
        ))
    }
}

impl TokenId {
    pub fn generate() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }
}

impl DeviceId {
    pub fn generate() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }
}

impl SessionId {
    pub fn generate() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }
}

impl Code {
    pub fn generate() -> Self {
        use rand::Rng;
        let bytes: [u8; 32] = rand::thread_rng().r#gen();
        Self(base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            bytes,
        ))
    }
}

impl RefreshToken {
    pub fn generate() -> Self {
        use rand::Rng;
        let bytes: [u8; 32] = rand::thread_rng().r#gen();
        Self(base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            bytes,
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method")]
pub enum ClientAuth {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "client_secret_basic")]
    SecretBasic { client_secret: String },
    #[serde(rename = "client_secret_post")]
    SecretPost { client_secret: String },
    #[serde(rename = "private_key_jwt")]
    PrivateKeyJwt { client_assertion: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationRequestParameters {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub response_mode: Option<String>,
    pub login_hint: Option<String>,
    pub dpop_jkt: Option<String>,
    #[serde(flatten)]
    pub extra: Option<JsonValue>,
}

#[derive(Debug, Clone)]
pub struct RequestData {
    pub client_id: String,
    pub client_auth: Option<ClientAuth>,
    pub parameters: AuthorizationRequestParameters,
    pub expires_at: DateTime<Utc>,
    pub did: Option<String>,
    pub device_id: Option<String>,
    pub code: Option<String>,
    pub controller_did: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DeviceData {
    pub session_id: String,
    pub user_agent: Option<String>,
    pub ip_address: String,
    pub last_seen_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct TokenData {
    pub did: String,
    pub token_id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub client_id: String,
    pub client_auth: ClientAuth,
    pub device_id: Option<String>,
    pub parameters: AuthorizationRequestParameters,
    pub details: Option<JsonValue>,
    pub code: Option<String>,
    pub current_refresh_token: Option<String>,
    pub scope: Option<String>,
    pub controller_did: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizedClientData {
    pub scope: Option<String>,
    pub remember: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthClientMetadata {
    pub client_id: String,
    pub client_name: Option<String>,
    pub client_uri: Option<String>,
    pub logo_uri: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Option<Vec<String>>,
    pub response_types: Option<Vec<String>>,
    pub scope: Option<String>,
    pub token_endpoint_auth_method: Option<String>,
    pub dpop_bound_access_tokens: Option<bool>,
    pub jwks: Option<JsonValue>,
    pub jwks_uri: Option<String>,
    pub application_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedResourceMetadata {
    pub resource: String,
    pub authorization_servers: Vec<String>,
    pub bearer_methods_supported: Vec<String>,
    pub scopes_supported: Vec<String>,
    pub resource_documentation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationServerMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub registration_endpoint: Option<String>,
    pub scopes_supported: Option<Vec<String>>,
    pub response_types_supported: Vec<String>,
    pub response_modes_supported: Option<Vec<String>>,
    pub grant_types_supported: Option<Vec<String>>,
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    pub code_challenge_methods_supported: Option<Vec<String>>,
    pub pushed_authorization_request_endpoint: Option<String>,
    pub require_pushed_authorization_requests: Option<bool>,
    pub dpop_signing_alg_values_supported: Option<Vec<String>>,
    pub authorization_response_iss_parameter_supported: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParResponse {
    pub request_uri: String,
    pub expires_in: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DPoPClaims {
    pub jti: String,
    pub htm: String,
    pub htu: String,
    pub iat: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ath: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkPublicKey {
    pub kty: String,
    pub crv: Option<String>,
    pub x: Option<String>,
    pub y: Option<String>,
    #[serde(rename = "use")]
    pub key_use: Option<String>,
    pub kid: Option<String>,
    pub alg: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: Vec<JwkPublicKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthFlowState {
    Pending,
    Authenticated {
        did: String,
        device_id: Option<String>,
    },
    Authorized {
        did: String,
        device_id: Option<String>,
        code: String,
    },
    Expired,
}

impl AuthFlowState {
    pub fn from_request_data(data: &RequestData) -> Self {
        if data.expires_at < chrono::Utc::now() {
            return AuthFlowState::Expired;
        }
        match (&data.did, &data.code) {
            (Some(did), Some(code)) => AuthFlowState::Authorized {
                did: did.clone(),
                device_id: data.device_id.clone(),
                code: code.clone(),
            },
            (Some(did), None) => AuthFlowState::Authenticated {
                did: did.clone(),
                device_id: data.device_id.clone(),
            },
            (None, _) => AuthFlowState::Pending,
        }
    }

    pub fn is_pending(&self) -> bool {
        matches!(self, AuthFlowState::Pending)
    }

    pub fn is_authenticated(&self) -> bool {
        matches!(self, AuthFlowState::Authenticated { .. })
    }

    pub fn is_authorized(&self) -> bool {
        matches!(self, AuthFlowState::Authorized { .. })
    }

    pub fn is_expired(&self) -> bool {
        matches!(self, AuthFlowState::Expired)
    }

    pub fn can_authenticate(&self) -> bool {
        matches!(self, AuthFlowState::Pending)
    }

    pub fn can_authorize(&self) -> bool {
        matches!(self, AuthFlowState::Authenticated { .. })
    }

    pub fn can_exchange(&self) -> bool {
        matches!(self, AuthFlowState::Authorized { .. })
    }

    pub fn did(&self) -> Option<&str> {
        match self {
            AuthFlowState::Authenticated { did, .. } | AuthFlowState::Authorized { did, .. } => {
                Some(did)
            }
            _ => None,
        }
    }

    pub fn code(&self) -> Option<&str> {
        match self {
            AuthFlowState::Authorized { code, .. } => Some(code),
            _ => None,
        }
    }
}

impl std::fmt::Display for AuthFlowState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthFlowState::Pending => write!(f, "pending"),
            AuthFlowState::Authenticated { did, .. } => write!(f, "authenticated ({})", did),
            AuthFlowState::Authorized { did, code, .. } => {
                write!(
                    f,
                    "authorized ({}, code={}...)",
                    did,
                    &code[..8.min(code.len())]
                )
            }
            AuthFlowState::Expired => write!(f, "expired"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshTokenState {
    Valid,
    Used {
        at: chrono::DateTime<chrono::Utc>,
    },
    InGracePeriod {
        rotated_at: chrono::DateTime<chrono::Utc>,
    },
    Expired,
    Revoked,
}

impl RefreshTokenState {
    pub fn is_valid(&self) -> bool {
        matches!(self, RefreshTokenState::Valid)
    }

    pub fn is_usable(&self) -> bool {
        matches!(
            self,
            RefreshTokenState::Valid | RefreshTokenState::InGracePeriod { .. }
        )
    }

    pub fn is_used(&self) -> bool {
        matches!(self, RefreshTokenState::Used { .. })
    }

    pub fn is_in_grace_period(&self) -> bool {
        matches!(self, RefreshTokenState::InGracePeriod { .. })
    }

    pub fn is_expired(&self) -> bool {
        matches!(self, RefreshTokenState::Expired)
    }

    pub fn is_revoked(&self) -> bool {
        matches!(self, RefreshTokenState::Revoked)
    }
}

impl std::fmt::Display for RefreshTokenState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RefreshTokenState::Valid => write!(f, "valid"),
            RefreshTokenState::Used { at } => write!(f, "used ({})", at),
            RefreshTokenState::InGracePeriod { rotated_at } => {
                write!(f, "grace period (rotated {})", rotated_at)
            }
            RefreshTokenState::Expired => write!(f, "expired"),
            RefreshTokenState::Revoked => write!(f, "revoked"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    fn make_request_data(
        did: Option<String>,
        code: Option<String>,
        expires_in: Duration,
    ) -> RequestData {
        RequestData {
            client_id: "test-client".into(),
            client_auth: None,
            parameters: AuthorizationRequestParameters {
                response_type: "code".into(),
                client_id: "test-client".into(),
                redirect_uri: "https://example.com/callback".into(),
                scope: Some("atproto".into()),
                state: None,
                code_challenge: "test".into(),
                code_challenge_method: "S256".into(),
                response_mode: None,
                login_hint: None,
                dpop_jkt: None,
                extra: None,
            },
            expires_at: Utc::now() + expires_in,
            did,
            device_id: None,
            code,
            controller_did: None,
        }
    }

    #[test]
    fn test_auth_flow_state_pending() {
        let data = make_request_data(None, None, Duration::minutes(5));
        let state = AuthFlowState::from_request_data(&data);
        assert!(state.is_pending());
        assert!(!state.is_authenticated());
        assert!(!state.is_authorized());
        assert!(!state.is_expired());
        assert!(state.can_authenticate());
        assert!(!state.can_authorize());
        assert!(!state.can_exchange());
        assert!(state.did().is_none());
        assert!(state.code().is_none());
    }

    #[test]
    fn test_auth_flow_state_authenticated() {
        let data = make_request_data(Some("did:plc:test".into()), None, Duration::minutes(5));
        let state = AuthFlowState::from_request_data(&data);
        assert!(!state.is_pending());
        assert!(state.is_authenticated());
        assert!(!state.is_authorized());
        assert!(!state.is_expired());
        assert!(!state.can_authenticate());
        assert!(state.can_authorize());
        assert!(!state.can_exchange());
        assert_eq!(state.did(), Some("did:plc:test"));
        assert!(state.code().is_none());
    }

    #[test]
    fn test_auth_flow_state_authorized() {
        let data = make_request_data(
            Some("did:plc:test".into()),
            Some("auth-code-123".into()),
            Duration::minutes(5),
        );
        let state = AuthFlowState::from_request_data(&data);
        assert!(!state.is_pending());
        assert!(!state.is_authenticated());
        assert!(state.is_authorized());
        assert!(!state.is_expired());
        assert!(!state.can_authenticate());
        assert!(!state.can_authorize());
        assert!(state.can_exchange());
        assert_eq!(state.did(), Some("did:plc:test"));
        assert_eq!(state.code(), Some("auth-code-123"));
    }

    #[test]
    fn test_auth_flow_state_expired() {
        let data = make_request_data(
            Some("did:plc:test".into()),
            Some("code".into()),
            Duration::minutes(-1),
        );
        let state = AuthFlowState::from_request_data(&data);
        assert!(state.is_expired());
        assert!(!state.can_authenticate());
        assert!(!state.can_authorize());
        assert!(!state.can_exchange());
    }

    #[test]
    fn test_refresh_token_state_valid() {
        let state = RefreshTokenState::Valid;
        assert!(state.is_valid());
        assert!(state.is_usable());
        assert!(!state.is_used());
        assert!(!state.is_in_grace_period());
        assert!(!state.is_expired());
        assert!(!state.is_revoked());
    }

    #[test]
    fn test_refresh_token_state_grace_period() {
        let state = RefreshTokenState::InGracePeriod {
            rotated_at: Utc::now(),
        };
        assert!(!state.is_valid());
        assert!(state.is_usable());
        assert!(!state.is_used());
        assert!(state.is_in_grace_period());
    }

    #[test]
    fn test_refresh_token_state_used() {
        let state = RefreshTokenState::Used { at: Utc::now() };
        assert!(!state.is_valid());
        assert!(!state.is_usable());
        assert!(state.is_used());
    }

    #[test]
    fn test_refresh_token_state_expired() {
        let state = RefreshTokenState::Expired;
        assert!(!state.is_usable());
        assert!(state.is_expired());
    }

    #[test]
    fn test_refresh_token_state_revoked() {
        let state = RefreshTokenState::Revoked;
        assert!(!state.is_usable());
        assert!(state.is_revoked());
    }
}
