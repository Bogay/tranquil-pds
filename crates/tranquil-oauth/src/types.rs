use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use tranquil_types::Did;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[serde(transparent)]
#[sqlx(transparent)]
pub struct RequestId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[serde(transparent)]
#[sqlx(transparent)]
pub struct TokenId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[serde(transparent)]
#[sqlx(transparent)]
pub struct DeviceId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[serde(transparent)]
#[sqlx(transparent)]
pub struct SessionId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[serde(transparent)]
#[sqlx(transparent)]
pub struct Code(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[serde(transparent)]
#[sqlx(transparent)]
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseType {
    #[default]
    Code,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum CodeChallengeMethod {
    #[default]
    #[serde(rename = "S256")]
    S256,
    #[serde(rename = "plain")]
    Plain,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseMode {
    #[default]
    Query,
    Fragment,
    FormPost,
}

impl ResponseMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::Fragment => "fragment",
            Self::FormPost => "form_post",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Prompt {
    None,
    Login,
    Consent,
    SelectAccount,
    Create,
}

impl Prompt {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Login => "login",
            Self::Consent => "consent",
            Self::SelectAccount => "select_account",
            Self::Create => "create",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationRequestParameters {
    pub response_type: ResponseType,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: CodeChallengeMethod,
    pub response_mode: Option<ResponseMode>,
    pub login_hint: Option<String>,
    pub dpop_jkt: Option<String>,
    pub prompt: Option<Prompt>,
    #[serde(flatten)]
    pub extra: Option<JsonValue>,
}

#[derive(Debug, Clone)]
pub struct RequestData {
    pub client_id: String,
    pub client_auth: Option<ClientAuth>,
    pub parameters: AuthorizationRequestParameters,
    pub expires_at: DateTime<Utc>,
    pub did: Option<Did>,
    pub device_id: Option<DeviceId>,
    pub code: Option<Code>,
    pub controller_did: Option<Did>,
}

#[derive(Debug, Clone)]
pub struct DeviceData {
    pub session_id: SessionId,
    pub user_agent: Option<String>,
    pub ip_address: String,
    pub last_seen_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct TokenData {
    pub did: Did,
    pub token_id: TokenId,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub client_id: String,
    pub client_auth: ClientAuth,
    pub device_id: Option<DeviceId>,
    pub parameters: AuthorizationRequestParameters,
    pub details: Option<JsonValue>,
    pub code: Option<Code>,
    pub current_refresh_token: Option<RefreshToken>,
    pub scope: Option<String>,
    pub controller_did: Option<Did>,
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

#[derive(Debug, Clone)]
pub struct FlowPending {
    pub parameters: AuthorizationRequestParameters,
    pub client_id: String,
    pub client_auth: Option<ClientAuth>,
    pub expires_at: DateTime<Utc>,
    pub controller_did: Option<Did>,
}

#[derive(Debug, Clone)]
pub struct FlowAuthenticated {
    pub parameters: AuthorizationRequestParameters,
    pub client_id: String,
    pub client_auth: Option<ClientAuth>,
    pub expires_at: DateTime<Utc>,
    pub did: Did,
    pub device_id: Option<DeviceId>,
    pub controller_did: Option<Did>,
}

#[derive(Debug, Clone)]
pub struct FlowAuthorized {
    pub parameters: AuthorizationRequestParameters,
    pub client_id: String,
    pub client_auth: Option<ClientAuth>,
    pub expires_at: DateTime<Utc>,
    pub did: Did,
    pub device_id: Option<DeviceId>,
    pub code: Code,
    pub controller_did: Option<Did>,
}

#[derive(Debug)]
pub struct FlowExpired;

#[derive(Debug)]
pub struct FlowNotAuthenticated;

#[derive(Debug)]
pub struct FlowNotAuthorized;

#[derive(Debug, Clone)]
pub enum AuthFlow {
    Pending(FlowPending),
    Authenticated(FlowAuthenticated),
    Authorized(FlowAuthorized),
}

#[derive(Debug, Clone)]
pub enum AuthFlowWithUser {
    Authenticated(FlowAuthenticated),
    Authorized(FlowAuthorized),
}

impl AuthFlow {
    pub fn from_request_data(data: RequestData) -> Result<Self, FlowExpired> {
        if data.expires_at < chrono::Utc::now() {
            return Err(FlowExpired);
        }
        match (data.did, data.code) {
            (None, _) => Ok(AuthFlow::Pending(FlowPending {
                parameters: data.parameters,
                client_id: data.client_id,
                client_auth: data.client_auth,
                expires_at: data.expires_at,
                controller_did: data.controller_did,
            })),
            (Some(did), None) => Ok(AuthFlow::Authenticated(FlowAuthenticated {
                parameters: data.parameters,
                client_id: data.client_id,
                client_auth: data.client_auth,
                expires_at: data.expires_at,
                did,
                device_id: data.device_id,
                controller_did: data.controller_did,
            })),
            (Some(did), Some(code)) => Ok(AuthFlow::Authorized(FlowAuthorized {
                parameters: data.parameters,
                client_id: data.client_id,
                client_auth: data.client_auth,
                expires_at: data.expires_at,
                did,
                device_id: data.device_id,
                code,
                controller_did: data.controller_did,
            })),
        }
    }

    pub fn require_user(self) -> Result<AuthFlowWithUser, FlowNotAuthenticated> {
        match self {
            AuthFlow::Pending(_) => Err(FlowNotAuthenticated),
            AuthFlow::Authenticated(a) => Ok(AuthFlowWithUser::Authenticated(a)),
            AuthFlow::Authorized(a) => Ok(AuthFlowWithUser::Authorized(a)),
        }
    }

    pub fn require_authorized(self) -> Result<FlowAuthorized, FlowNotAuthorized> {
        match self {
            AuthFlow::Authorized(a) => Ok(a),
            _ => Err(FlowNotAuthorized),
        }
    }
}

impl AuthFlowWithUser {
    pub fn did(&self) -> &Did {
        match self {
            AuthFlowWithUser::Authenticated(a) => &a.did,
            AuthFlowWithUser::Authorized(a) => &a.did,
        }
    }

    pub fn device_id(&self) -> Option<&DeviceId> {
        match self {
            AuthFlowWithUser::Authenticated(a) => a.device_id.as_ref(),
            AuthFlowWithUser::Authorized(a) => a.device_id.as_ref(),
        }
    }

    pub fn parameters(&self) -> &AuthorizationRequestParameters {
        match self {
            AuthFlowWithUser::Authenticated(a) => &a.parameters,
            AuthFlowWithUser::Authorized(a) => &a.parameters,
        }
    }

    pub fn client_id(&self) -> &str {
        match self {
            AuthFlowWithUser::Authenticated(a) => &a.client_id,
            AuthFlowWithUser::Authorized(a) => &a.client_id,
        }
    }

    pub fn controller_did(&self) -> Option<&Did> {
        match self {
            AuthFlowWithUser::Authenticated(a) => a.controller_did.as_ref(),
            AuthFlowWithUser::Authorized(a) => a.controller_did.as_ref(),
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
        did: Option<Did>,
        code: Option<Code>,
        expires_in: Duration,
    ) -> RequestData {
        RequestData {
            client_id: "test-client".into(),
            client_auth: None,
            parameters: AuthorizationRequestParameters {
                response_type: ResponseType::Code,
                client_id: "test-client".into(),
                redirect_uri: "https://example.com/callback".into(),
                scope: Some("atproto".into()),
                state: None,
                code_challenge: "test".into(),
                code_challenge_method: CodeChallengeMethod::S256,
                response_mode: None,
                login_hint: None,
                dpop_jkt: None,
                prompt: None,
                extra: None,
            },
            expires_at: Utc::now() + expires_in,
            did,
            device_id: None,
            code,
            controller_did: None,
        }
    }

    fn test_did(s: &str) -> Did {
        s.parse().expect("valid test DID")
    }

    fn test_code(s: &str) -> Code {
        Code(s.to_string())
    }

    #[test]
    fn test_auth_flow_pending() {
        let data = make_request_data(None, None, Duration::minutes(5));
        let flow = AuthFlow::from_request_data(data).expect("should not be expired");
        assert!(matches!(flow, AuthFlow::Pending(_)));
        assert!(flow.clone().require_user().is_err());
        assert!(flow.require_authorized().is_err());
    }

    #[test]
    fn test_auth_flow_authenticated() {
        let did = test_did("did:plc:test");
        let data = make_request_data(Some(did.clone()), None, Duration::minutes(5));
        let flow = AuthFlow::from_request_data(data).expect("should not be expired");
        assert!(matches!(flow, AuthFlow::Authenticated(_)));
        let with_user = flow.clone().require_user().expect("should have user");
        assert_eq!(with_user.did(), &did);
        assert!(flow.require_authorized().is_err());
    }

    #[test]
    fn test_auth_flow_authorized() {
        let did = test_did("did:plc:test");
        let code = test_code("auth-code-123");
        let data = make_request_data(Some(did.clone()), Some(code.clone()), Duration::minutes(5));
        let flow = AuthFlow::from_request_data(data).expect("should not be expired");
        assert!(matches!(flow, AuthFlow::Authorized(_)));
        let with_user = flow.clone().require_user().expect("should have user");
        assert_eq!(with_user.did(), &did);
        let authorized = flow.require_authorized().expect("should be authorized");
        assert_eq!(authorized.did, did);
        assert_eq!(authorized.code, code);
    }

    #[test]
    fn test_auth_flow_expired() {
        let did = test_did("did:plc:test");
        let code = test_code("code");
        let data = make_request_data(Some(did), Some(code), Duration::minutes(-1));
        let result = AuthFlow::from_request_data(data);
        assert!(result.is_err());
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
