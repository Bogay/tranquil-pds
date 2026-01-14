pub mod db;
pub mod endpoints;
pub mod jwks;
pub mod scopes;
pub mod verify;

pub fn db_err_to_oauth(err: tranquil_db::DbError) -> OAuthError {
    tracing::error!("Database error in OAuth flow: {}", err);
    OAuthError::ServerError("An internal error occurred".to_string())
}

pub use tranquil_oauth::{
    AuthFlowState, AuthorizationRequestParameters, AuthorizationServerMetadata,
    AuthorizedClientData, ClientAuth, ClientMetadata, ClientMetadataCache, Code, DPoPClaims,
    DPoPJwk, DPoPProofHeader, DPoPProofPayload, DPoPVerifier, DPoPVerifyResult, DeviceData,
    DeviceId, JwkPublicKey, Jwks, OAuthClientMetadata, OAuthError, ParResponse,
    ProtectedResourceMetadata, RefreshToken, RefreshTokenState, RequestData, RequestId, SessionId,
    TokenData, TokenId, TokenRequest, TokenResponse, compute_access_token_hash,
    compute_jwk_thumbprint, verify_client_auth,
};

pub use scopes::{AccountAction, AccountAttr, RepoAction, ScopeError, ScopePermissions};
pub use verify::{
    OAuthAuthError, OAuthUser, VerifyResult, generate_dpop_nonce, verify_oauth_access_token,
};
