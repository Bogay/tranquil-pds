use crate::oauth::jwks::{JwkSet, create_jwk_set};
use crate::state::AppState;
use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ProtectedResourceMetadata {
    pub resource: String,
    pub authorization_servers: Vec<String>,
    pub bearer_methods_supported: Vec<String>,
    pub scopes_supported: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_documentation: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthorizationServerMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes_supported: Option<Vec<String>>,
    pub response_types_supported: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_modes_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_types_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge_methods_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pushed_authorization_request_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_pushed_authorization_requests: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_request_uri_registration: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_signing_alg_values_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_response_iss_parameter_supported: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id_metadata_document_supported: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_values_supported: Option<Vec<String>>,
}

pub async fn oauth_protected_resource(
    State(_state): State<AppState>,
) -> Json<ProtectedResourceMetadata> {
    let pds_hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let public_url = format!("https://{}", pds_hostname);
    Json(ProtectedResourceMetadata {
        resource: public_url.clone(),
        authorization_servers: vec![public_url],
        bearer_methods_supported: vec!["header".to_string()],
        scopes_supported: vec![],
        resource_documentation: Some("https://atproto.com".to_string()),
    })
}

pub async fn oauth_authorization_server(
    State(_state): State<AppState>,
) -> Json<AuthorizationServerMetadata> {
    let pds_hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let issuer = format!("https://{}", pds_hostname);
    Json(AuthorizationServerMetadata {
        issuer: issuer.clone(),
        authorization_endpoint: format!("{}/oauth/authorize", issuer),
        token_endpoint: format!("{}/oauth/token", issuer),
        jwks_uri: format!("{}/oauth/jwks", issuer),
        registration_endpoint: None,
        scopes_supported: Some(vec![
            "atproto".to_string(),
            "transition:generic".to_string(),
            "transition:chat.bsky".to_string(),
            "transition:email".to_string(),
        ]),
        response_types_supported: vec!["code".to_string()],
        response_modes_supported: Some(vec!["query".to_string(), "fragment".to_string()]),
        grant_types_supported: Some(vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ]),
        token_endpoint_auth_methods_supported: Some(vec![
            "none".to_string(),
            "private_key_jwt".to_string(),
        ]),
        token_endpoint_auth_signing_alg_values_supported: Some(vec![
            "ES256".to_string(),
            "ES384".to_string(),
            "ES512".to_string(),
            "EdDSA".to_string(),
        ]),
        code_challenge_methods_supported: Some(vec!["S256".to_string()]),
        pushed_authorization_request_endpoint: Some(format!("{}/oauth/par", issuer)),
        require_pushed_authorization_requests: Some(true),
        require_request_uri_registration: Some(true),
        dpop_signing_alg_values_supported: Some(vec![
            "ES256".to_string(),
            "ES384".to_string(),
            "ES512".to_string(),
            "EdDSA".to_string(),
        ]),
        authorization_response_iss_parameter_supported: Some(true),
        revocation_endpoint: Some(format!("{}/oauth/revoke", issuer)),
        introspection_endpoint: Some(format!("{}/oauth/introspect", issuer)),
        client_id_metadata_document_supported: Some(true),
        prompt_values_supported: Some(vec![
            "none".to_string(),
            "login".to_string(),
            "consent".to_string(),
            "select_account".to_string(),
            "create".to_string(),
        ]),
    })
}

pub async fn oauth_jwks(State(_state): State<AppState>) -> Json<JwkSet> {
    use crate::config::AuthConfig;
    use crate::oauth::jwks::Jwk;
    let config = AuthConfig::get();
    let server_key = Jwk {
        kty: "EC".to_string(),
        key_use: Some("sig".to_string()),
        kid: Some(config.signing_key_id.clone()),
        alg: Some("ES256".to_string()),
        crv: Some("P-256".to_string()),
        x: Some(config.signing_key_x.clone()),
        y: Some(config.signing_key_y.clone()),
    };
    Json(create_jwk_set(vec![server_key]))
}
