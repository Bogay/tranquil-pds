use serde::{Deserialize, Serialize};

pub mod token;
pub mod verify;

pub use token::{create_access_token, create_refresh_token, create_service_token};
pub use verify::{get_did_from_token, verify_token};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: usize,
    pub iat: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lxm: Option<String>,
    pub jti: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Header {
    pub alg: String,
    pub typ: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UnsafeClaims {
    pub iss: String,
    pub sub: Option<String>,
}

// fancy boy TokenData equivalent for compatibility/structure
pub struct TokenData<T> {
    pub claims: T,
}
