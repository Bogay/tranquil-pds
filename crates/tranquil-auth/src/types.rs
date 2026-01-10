use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActClaim {
    pub sub: String,
}

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub act: Option<ActClaim>,
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

pub struct TokenData<T> {
    pub claims: T,
}

pub struct TokenWithMetadata {
    pub token: String,
    pub jti: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenVerifyError {
    Expired,
    Invalid,
}

impl fmt::Display for TokenVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Expired => write!(f, "Token expired"),
            Self::Invalid => write!(f, "Token invalid"),
        }
    }
}

impl std::error::Error for TokenVerifyError {}
