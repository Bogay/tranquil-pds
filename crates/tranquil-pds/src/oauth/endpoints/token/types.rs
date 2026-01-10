use crate::oauth::OAuthError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantType {
    AuthorizationCode,
    RefreshToken,
    Unsupported(String),
}

impl GrantType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::AuthorizationCode => "authorization_code",
            Self::RefreshToken => "refresh_token",
            Self::Unsupported(s) => s,
        }
    }
}

impl std::str::FromStr for GrantType {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "authorization_code" => Self::AuthorizationCode,
            "refresh_token" => Self::RefreshToken,
            other => Self::Unsupported(other.to_string()),
        })
    }
}

impl<'de> Deserialize<'de> for GrantType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(s.parse().unwrap())
    }
}

impl Serialize for GrantType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: GrantType,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub redirect_uri: Option<String>,
    #[serde(default)]
    pub code_verifier: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub client_assertion: Option<String>,
    #[serde(default)]
    pub client_assertion_type: Option<String>,
}

#[derive(Debug, Clone)]
pub enum TokenGrant {
    AuthorizationCode {
        code: String,
        code_verifier: String,
        redirect_uri: Option<String>,
    },
    RefreshToken {
        refresh_token: String,
    },
}

#[derive(Debug, Clone, Default)]
pub struct ClientAuthParams {
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub client_assertion: Option<String>,
    pub client_assertion_type: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ValidatedTokenRequest {
    pub grant: TokenGrant,
    pub client_auth: ClientAuthParams,
}

impl TokenRequest {
    pub fn validate(self) -> Result<ValidatedTokenRequest, OAuthError> {
        let grant = match self.grant_type {
            GrantType::AuthorizationCode => {
                let code = self.code.ok_or_else(|| {
                    OAuthError::InvalidRequest(
                        "code is required for authorization_code grant".to_string(),
                    )
                })?;
                let code_verifier = self.code_verifier.ok_or_else(|| {
                    OAuthError::InvalidRequest(
                        "code_verifier is required for authorization_code grant".to_string(),
                    )
                })?;
                TokenGrant::AuthorizationCode {
                    code,
                    code_verifier,
                    redirect_uri: self.redirect_uri,
                }
            }
            GrantType::RefreshToken => {
                let refresh_token = self.refresh_token.ok_or_else(|| {
                    OAuthError::InvalidRequest(
                        "refresh_token is required for refresh_token grant".to_string(),
                    )
                })?;
                TokenGrant::RefreshToken { refresh_token }
            }
            GrantType::Unsupported(grant_type) => {
                return Err(OAuthError::UnsupportedGrantType(grant_type));
            }
        };

        let client_auth = ClientAuthParams {
            client_id: self.client_id,
            client_secret: self.client_secret,
            client_assertion: self.client_assertion,
            client_assertion_type: self.client_assertion_type,
        };

        Ok(ValidatedTokenRequest { grant, client_auth })
    }
}

#[derive(Debug, Serialize)]
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
