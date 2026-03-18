use serde::{Deserialize, Serialize};
use tranquil_pds::oauth::OAuthError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantType {
    AuthorizationCode,
    RefreshToken,
}

impl GrantType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::AuthorizationCode => "authorization_code",
            Self::RefreshToken => "refresh_token",
        }
    }
}

#[derive(Debug, Clone)]
pub struct UnsupportedGrantType(pub String);

impl std::fmt::Display for UnsupportedGrantType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unsupported grant type: {}", self.0)
    }
}

impl std::error::Error for UnsupportedGrantType {}

impl std::str::FromStr for GrantType {
    type Err = UnsupportedGrantType;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "authorization_code" => Ok(Self::AuthorizationCode),
            "refresh_token" => Ok(Self::RefreshToken),
            other => Err(UnsupportedGrantType(other.to_string())),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
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

#[derive(Debug, Clone)]
pub enum RequestClientAuth {
    None {
        client_id: Option<String>,
    },
    SecretPost {
        client_id: Option<String>,
        client_secret: String,
    },
    PrivateKeyJwt {
        client_id: Option<String>,
        assertion: String,
        assertion_type: String,
    },
}

impl RequestClientAuth {
    pub fn client_id(&self) -> Option<&str> {
        match self {
            Self::None { client_id }
            | Self::SecretPost { client_id, .. }
            | Self::PrivateKeyJwt { client_id, .. } => client_id.as_deref(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ValidatedTokenRequest {
    pub grant: TokenGrant,
    pub client_auth: RequestClientAuth,
}

impl TokenRequest {
    pub fn validate(self) -> Result<ValidatedTokenRequest, OAuthError> {
        let grant_type: GrantType = self
            .grant_type
            .parse()
            .map_err(|e: UnsupportedGrantType| OAuthError::UnsupportedGrantType(e.0))?;
        let grant = match grant_type {
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
        };

        let client_auth = match (self.client_assertion, self.client_assertion_type) {
            (Some(assertion), Some(assertion_type)) => RequestClientAuth::PrivateKeyJwt {
                client_id: self.client_id,
                assertion,
                assertion_type,
            },
            _ => match self.client_secret {
                Some(secret) => RequestClientAuth::SecretPost {
                    client_id: self.client_id,
                    client_secret: secret,
                },
                None => RequestClientAuth::None {
                    client_id: self.client_id,
                },
            },
        };

        Ok(ValidatedTokenRequest { grant, client_auth })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum TokenType {
    Bearer,
    #[serde(rename = "DPoP")]
    DPoP,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: TokenType,
    pub expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
}
