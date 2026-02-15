use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, de, ser};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    Access,
    Refresh,
    Service,
}

impl TokenType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Access => "at+jwt",
            Self::Refresh => "refresh+jwt",
            Self::Service => "jwt",
        }
    }
}

impl fmt::Display for TokenType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for TokenType {
    type Err = TokenTypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "at+jwt" => Ok(Self::Access),
            "refresh+jwt" => Ok(Self::Refresh),
            "jwt" => Ok(Self::Service),
            _ => Err(TokenTypeParseError(s.to_string())),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TokenTypeParseError(pub String);

impl fmt::Display for TokenTypeParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown token type: {}", self.0)
    }
}

impl std::error::Error for TokenTypeParseError {}

impl Serialize for TokenType {
    fn serialize<S: ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for TokenType {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::from_str(&s).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningAlgorithm {
    ES256K,
    HS256,
}

impl SigningAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ES256K => "ES256K",
            Self::HS256 => "HS256",
        }
    }
}

impl fmt::Display for SigningAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SigningAlgorithm {
    type Err = SigningAlgorithmParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_uppercase().as_str() {
            "ES256K" => Ok(Self::ES256K),
            "HS256" => Ok(Self::HS256),
            _ => Err(SigningAlgorithmParseError(s.to_string())),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SigningAlgorithmParseError(pub String);

impl fmt::Display for SigningAlgorithmParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown signing algorithm: {}", self.0)
    }
}

impl std::error::Error for SigningAlgorithmParseError {}

impl Serialize for SigningAlgorithm {
    fn serialize<S: ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SigningAlgorithm {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::from_str(&s).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenScope {
    Access,
    Refresh,
    AppPass,
    AppPassPrivileged,
    Custom(String),
}

impl TokenScope {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Access => "com.atproto.access",
            Self::Refresh => "com.atproto.refresh",
            Self::AppPass => "com.atproto.appPass",
            Self::AppPassPrivileged => "com.atproto.appPassPrivileged",
            Self::Custom(s) => s,
        }
    }

    pub fn is_access_like(&self) -> bool {
        matches!(self, Self::Access | Self::AppPass | Self::AppPassPrivileged)
    }
}

impl fmt::Display for TokenScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for TokenScope {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "com.atproto.access" => Self::Access,
            "com.atproto.refresh" => Self::Refresh,
            "com.atproto.appPass" => Self::AppPass,
            "com.atproto.appPassPrivileged" => Self::AppPassPrivileged,
            other => Self::Custom(other.to_string()),
        })
    }
}

impl Serialize for TokenScope {
    fn serialize<S: ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for TokenScope {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(Self::from_str(&s).unwrap_or_else(|e| match e {}))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenDecodeError {
    InvalidFormat,
    Base64DecodeFailed,
    JsonDecodeFailed,
    MissingClaim,
}

impl fmt::Display for TokenDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormat => write!(f, "Invalid token format"),
            Self::Base64DecodeFailed => write!(f, "Base64 decode failed"),
            Self::JsonDecodeFailed => write!(f, "JSON decode failed"),
            Self::MissingClaim => write!(f, "Missing required claim"),
        }
    }
}

impl std::error::Error for TokenDecodeError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActClaim {
    pub sub: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
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
    pub alg: SigningAlgorithm,
    pub typ: TokenType,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_type_accepts_bluesky_uppercase_jwt() {
        let result: Result<Header, _> =
            serde_json::from_str(r#"{"alg":"ES256K","typ":"JWT"}"#);
        let header = result.expect("should parse uppercase JWT from bluesky reference pds");
        assert_eq!(header.typ, TokenType::Service);
        assert_eq!(header.alg, SigningAlgorithm::ES256K);
    }

    #[test]
    fn token_type_accepts_lowercase_jwt() {
        let result: Result<Header, _> =
            serde_json::from_str(r#"{"alg":"ES256K","typ":"jwt"}"#);
        let header = result.expect("should parse lowercase jwt");
        assert_eq!(header.typ, TokenType::Service);
    }

    #[test]
    fn token_type_accepts_mixed_case_access() {
        assert_eq!(TokenType::from_str("AT+JWT").unwrap(), TokenType::Access);
        assert_eq!(TokenType::from_str("at+jwt").unwrap(), TokenType::Access);
        assert_eq!(TokenType::from_str("At+Jwt").unwrap(), TokenType::Access);
    }

    #[test]
    fn token_type_rejects_unknown() {
        assert!(TokenType::from_str("bearer").is_err());
    }

    #[test]
    fn signing_algorithm_case_insensitive() {
        assert_eq!(SigningAlgorithm::from_str("ES256K").unwrap(), SigningAlgorithm::ES256K);
        assert_eq!(SigningAlgorithm::from_str("es256k").unwrap(), SigningAlgorithm::ES256K);
        assert_eq!(SigningAlgorithm::from_str("hs256").unwrap(), SigningAlgorithm::HS256);
    }
}
