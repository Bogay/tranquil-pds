use crate::util::pds_hostname;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use k256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::debug;
use tranquil_types::Did;

#[derive(Debug, thiserror::Error)]
pub enum ServiceTokenError {
    #[error("Invalid token format")]
    InvalidFormat,
    #[error("Base64 decode failed")]
    Base64Decode(#[source] base64::DecodeError),
    #[error("JSON decode failed")]
    JsonDecode(#[source] serde_json::Error),
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(super::SigningAlgorithm),
    #[error("Token expired")]
    Expired,
    #[error("Invalid audience: expected {expected}, got {actual}")]
    InvalidAudience { expected: Did, actual: Did },
    #[error("Token lxm '{token_lxm}' does not permit '{required}'")]
    LxmMismatch { token_lxm: String, required: String },
    #[error("Token missing lxm claim")]
    MissingLxm,
    #[error("Invalid signature format")]
    InvalidSignature(#[source] k256::ecdsa::Error),
    #[error("Signature verification failed")]
    SignatureVerificationFailed(#[source] k256::ecdsa::Error),
    #[error("No atproto verification method found")]
    NoVerificationMethod,
    #[error("Verification method missing publicKeyMultibase")]
    MissingPublicKey,
    #[error("Unsupported DID method")]
    UnsupportedDidMethod,
    #[error("DID not found: {0}")]
    DidNotFound(String),
    #[error("HTTP request failed")]
    HttpFailed(#[source] reqwest::Error),
    #[error("Failed to parse DID document")]
    InvalidDidDocument(#[source] reqwest::Error),
    #[error("HTTP {0}")]
    HttpStatus(reqwest::StatusCode),
    #[error("Invalid multibase encoding")]
    InvalidMultibase(#[source] multibase::Error),
    #[error("Invalid multicodec data")]
    InvalidMulticodec,
    #[error("Unsupported key type: expected secp256k1")]
    UnsupportedKeyType,
    #[error("Invalid public key")]
    InvalidPublicKey(#[source] k256::ecdsa::Error),
}

struct JwtParts<'a> {
    header: &'a str,
    claims: &'a str,
    signature: &'a str,
}

impl<'a> JwtParts<'a> {
    fn parse(token: &'a str) -> Result<Self, ServiceTokenError> {
        let mut parts = token.splitn(4, '.');
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(header), Some(claims), Some(signature), None) => Ok(Self {
                header,
                claims,
                signature,
            }),
            _ => Err(ServiceTokenError::InvalidFormat),
        }
    }

    fn signing_input(&self) -> String {
        format!("{}.{}", self.header, self.claims)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FullDidDocument {
    pub id: String,
    #[serde(default)]
    pub also_known_as: Vec<String>,
    #[serde(default)]
    pub verification_method: Vec<VerificationMethod>,
    #[serde(default)]
    pub service: Vec<DidService>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub method_type: String,
    pub controller: String,
    #[serde(default)]
    pub public_key_multibase: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DidService {
    pub id: String,
    #[serde(rename = "type")]
    pub service_type: String,
    pub service_endpoint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceTokenClaims {
    pub iss: Did,
    #[serde(default)]
    pub sub: Option<Did>,
    pub aud: Did,
    pub exp: i64,
    #[serde(default)]
    pub iat: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lxm: Option<String>,
    #[serde(default)]
    pub jti: Option<String>,
}

impl ServiceTokenClaims {
    pub fn subject(&self) -> &Did {
        self.sub.as_ref().unwrap_or(&self.iss)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TokenHeader {
    pub alg: super::SigningAlgorithm,
    pub typ: super::TokenType,
}

pub struct ServiceTokenVerifier {
    client: Client,
    plc_directory_url: String,
    pds_did: Did,
}

impl ServiceTokenVerifier {
    pub fn new() -> Self {
        let plc_directory_url = std::env::var("PLC_DIRECTORY_URL")
            .unwrap_or_else(|_| "https://plc.directory".to_string());

        let pds_hostname = pds_hostname();
        let pds_did: Did = format!("did:web:{}", pds_hostname)
            .parse()
            .expect("PDS hostname produces a valid DID");

        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .pool_max_idle_per_host(10)
            .pool_idle_timeout(Duration::from_secs(90))
            .build()
            .unwrap_or_else(|_| Client::new());

        Self {
            client,
            plc_directory_url,
            pds_did,
        }
    }

    pub async fn verify_service_token(
        &self,
        token: &str,
        required_lxm: Option<&str>,
    ) -> Result<ServiceTokenClaims, ServiceTokenError> {
        let jwt = JwtParts::parse(token)?;

        let header_bytes = URL_SAFE_NO_PAD
            .decode(jwt.header)
            .map_err(ServiceTokenError::Base64Decode)?;

        let header: TokenHeader =
            serde_json::from_slice(&header_bytes).map_err(ServiceTokenError::JsonDecode)?;

        if header.alg != super::SigningAlgorithm::ES256K {
            return Err(ServiceTokenError::UnsupportedAlgorithm(header.alg));
        }

        let claims_bytes = URL_SAFE_NO_PAD
            .decode(jwt.claims)
            .map_err(ServiceTokenError::Base64Decode)?;

        let claims: ServiceTokenClaims =
            serde_json::from_slice(&claims_bytes).map_err(ServiceTokenError::JsonDecode)?;

        let now = Utc::now().timestamp();
        if claims.exp < now {
            return Err(ServiceTokenError::Expired);
        }

        if claims.aud != self.pds_did {
            return Err(ServiceTokenError::InvalidAudience {
                expected: self.pds_did.clone(),
                actual: claims.aud.clone(),
            });
        }

        if let Some(required) = required_lxm {
            match &claims.lxm {
                Some(lxm) if crate::auth::lxm_permits(lxm, required) => {}
                Some(lxm) => {
                    return Err(ServiceTokenError::LxmMismatch {
                        token_lxm: lxm.clone(),
                        required: required.to_string(),
                    });
                }
                None => {
                    return Err(ServiceTokenError::MissingLxm);
                }
            }
        }

        let did = claims.iss.as_str();
        let public_key = self.resolve_signing_key(did).await?;

        let signature_bytes = URL_SAFE_NO_PAD
            .decode(jwt.signature)
            .map_err(ServiceTokenError::Base64Decode)?;

        let signature =
            Signature::from_slice(&signature_bytes).map_err(ServiceTokenError::InvalidSignature)?;

        let message = jwt.signing_input();

        public_key
            .verify(message.as_bytes(), &signature)
            .map_err(ServiceTokenError::SignatureVerificationFailed)?;

        debug!("Service token verified for DID: {}", did);

        Ok(claims)
    }

    async fn resolve_signing_key(&self, did: &str) -> Result<VerifyingKey, ServiceTokenError> {
        let did_doc = self.resolve_did_document(did).await?;

        let atproto_key = did_doc
            .verification_method
            .iter()
            .find(|vm| vm.id.ends_with("#atproto") || vm.id == format!("{}#atproto", did))
            .ok_or(ServiceTokenError::NoVerificationMethod)?;

        let multibase = atproto_key
            .public_key_multibase
            .as_ref()
            .ok_or(ServiceTokenError::MissingPublicKey)?;

        parse_did_key_multibase(multibase)
    }

    async fn resolve_did_document(&self, did: &str) -> Result<FullDidDocument, ServiceTokenError> {
        if did.starts_with("did:plc:") {
            self.resolve_did_plc(did).await
        } else if did.starts_with("did:web:") {
            self.resolve_did_web(did).await
        } else {
            Err(ServiceTokenError::UnsupportedDidMethod)
        }
    }

    async fn resolve_did_plc(&self, did: &str) -> Result<FullDidDocument, ServiceTokenError> {
        let url = format!("{}/{}", self.plc_directory_url, urlencoding::encode(did));
        debug!("Resolving did:plc {} via {}", did, url);

        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(ServiceTokenError::HttpFailed)?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(ServiceTokenError::DidNotFound(did.to_string()));
        }

        if !resp.status().is_success() {
            return Err(ServiceTokenError::HttpStatus(resp.status()));
        }

        resp.json::<FullDidDocument>()
            .await
            .map_err(ServiceTokenError::InvalidDidDocument)
    }

    async fn resolve_did_web(&self, did: &str) -> Result<FullDidDocument, ServiceTokenError> {
        let host = did
            .strip_prefix("did:web:")
            .ok_or(ServiceTokenError::InvalidFormat)?;

        let mut host_parts = host.splitn(2, ':');
        let host_part = host_parts
            .next()
            .ok_or(ServiceTokenError::InvalidFormat)?
            .replace("%3A", ":");
        let path_part = host_parts.next();

        let scheme = if host_part.starts_with("localhost")
            || host_part.starts_with("127.0.0.1")
            || host_part.contains(':')
        {
            "http"
        } else {
            "https"
        };

        let url = match path_part {
            None => format!("{}://{}/.well-known/did.json", scheme, host_part),
            Some(path) => {
                let resolved_path = path.replace(':', "/");
                format!("{}://{}/{}/did.json", scheme, host_part, resolved_path)
            }
        };

        debug!("Resolving did:web {} via {}", did, url);

        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(ServiceTokenError::HttpFailed)?;

        if !resp.status().is_success() {
            return Err(ServiceTokenError::HttpStatus(resp.status()));
        }

        resp.json::<FullDidDocument>()
            .await
            .map_err(ServiceTokenError::InvalidDidDocument)
    }
}

impl Default for ServiceTokenVerifier {
    fn default() -> Self {
        Self::new()
    }
}

fn parse_did_key_multibase(multibase: &str) -> Result<VerifyingKey, ServiceTokenError> {
    if !multibase.starts_with('z') {
        let base_char = multibase.chars().next().unwrap_or('?');
        return Err(ServiceTokenError::InvalidMultibase(
            multibase::Error::UnknownBase(base_char),
        ));
    }

    let (_, decoded) = multibase::decode(multibase).map_err(ServiceTokenError::InvalidMultibase)?;

    if decoded.len() < 2 {
        return Err(ServiceTokenError::InvalidMulticodec);
    }

    let key_bytes = if decoded.starts_with(&crate::plc::SECP256K1_MULTICODEC_PREFIX) {
        &decoded[crate::plc::SECP256K1_MULTICODEC_PREFIX.len()..]
    } else {
        return Err(ServiceTokenError::UnsupportedKeyType);
    };

    VerifyingKey::from_sec1_bytes(key_bytes).map_err(ServiceTokenError::InvalidPublicKey)
}

pub fn is_service_token(token: &str) -> bool {
    let Ok(jwt) = JwtParts::parse(token) else {
        return false;
    };

    let Ok(claims_bytes) = URL_SAFE_NO_PAD.decode(jwt.claims) else {
        return false;
    };

    let Ok(claims) = serde_json::from_slice::<serde_json::Value>(&claims_bytes) else {
        return false;
    };

    claims.get("lxm").is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_service_token() {
        let claims_with_lxm = serde_json::json!({
            "iss": "did:plc:test",
            "sub": "did:plc:test",
            "aud": "did:web:test.com",
            "exp": 9999999999i64,
            "iat": 1000000000i64,
            "lxm": "com.atproto.repo.uploadBlob",
            "jti": "test-jti"
        });

        let claims_without_lxm = serde_json::json!({
            "iss": "did:plc:test",
            "sub": "did:plc:test",
            "aud": "did:web:test.com",
            "exp": 9999999999i64,
            "iat": 1000000000i64,
            "jti": "test-jti"
        });

        let token_with_lxm = format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256K","typ":"jwt"}"#),
            URL_SAFE_NO_PAD.encode(claims_with_lxm.to_string()),
            URL_SAFE_NO_PAD.encode("fake-sig")
        );

        let token_without_lxm = format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256K","typ":"at+jwt"}"#),
            URL_SAFE_NO_PAD.encode(claims_without_lxm.to_string()),
            URL_SAFE_NO_PAD.encode("fake-sig")
        );

        assert!(is_service_token(&token_with_lxm));
        assert!(!is_service_token(&token_without_lxm));
    }

    #[test]
    fn test_parse_did_key_multibase() {
        let test_key = "zQ3shcXtVCEBjUvAhzTW3r12DkpFdR2KmA3rHmuEMFx4GMBDB";
        let result = parse_did_key_multibase(test_key);
        assert!(result.is_ok(), "Failed to parse valid multibase key");
    }

    #[test]
    fn test_jwt_parts_parse_valid() {
        let jwt = JwtParts::parse("a.b.c").unwrap();
        assert_eq!(jwt.header, "a");
        assert_eq!(jwt.claims, "b");
        assert_eq!(jwt.signature, "c");
    }

    #[test]
    fn test_jwt_parts_parse_too_few() {
        assert!(matches!(
            JwtParts::parse("a.b"),
            Err(ServiceTokenError::InvalidFormat)
        ));
    }

    #[test]
    fn test_jwt_parts_parse_too_many() {
        assert!(matches!(
            JwtParts::parse("a.b.c.d"),
            Err(ServiceTokenError::InvalidFormat)
        ));
    }

    #[test]
    fn test_jwt_parts_signing_input() {
        let jwt = JwtParts::parse("header.claims.sig").unwrap();
        assert_eq!(jwt.signing_input(), "header.claims");
    }
}
