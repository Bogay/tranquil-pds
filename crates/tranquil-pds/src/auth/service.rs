use crate::types::Did;
use crate::util::pds_hostname;
use anyhow::{Result, anyhow};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use k256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::debug;

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
    pub exp: usize,
    #[serde(default)]
    pub iat: Option<usize>,
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
    pub alg: String,
    pub typ: String,
}

pub struct ServiceTokenVerifier {
    client: Client,
    plc_directory_url: String,
    pds_did: String,
}

impl ServiceTokenVerifier {
    pub fn new() -> Self {
        let plc_directory_url = std::env::var("PLC_DIRECTORY_URL")
            .unwrap_or_else(|_| "https://plc.directory".to_string());

        let pds_hostname = pds_hostname();
        let pds_did = format!("did:web:{}", pds_hostname);

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
    ) -> Result<ServiceTokenClaims> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(anyhow!("Invalid token format"));
        }

        let header_bytes = URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|e| anyhow!("Base64 decode of header failed: {}", e))?;

        let header: TokenHeader = serde_json::from_slice(&header_bytes)
            .map_err(|e| anyhow!("JSON decode of header failed: {}", e))?;

        if header.alg != "ES256K" {
            return Err(anyhow!("Unsupported algorithm: {}", header.alg));
        }

        let claims_bytes = URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|e| anyhow!("Base64 decode of claims failed: {}", e))?;

        let claims: ServiceTokenClaims = serde_json::from_slice(&claims_bytes)
            .map_err(|e| anyhow!("JSON decode of claims failed: {}", e))?;

        let now = Utc::now().timestamp() as usize;
        if claims.exp < now {
            return Err(anyhow!("Token expired"));
        }

        if claims.aud.as_str() != self.pds_did {
            return Err(anyhow!(
                "Invalid audience: expected {}, got {}",
                self.pds_did,
                claims.aud
            ));
        }

        if let Some(required) = required_lxm {
            match &claims.lxm {
                Some(lxm) if lxm == "*" || lxm == required => {}
                Some(lxm) => {
                    return Err(anyhow!(
                        "Token lxm '{}' does not permit '{}'",
                        lxm,
                        required
                    ));
                }
                None => {
                    return Err(anyhow!("Token missing lxm claim"));
                }
            }
        }

        let did = claims.iss.as_str();
        let public_key = self.resolve_signing_key(did).await?;

        let signature_bytes = URL_SAFE_NO_PAD
            .decode(parts[2])
            .map_err(|e| anyhow!("Base64 decode of signature failed: {}", e))?;

        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|e| anyhow!("Invalid signature format: {}", e))?;

        let message = format!("{}.{}", parts[0], parts[1]);

        public_key
            .verify(message.as_bytes(), &signature)
            .map_err(|e| anyhow!("Signature verification failed: {}", e))?;

        debug!("Service token verified for DID: {}", did);

        Ok(claims)
    }

    async fn resolve_signing_key(&self, did: &str) -> Result<VerifyingKey> {
        let did_doc = self.resolve_did_document(did).await?;

        let atproto_key = did_doc
            .verification_method
            .iter()
            .find(|vm| vm.id.ends_with("#atproto") || vm.id == format!("{}#atproto", did))
            .ok_or_else(|| anyhow!("No atproto verification method found in DID document"))?;

        let multibase = atproto_key
            .public_key_multibase
            .as_ref()
            .ok_or_else(|| anyhow!("Verification method missing publicKeyMultibase"))?;

        parse_did_key_multibase(multibase)
    }

    async fn resolve_did_document(&self, did: &str) -> Result<FullDidDocument> {
        if did.starts_with("did:plc:") {
            self.resolve_did_plc(did).await
        } else if did.starts_with("did:web:") {
            self.resolve_did_web(did).await
        } else {
            Err(anyhow!("Unsupported DID method: {}", did))
        }
    }

    async fn resolve_did_plc(&self, did: &str) -> Result<FullDidDocument> {
        let url = format!("{}/{}", self.plc_directory_url, urlencoding::encode(did));
        debug!("Resolving did:plc {} via {}", did, url);

        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| anyhow!("HTTP request failed: {}", e))?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(anyhow!("DID not found: {}", did));
        }

        if !resp.status().is_success() {
            return Err(anyhow!("HTTP {}", resp.status()));
        }

        resp.json::<FullDidDocument>()
            .await
            .map_err(|e| anyhow!("Failed to parse DID document: {}", e))
    }

    async fn resolve_did_web(&self, did: &str) -> Result<FullDidDocument> {
        let host = did
            .strip_prefix("did:web:")
            .ok_or_else(|| anyhow!("Invalid did:web format"))?;

        let parts: Vec<&str> = host.split(':').collect();
        if parts.is_empty() {
            return Err(anyhow!("Invalid did:web format - no host"));
        }

        let host_part = parts[0].replace("%3A", ":");

        let scheme = if host_part.starts_with("localhost")
            || host_part.starts_with("127.0.0.1")
            || host_part.contains(':')
        {
            "http"
        } else {
            "https"
        };

        let url = if parts.len() == 1 {
            format!("{}://{}/.well-known/did.json", scheme, host_part)
        } else {
            let path = parts[1..].join("/");
            format!("{}://{}/{}/did.json", scheme, host_part, path)
        };

        debug!("Resolving did:web {} via {}", did, url);

        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| anyhow!("HTTP request failed: {}", e))?;

        if !resp.status().is_success() {
            return Err(anyhow!("HTTP {}", resp.status()));
        }

        resp.json::<FullDidDocument>()
            .await
            .map_err(|e| anyhow!("Failed to parse DID document: {}", e))
    }
}

impl Default for ServiceTokenVerifier {
    fn default() -> Self {
        Self::new()
    }
}

fn parse_did_key_multibase(multibase: &str) -> Result<VerifyingKey> {
    if !multibase.starts_with('z') {
        return Err(anyhow!(
            "Expected base58btc multibase encoding (starts with 'z')"
        ));
    }

    let (_, decoded) =
        multibase::decode(multibase).map_err(|e| anyhow!("Failed to decode multibase: {}", e))?;

    if decoded.len() < 2 {
        return Err(anyhow!("Invalid multicodec data"));
    }

    let (codec, key_bytes) = if decoded[0] == 0xe7 && decoded[1] == 0x01 {
        (0xe701u16, &decoded[2..])
    } else {
        return Err(anyhow!(
            "Unsupported key type. Expected secp256k1 (0xe701), got {:02x}{:02x}",
            decoded[0],
            decoded[1]
        ));
    };

    if codec != 0xe701 {
        return Err(anyhow!("Only secp256k1 keys are supported"));
    }

    VerifyingKey::from_sec1_bytes(key_bytes).map_err(|e| anyhow!("Invalid public key: {}", e))
}

pub fn is_service_token(token: &str) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return false;
    }

    let Ok(claims_bytes) = URL_SAFE_NO_PAD.decode(parts[1]) else {
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
}
