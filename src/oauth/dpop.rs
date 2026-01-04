use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::OAuthError;
use crate::types::{DPoPProofId, JwkThumbprint};

const DPOP_NONCE_VALIDITY_SECS: i64 = 300;
const DPOP_MAX_AGE_SECS: i64 = 300;

#[derive(Debug, Clone)]
pub struct DPoPVerifyResult {
    pub jkt: JwkThumbprint,
    pub jti: DPoPProofId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DPoPProofHeader {
    pub typ: String,
    pub alg: String,
    pub jwk: DPoPJwk,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DPoPJwk {
    pub kty: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DPoPProofPayload {
    pub jti: String,
    pub htm: String,
    pub htu: String,
    pub iat: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ath: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

pub struct DPoPVerifier {
    secret: Vec<u8>,
}

impl DPoPVerifier {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            secret: secret.to_vec(),
        }
    }

    pub fn generate_nonce(&self) -> String {
        let timestamp = Utc::now().timestamp();
        let timestamp_bytes = timestamp.to_be_bytes();
        let mut hasher = Sha256::new();
        hasher.update(&self.secret);
        hasher.update(timestamp_bytes);
        let hash = hasher.finalize();
        let mut nonce_data = Vec::with_capacity(8 + 16);
        nonce_data.extend_from_slice(&timestamp_bytes);
        nonce_data.extend_from_slice(&hash[..16]);
        URL_SAFE_NO_PAD.encode(&nonce_data)
    }

    pub fn validate_nonce(&self, nonce: &str) -> Result<(), OAuthError> {
        let nonce_bytes = URL_SAFE_NO_PAD
            .decode(nonce)
            .map_err(|_| OAuthError::InvalidDpopProof("Invalid nonce encoding".to_string()))?;
        if nonce_bytes.len() < 24 {
            return Err(OAuthError::InvalidDpopProof(
                "Invalid nonce length".to_string(),
            ));
        }
        let timestamp_bytes: [u8; 8] = nonce_bytes[..8]
            .try_into()
            .map_err(|_| OAuthError::InvalidDpopProof("Invalid nonce".to_string()))?;
        let timestamp = i64::from_be_bytes(timestamp_bytes);
        let now = Utc::now().timestamp();
        if now - timestamp > DPOP_NONCE_VALIDITY_SECS {
            return Err(OAuthError::UseDpopNonce(self.generate_nonce()));
        }
        let mut hasher = Sha256::new();
        hasher.update(&self.secret);
        hasher.update(timestamp_bytes);
        let expected_hash = hasher.finalize();
        if nonce_bytes[8..24] != expected_hash[..16] {
            return Err(OAuthError::InvalidDpopProof(
                "Invalid nonce signature".to_string(),
            ));
        }
        Ok(())
    }

    pub fn verify_proof(
        &self,
        dpop_header: &str,
        http_method: &str,
        http_uri: &str,
        access_token_hash: Option<&str>,
    ) -> Result<DPoPVerifyResult, OAuthError> {
        let parts: Vec<&str> = dpop_header.split('.').collect();
        if parts.len() != 3 {
            return Err(OAuthError::InvalidDpopProof(
                "Invalid DPoP proof format".to_string(),
            ));
        }
        let header_json = URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|_| OAuthError::InvalidDpopProof("Invalid header encoding".to_string()))?;
        let payload_json = URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|_| OAuthError::InvalidDpopProof("Invalid payload encoding".to_string()))?;
        let header: DPoPProofHeader = serde_json::from_slice(&header_json)
            .map_err(|_| OAuthError::InvalidDpopProof("Invalid header JSON".to_string()))?;
        let payload: DPoPProofPayload = serde_json::from_slice(&payload_json)
            .map_err(|_| OAuthError::InvalidDpopProof("Invalid payload JSON".to_string()))?;
        if header.typ != "dpop+jwt" {
            return Err(OAuthError::InvalidDpopProof(
                "Invalid typ claim".to_string(),
            ));
        }
        if !matches!(header.alg.as_str(), "ES256" | "ES384" | "ES512" | "EdDSA") {
            return Err(OAuthError::InvalidDpopProof(
                "Unsupported algorithm".to_string(),
            ));
        }
        if payload.htm.to_uppercase() != http_method.to_uppercase() {
            return Err(OAuthError::InvalidDpopProof(
                "HTTP method mismatch".to_string(),
            ));
        }
        let proof_uri = payload.htu.split('?').next().unwrap_or(&payload.htu);
        let request_uri = http_uri.split('?').next().unwrap_or(http_uri);
        if proof_uri != request_uri {
            return Err(OAuthError::InvalidDpopProof(
                "HTTP URI mismatch".to_string(),
            ));
        }
        let now = Utc::now().timestamp();
        if (now - payload.iat).abs() > DPOP_MAX_AGE_SECS {
            return Err(OAuthError::InvalidDpopProof(
                "Proof too old or from the future".to_string(),
            ));
        }
        if let Some(nonce) = &payload.nonce {
            self.validate_nonce(nonce)?;
        }
        if let Some(expected_ath) = access_token_hash {
            match &payload.ath {
                Some(ath) if ath == expected_ath => {}
                Some(_) => {
                    return Err(OAuthError::InvalidDpopProof(
                        "Access token hash mismatch".to_string(),
                    ));
                }
                None => {
                    return Err(OAuthError::InvalidDpopProof(
                        "Missing access token hash".to_string(),
                    ));
                }
            }
        }
        let signature_bytes = URL_SAFE_NO_PAD
            .decode(parts[2])
            .map_err(|_| OAuthError::InvalidDpopProof("Invalid signature encoding".to_string()))?;
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        verify_dpop_signature(
            &header.alg,
            &header.jwk,
            signing_input.as_bytes(),
            &signature_bytes,
        )?;
        let jkt = compute_jwk_thumbprint(&header.jwk)?;
        Ok(DPoPVerifyResult {
            jkt: jkt.into(),
            jti: payload.jti.clone().into(),
        })
    }
}

fn verify_dpop_signature(
    alg: &str,
    jwk: &DPoPJwk,
    message: &[u8],
    signature: &[u8],
) -> Result<(), OAuthError> {
    match alg {
        "ES256" => verify_es256(jwk, message, signature),
        "ES384" => verify_es384(jwk, message, signature),
        "EdDSA" => verify_eddsa(jwk, message, signature),
        _ => Err(OAuthError::InvalidDpopProof(format!(
            "Unsupported algorithm: {}",
            alg
        ))),
    }
}

fn verify_es256(jwk: &DPoPJwk, message: &[u8], signature: &[u8]) -> Result<(), OAuthError> {
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    use p256::elliptic_curve::sec1::FromEncodedPoint;
    use p256::{AffinePoint, EncodedPoint};
    let crv = jwk
        .crv
        .as_ref()
        .ok_or_else(|| OAuthError::InvalidDpopProof("Missing crv for ES256".to_string()))?;
    if crv != "P-256" {
        return Err(OAuthError::InvalidDpopProof(format!(
            "Invalid curve for ES256: {}",
            crv
        )));
    }
    let x_bytes = URL_SAFE_NO_PAD
        .decode(
            jwk.x
                .as_ref()
                .ok_or_else(|| OAuthError::InvalidDpopProof("Missing x coordinate".to_string()))?,
        )
        .map_err(|_| OAuthError::InvalidDpopProof("Invalid x encoding".to_string()))?;
    let y_bytes = URL_SAFE_NO_PAD
        .decode(
            jwk.y
                .as_ref()
                .ok_or_else(|| OAuthError::InvalidDpopProof("Missing y coordinate".to_string()))?,
        )
        .map_err(|_| OAuthError::InvalidDpopProof("Invalid y encoding".to_string()))?;
    let point = EncodedPoint::from_affine_coordinates(
        x_bytes.as_slice().into(),
        y_bytes.as_slice().into(),
        false,
    );
    let affine_opt: Option<AffinePoint> = AffinePoint::from_encoded_point(&point).into();
    let affine =
        affine_opt.ok_or_else(|| OAuthError::InvalidDpopProof("Invalid EC point".to_string()))?;
    let verifying_key = VerifyingKey::from_affine(affine)
        .map_err(|_| OAuthError::InvalidDpopProof("Invalid verifying key".to_string()))?;
    let sig = Signature::from_slice(signature)
        .map_err(|_| OAuthError::InvalidDpopProof("Invalid signature format".to_string()))?;
    verifying_key
        .verify(message, &sig)
        .map_err(|_| OAuthError::InvalidDpopProof("Signature verification failed".to_string()))
}

fn verify_es384(jwk: &DPoPJwk, message: &[u8], signature: &[u8]) -> Result<(), OAuthError> {
    use p384::ecdsa::signature::Verifier;
    use p384::ecdsa::{Signature, VerifyingKey};
    use p384::elliptic_curve::sec1::FromEncodedPoint;
    use p384::{AffinePoint, EncodedPoint};
    let crv = jwk
        .crv
        .as_ref()
        .ok_or_else(|| OAuthError::InvalidDpopProof("Missing crv for ES384".to_string()))?;
    if crv != "P-384" {
        return Err(OAuthError::InvalidDpopProof(format!(
            "Invalid curve for ES384: {}",
            crv
        )));
    }
    let x_bytes = URL_SAFE_NO_PAD
        .decode(
            jwk.x
                .as_ref()
                .ok_or_else(|| OAuthError::InvalidDpopProof("Missing x coordinate".to_string()))?,
        )
        .map_err(|_| OAuthError::InvalidDpopProof("Invalid x encoding".to_string()))?;
    let y_bytes = URL_SAFE_NO_PAD
        .decode(
            jwk.y
                .as_ref()
                .ok_or_else(|| OAuthError::InvalidDpopProof("Missing y coordinate".to_string()))?,
        )
        .map_err(|_| OAuthError::InvalidDpopProof("Invalid y encoding".to_string()))?;
    let point = EncodedPoint::from_affine_coordinates(
        x_bytes.as_slice().into(),
        y_bytes.as_slice().into(),
        false,
    );
    let affine_opt: Option<AffinePoint> = AffinePoint::from_encoded_point(&point).into();
    let affine =
        affine_opt.ok_or_else(|| OAuthError::InvalidDpopProof("Invalid EC point".to_string()))?;
    let verifying_key = VerifyingKey::from_affine(affine)
        .map_err(|_| OAuthError::InvalidDpopProof("Invalid verifying key".to_string()))?;
    let sig = Signature::from_slice(signature)
        .map_err(|_| OAuthError::InvalidDpopProof("Invalid signature format".to_string()))?;
    verifying_key
        .verify(message, &sig)
        .map_err(|_| OAuthError::InvalidDpopProof("Signature verification failed".to_string()))
}

fn verify_eddsa(jwk: &DPoPJwk, message: &[u8], signature: &[u8]) -> Result<(), OAuthError> {
    use ed25519_dalek::{Signature, VerifyingKey};
    let crv = jwk
        .crv
        .as_ref()
        .ok_or_else(|| OAuthError::InvalidDpopProof("Missing crv for EdDSA".to_string()))?;
    if crv != "Ed25519" {
        return Err(OAuthError::InvalidDpopProof(format!(
            "Invalid curve for EdDSA: {}",
            crv
        )));
    }
    let x_bytes = URL_SAFE_NO_PAD
        .decode(
            jwk.x
                .as_ref()
                .ok_or_else(|| OAuthError::InvalidDpopProof("Missing x coordinate".to_string()))?,
        )
        .map_err(|_| OAuthError::InvalidDpopProof("Invalid x encoding".to_string()))?;
    let key_bytes: [u8; 32] = x_bytes
        .try_into()
        .map_err(|_| OAuthError::InvalidDpopProof("Invalid Ed25519 key length".to_string()))?;
    let verifying_key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| OAuthError::InvalidDpopProof("Invalid Ed25519 key".to_string()))?;
    let sig_bytes: [u8; 64] = signature.try_into().map_err(|_| {
        OAuthError::InvalidDpopProof("Invalid Ed25519 signature length".to_string())
    })?;
    let sig = Signature::from_bytes(&sig_bytes);
    verifying_key
        .verify_strict(message, &sig)
        .map_err(|_| OAuthError::InvalidDpopProof("Signature verification failed".to_string()))
}

pub fn compute_jwk_thumbprint(jwk: &DPoPJwk) -> Result<String, OAuthError> {
    let canonical = match jwk.kty.as_str() {
        "EC" => {
            let crv = jwk
                .crv
                .as_ref()
                .ok_or_else(|| OAuthError::InvalidDpopProof("Missing crv".to_string()))?;
            let x = jwk
                .x
                .as_ref()
                .ok_or_else(|| OAuthError::InvalidDpopProof("Missing x".to_string()))?;
            let y = jwk
                .y
                .as_ref()
                .ok_or_else(|| OAuthError::InvalidDpopProof("Missing y".to_string()))?;
            format!(r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#, crv, x, y)
        }
        "OKP" => {
            let crv = jwk
                .crv
                .as_ref()
                .ok_or_else(|| OAuthError::InvalidDpopProof("Missing crv".to_string()))?;
            let x = jwk
                .x
                .as_ref()
                .ok_or_else(|| OAuthError::InvalidDpopProof("Missing x".to_string()))?;
            format!(r#"{{"crv":"{}","kty":"OKP","x":"{}"}}"#, crv, x)
        }
        _ => {
            return Err(OAuthError::InvalidDpopProof(
                "Unsupported key type".to_string(),
            ));
        }
    };
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let hash = hasher.finalize();
    Ok(URL_SAFE_NO_PAD.encode(hash))
}

pub fn compute_access_token_hash(access_token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(access_token.as_bytes());
    let hash = hasher.finalize();
    URL_SAFE_NO_PAD.encode(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_generation_and_validation() {
        let secret = b"test-secret-key-32-bytes-long!!!";
        let verifier = DPoPVerifier::new(secret);
        let nonce = verifier.generate_nonce();
        assert!(verifier.validate_nonce(&nonce).is_ok());
    }

    #[test]
    fn test_jwk_thumbprint_ec() {
        let jwk = DPoPJwk {
            kty: "EC".to_string(),
            crv: Some("P-256".to_string()),
            x: Some("test_x".to_string()),
            y: Some("test_y".to_string()),
        };
        let thumbprint = compute_jwk_thumbprint(&jwk).unwrap();
        assert!(!thumbprint.is_empty());
    }
}
