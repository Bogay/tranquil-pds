use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::Mac;
use p256::ecdsa::SigningKey;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::CryptoError;

type HmacSha256 = hmac::Hmac<Sha256>;

pub struct SigningKeyPair {
    #[allow(dead_code)]
    signing_key: SigningKey,
    pub key_id: String,
    pub x: String,
    pub y: String,
}

impl SigningKeyPair {
    pub fn from_seed(seed: &[u8]) -> Result<Self, CryptoError> {
        let mut hasher = Sha256::new();
        hasher.update(b"oauth-signing-key-derivation:");
        hasher.update(seed);
        let hash = hasher.finalize();

        let signing_key = SigningKey::from_slice(&hash)
            .map_err(|e| CryptoError::InvalidKey(format!("Failed to create signing key: {}", e)))?;

        let verifying_key = signing_key.verifying_key();
        let point = verifying_key.to_encoded_point(false);

        let x = URL_SAFE_NO_PAD.encode(
            point
                .x()
                .ok_or_else(|| CryptoError::InvalidKey("Missing X coordinate".to_string()))?,
        );
        let y = URL_SAFE_NO_PAD.encode(
            point
                .y()
                .ok_or_else(|| CryptoError::InvalidKey("Missing Y coordinate".to_string()))?,
        );

        let mut kid_hasher = Sha256::new();
        kid_hasher.update(x.as_bytes());
        kid_hasher.update(y.as_bytes());
        let kid_hash = kid_hasher.finalize();
        let key_id = URL_SAFE_NO_PAD.encode(&kid_hash[..8]);

        Ok(Self {
            signing_key,
            key_id,
            x,
            y,
        })
    }
}

pub struct DeviceCookieSigner {
    key: [u8; 32],
}

impl DeviceCookieSigner {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    pub fn sign(&self, device_id: &str) -> String {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let message = format!("{}:{}", device_id, timestamp);
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(&self.key).expect("HMAC key size is valid");
        mac.update(message.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());

        format!("{}.{}.{}", device_id, timestamp, signature)
    }

    pub fn verify(&self, cookie_value: &str, max_age_days: u64) -> Option<String> {
        let parts: Vec<&str> = cookie_value.splitn(3, '.').collect();
        if parts.len() != 3 {
            return None;
        }

        let device_id = parts[0];
        let timestamp_str = parts[1];
        let provided_signature = parts[2];

        let timestamp: u64 = timestamp_str.parse().ok()?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if now.saturating_sub(timestamp) > max_age_days * 24 * 60 * 60 {
            return None;
        }

        let message = format!("{}:{}", device_id, timestamp);
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(&self.key).expect("HMAC key size is valid");
        mac.update(message.as_bytes());
        let expected_signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());

        if provided_signature
            .as_bytes()
            .ct_eq(expected_signature.as_bytes())
            .into()
        {
            Some(device_id.to_string())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signing_key_pair() {
        let seed = b"test-seed-for-signing-key";
        let kp = SigningKeyPair::from_seed(seed).unwrap();
        assert!(!kp.key_id.is_empty());
        assert!(!kp.x.is_empty());
        assert!(!kp.y.is_empty());
    }

    #[test]
    fn test_device_cookie_signer() {
        let key = [0u8; 32];
        let signer = DeviceCookieSigner::new(key);
        let signed = signer.sign("device-123");
        let verified = signer.verify(&signed, 400);
        assert_eq!(verified, Some("device-123".to_string()));
    }

    #[test]
    fn test_device_cookie_invalid() {
        let key = [0u8; 32];
        let signer = DeviceCookieSigner::new(key);
        assert!(signer.verify("invalid", 400).is_none());
        assert!(signer.verify("a.b.c", 400).is_none());
    }
}
