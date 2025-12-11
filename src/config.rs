#[allow(deprecated)]
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::Aead,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hkdf::Hkdf;
use p256::ecdsa::SigningKey;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

static CONFIG: OnceLock<AuthConfig> = OnceLock::new();

pub const ENCRYPTION_VERSION: i32 = 1;

pub struct AuthConfig {
    jwt_secret: String,
    dpop_secret: String,
    #[allow(dead_code)]
    signing_key: SigningKey,
    pub signing_key_id: String,
    pub signing_key_x: String,
    pub signing_key_y: String,
    key_encryption_key: [u8; 32],
}

impl AuthConfig {
    pub fn init() -> &'static Self {
        CONFIG.get_or_init(|| {
            let jwt_secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| {
                if cfg!(test) || std::env::var("BSPDS_ALLOW_INSECURE_SECRETS").is_ok() {
                    "test-jwt-secret-not-for-production".to_string()
                } else {
                    panic!(
                        "JWT_SECRET environment variable must be set in production. \
                         Set BSPDS_ALLOW_INSECURE_SECRETS=1 for development/testing."
                    );
                }
            });

            let dpop_secret = std::env::var("DPOP_SECRET").unwrap_or_else(|_| {
                if cfg!(test) || std::env::var("BSPDS_ALLOW_INSECURE_SECRETS").is_ok() {
                    "test-dpop-secret-not-for-production".to_string()
                } else {
                    panic!(
                        "DPOP_SECRET environment variable must be set in production. \
                         Set BSPDS_ALLOW_INSECURE_SECRETS=1 for development/testing."
                    );
                }
            });

            if jwt_secret.len() < 32 && std::env::var("BSPDS_ALLOW_INSECURE_SECRETS").is_err() {
                panic!("JWT_SECRET must be at least 32 characters");
            }
            if dpop_secret.len() < 32 && std::env::var("BSPDS_ALLOW_INSECURE_SECRETS").is_err() {
                panic!("DPOP_SECRET must be at least 32 characters");
            }

            let mut hasher = Sha256::new();
            hasher.update(b"oauth-signing-key-derivation:");
            hasher.update(jwt_secret.as_bytes());
            let seed = hasher.finalize();

            let signing_key = SigningKey::from_slice(&seed)
                .unwrap_or_else(|e| panic!("Failed to create signing key from seed: {}. This is a bug.", e));

            let verifying_key = signing_key.verifying_key();
            let point = verifying_key.to_encoded_point(false);

            let signing_key_x = URL_SAFE_NO_PAD.encode(
                point.x().expect("EC point missing X coordinate - this should never happen")
            );
            let signing_key_y = URL_SAFE_NO_PAD.encode(
                point.y().expect("EC point missing Y coordinate - this should never happen")
            );

            let mut kid_hasher = Sha256::new();
            kid_hasher.update(signing_key_x.as_bytes());
            kid_hasher.update(signing_key_y.as_bytes());
            let kid_hash = kid_hasher.finalize();
            let signing_key_id = URL_SAFE_NO_PAD.encode(&kid_hash[..8]);

            let master_key = std::env::var("MASTER_KEY").unwrap_or_else(|_| {
                if cfg!(test) || std::env::var("BSPDS_ALLOW_INSECURE_SECRETS").is_ok() {
                    "test-master-key-not-for-production".to_string()
                } else {
                    panic!(
                        "MASTER_KEY environment variable must be set in production. \
                         Set BSPDS_ALLOW_INSECURE_SECRETS=1 for development/testing."
                    );
                }
            });

            if master_key.len() < 32 && std::env::var("BSPDS_ALLOW_INSECURE_SECRETS").is_err() {
                panic!("MASTER_KEY must be at least 32 characters");
            }

            let hk = Hkdf::<Sha256>::new(None, master_key.as_bytes());
            let mut key_encryption_key = [0u8; 32];
            hk.expand(b"bspds-user-key-encryption", &mut key_encryption_key)
                .expect("HKDF expansion failed");

            AuthConfig {
                jwt_secret,
                dpop_secret,
                signing_key,
                signing_key_id,
                signing_key_x,
                signing_key_y,
                key_encryption_key,
            }
        })
    }

    pub fn get() -> &'static Self {
        CONFIG.get().expect("AuthConfig not initialized - call AuthConfig::init() first")
    }

    pub fn jwt_secret(&self) -> &str {
        &self.jwt_secret
    }

    pub fn dpop_secret(&self) -> &str {
        &self.dpop_secret
    }

    pub fn encrypt_user_key(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        use rand::RngCore;

        let cipher = Aes256Gcm::new_from_slice(&self.key_encryption_key)
            .map_err(|e| format!("Failed to create cipher: {}", e))?;

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        #[allow(deprecated)]
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| format!("Encryption failed: {}", e))?;

        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    pub fn decrypt_user_key(&self, encrypted: &[u8]) -> Result<Vec<u8>, String> {
        if encrypted.len() < 12 {
            return Err("Encrypted data too short".to_string());
        }

        let cipher = Aes256Gcm::new_from_slice(&self.key_encryption_key)
            .map_err(|e| format!("Failed to create cipher: {}", e))?;

        #[allow(deprecated)]
        let nonce = Nonce::from_slice(&encrypted[..12]);
        let ciphertext = &encrypted[12..];

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| format!("Decryption failed: {}", e))
    }
}

pub fn encrypt_key(plaintext: &[u8]) -> Result<Vec<u8>, String> {
    AuthConfig::get().encrypt_user_key(plaintext)
}

pub fn decrypt_key(encrypted: &[u8], version: Option<i32>) -> Result<Vec<u8>, String> {
    match version.unwrap_or(0) {
        0 => Ok(encrypted.to_vec()),
        1 => AuthConfig::get().decrypt_user_key(encrypted),
        v => Err(format!("Unknown encryption version: {}", v)),
    }
}
