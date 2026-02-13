#[allow(deprecated)]
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hkdf::Hkdf;
use p256::ecdsa::SigningKey;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

#[derive(Debug)]
pub enum CryptoError {
    CipherCreationFailed(String),
    EncryptionFailed(String),
    DecryptionFailed(String),
    DataTooShort,
    UnknownEncryptionVersion(i32),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CipherCreationFailed(e) => write!(f, "Failed to create cipher: {}", e),
            Self::EncryptionFailed(e) => write!(f, "Encryption failed: {}", e),
            Self::DecryptionFailed(e) => write!(f, "Decryption failed: {}", e),
            Self::DataTooShort => write!(f, "Encrypted data too short"),
            Self::UnknownEncryptionVersion(v) => write!(f, "Unknown encryption version: {}", v),
        }
    }
}

impl std::error::Error for CryptoError {}

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
    device_cookie_key: [u8; 32],
}

impl AuthConfig {
    pub fn init() -> &'static Self {
        CONFIG.get_or_init(|| {
            let secrets = &tranquil_config::get().secrets;

            let jwt_secret = secrets.jwt_secret_or_default();
            let dpop_secret = secrets.dpop_secret_or_default();

            let mut hasher = Sha256::new();
            hasher.update(b"oauth-signing-key-derivation:");
            hasher.update(jwt_secret.as_bytes());
            let seed = hasher.finalize();

            let signing_key = SigningKey::from_slice(&seed).unwrap_or_else(|e| {
                panic!(
                    "Failed to create signing key from seed: {}. This is a bug.",
                    e
                )
            });

            let verifying_key = signing_key.verifying_key();
            let point = verifying_key.to_encoded_point(false);

            let signing_key_x = URL_SAFE_NO_PAD.encode(
                point
                    .x()
                    .expect("EC point missing X coordinate - this should never happen"),
            );
            let signing_key_y = URL_SAFE_NO_PAD.encode(
                point
                    .y()
                    .expect("EC point missing Y coordinate - this should never happen"),
            );

            let mut kid_hasher = Sha256::new();
            kid_hasher.update(signing_key_x.as_bytes());
            kid_hasher.update(signing_key_y.as_bytes());
            let kid_hash = kid_hasher.finalize();
            let signing_key_id = URL_SAFE_NO_PAD.encode(&kid_hash[..8]);

            let master_key = secrets.master_key_or_default();

            let hk = Hkdf::<Sha256>::new(None, master_key.as_bytes());
            let mut key_encryption_key = [0u8; 32];
            hk.expand(b"tranquil-pds-user-key-encryption", &mut key_encryption_key)
                .expect("HKDF expansion failed");

            let mut device_cookie_key = [0u8; 32];
            hk.expand(
                b"tranquil-pds-device-cookie-signing",
                &mut device_cookie_key,
            )
            .expect("HKDF expansion failed");

            AuthConfig {
                jwt_secret,
                dpop_secret,
                signing_key,
                signing_key_id,
                signing_key_x,
                signing_key_y,
                key_encryption_key,
                device_cookie_key,
            }
        })
    }

    pub fn get() -> &'static Self {
        CONFIG
            .get()
            .expect("AuthConfig not initialized - call AuthConfig::init() first")
    }

    pub fn jwt_secret(&self) -> &str {
        &self.jwt_secret
    }

    pub fn dpop_secret(&self) -> &str {
        &self.dpop_secret
    }

    pub fn sign_device_cookie(&self, device_id: &str) -> String {
        use hmac::Mac;
        type HmacSha256 = hmac::Hmac<Sha256>;

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let message = format!("{}:{}", device_id, timestamp);
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.device_cookie_key)
            .expect("HMAC key size is valid");
        mac.update(message.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());

        format!("{}.{}.{}", device_id, timestamp, signature)
    }

    pub fn verify_device_cookie(&self, cookie_value: &str) -> Option<String> {
        use hmac::Mac;
        type HmacSha256 = hmac::Hmac<Sha256>;

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

        let max_age_days = 400;
        if now.saturating_sub(timestamp) > max_age_days * 24 * 60 * 60 {
            return None;
        }

        let message = format!("{}:{}", device_id, timestamp);
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.device_cookie_key)
            .expect("HMAC key size is valid");
        mac.update(message.as_bytes());
        let expected_signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());

        use subtle::ConstantTimeEq;
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

    pub fn encrypt_user_key(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        use rand::RngCore;

        let cipher = Aes256Gcm::new_from_slice(&self.key_encryption_key)
            .map_err(|e| CryptoError::CipherCreationFailed(e.to_string()))?;

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        #[allow(deprecated)]
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    pub fn decrypt_user_key(&self, encrypted: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if encrypted.len() < 12 {
            return Err(CryptoError::DataTooShort);
        }

        let cipher = Aes256Gcm::new_from_slice(&self.key_encryption_key)
            .map_err(|e| CryptoError::CipherCreationFailed(e.to_string()))?;

        #[allow(deprecated)]
        let nonce = Nonce::from_slice(&encrypted[..12]);
        let ciphertext = &encrypted[12..];

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
    }
}

pub fn encrypt_key(plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    AuthConfig::get().encrypt_user_key(plaintext)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionVersion {
    Unencrypted,
    AesGcm,
}

impl EncryptionVersion {
    pub fn from_db(version: Option<i32>) -> Result<Self, CryptoError> {
        match version.unwrap_or(0) {
            0 => Ok(Self::Unencrypted),
            1 => Ok(Self::AesGcm),
            v => Err(CryptoError::UnknownEncryptionVersion(v)),
        }
    }

    pub fn from_db_required(version: i32) -> Result<Self, CryptoError> {
        Self::from_db(Some(version))
    }
}

pub fn decrypt_key(encrypted: &[u8], version: Option<i32>) -> Result<Vec<u8>, CryptoError> {
    match EncryptionVersion::from_db(version)? {
        EncryptionVersion::Unencrypted => Ok(encrypted.to_vec()),
        EncryptionVersion::AesGcm => AuthConfig::get().decrypt_user_key(encrypted),
    }
}
