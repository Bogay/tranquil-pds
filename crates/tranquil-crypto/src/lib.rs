mod encryption;
mod jwk;
mod signing;

pub use encryption::{decrypt_with_key, derive_key, encrypt_with_key};
pub use jwk::{Jwk, JwkSet, create_jwk_set};
pub use signing::{DeviceCookieSigner, SigningKeyPair};

#[derive(Debug, Clone, thiserror::Error)]
pub enum CryptoError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Invalid key: {0}")]
    InvalidKey(String),
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),
}
