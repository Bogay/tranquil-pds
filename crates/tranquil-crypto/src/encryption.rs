#[allow(deprecated)]
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::CryptoError;

pub fn derive_key(master_key: &[u8], context: &[u8]) -> Result<[u8; 32], CryptoError> {
    let hk = Hkdf::<Sha256>::new(None, master_key);
    let mut output = [0u8; 32];
    hk.expand(context, &mut output)
        .map_err(|e| CryptoError::KeyDerivationFailed(format!("{}", e)))?;
    Ok(output)
}

pub fn encrypt_with_key(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    use rand::RngCore;

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| CryptoError::EncryptionFailed(format!("Failed to create cipher: {}", e)))?;

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    #[allow(deprecated)]
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| CryptoError::EncryptionFailed(format!("{}", e)))?;

    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

pub fn decrypt_with_key(key: &[u8; 32], encrypted: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if encrypted.len() < 12 {
        return Err(CryptoError::DecryptionFailed(
            "Encrypted data too short".to_string(),
        ));
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| CryptoError::DecryptionFailed(format!("Failed to create cipher: {}", e)))?;

    #[allow(deprecated)]
    let nonce = Nonce::from_slice(&encrypted[..12]);
    let ciphertext = &encrypted[12..];

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| CryptoError::DecryptionFailed(format!("{}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = [0u8; 32];
        let plaintext = b"hello world";
        let encrypted = encrypt_with_key(&key, plaintext).unwrap();
        let decrypted = decrypt_with_key(&key, &encrypted).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_derive_key() {
        let master = b"master-key-for-testing";
        let key1 = derive_key(master, b"context-1").unwrap();
        let key2 = derive_key(master, b"context-2").unwrap();
        assert_ne!(key1, key2);
    }
}
