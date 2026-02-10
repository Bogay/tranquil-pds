use base32::Alphabet;
use rand::{Rng, RngCore};
use subtle::ConstantTimeEq;
use totp_rs::{Algorithm, TOTP};

const TOTP_DIGITS: usize = 6;
const TOTP_STEP: u64 = 30;
const TOTP_STEP_SIGNED: i64 = TOTP_STEP as i64;
const TOTP_SECRET_LENGTH: usize = 20;

#[derive(Debug)]
pub enum TotpError {
    CreationFailed(String),
    QrGenerationFailed(String),
    HashFailed(String),
}

impl std::fmt::Display for TotpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CreationFailed(e) => write!(f, "TOTP creation failed: {}", e),
            Self::QrGenerationFailed(e) => write!(f, "QR generation failed: {}", e),
            Self::HashFailed(e) => write!(f, "Hash failed: {}", e),
        }
    }
}

impl std::error::Error for TotpError {}

pub fn generate_totp_secret() -> Vec<u8> {
    let mut secret = vec![0u8; TOTP_SECRET_LENGTH];
    rand::thread_rng().fill_bytes(&mut secret);
    secret
}

pub fn encrypt_totp_secret(
    secret: &[u8],
    master_key: &[u8; 32],
) -> Result<Vec<u8>, tranquil_crypto::CryptoError> {
    tranquil_crypto::encrypt_with_key(master_key, secret)
}

pub fn decrypt_totp_secret(
    encrypted: &[u8],
    master_key: &[u8; 32],
) -> Result<Vec<u8>, tranquil_crypto::CryptoError> {
    tranquil_crypto::decrypt_with_key(master_key, encrypted)
}

fn create_totp(
    secret: Vec<u8>,
    issuer: Option<String>,
    account_name: String,
) -> Result<TOTP, TotpError> {
    TOTP::new(
        Algorithm::SHA1,
        TOTP_DIGITS,
        1,
        TOTP_STEP,
        secret,
        issuer,
        account_name,
    )
    .map_err(|e| TotpError::CreationFailed(e.to_string()))
}

pub fn verify_totp_code(secret: &[u8], code: &str) -> bool {
    let code = code.trim();
    if code.len() != TOTP_DIGITS {
        return false;
    }

    let Ok(totp) = create_totp(secret.to_vec(), None, String::new()) else {
        return false;
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    [-1i64, 0, 1].iter().any(|&offset| {
        let time = now.wrapping_add_signed(offset * TOTP_STEP_SIGNED);
        let expected = totp.generate(time);
        let is_valid: bool = code.as_bytes().ct_eq(expected.as_bytes()).into();
        is_valid
    })
}

pub fn generate_totp_uri(secret: &[u8], account_name: &str, issuer: &str) -> String {
    let secret_base32 = base32::encode(Alphabet::Rfc4648 { padding: false }, secret);
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits={}&period={}",
        urlencoding::encode(issuer),
        urlencoding::encode(account_name),
        secret_base32,
        urlencoding::encode(issuer),
        TOTP_DIGITS,
        TOTP_STEP
    )
}

pub fn generate_qr_png_base64(
    secret: &[u8],
    account_name: &str,
    issuer: &str,
) -> Result<String, TotpError> {
    use base64::{Engine, engine::general_purpose::STANDARD};

    let totp = create_totp(
        secret.to_vec(),
        Some(issuer.to_string()),
        account_name.to_string(),
    )?;

    let qr_png = totp
        .get_qr_png()
        .map_err(|e| TotpError::QrGenerationFailed(e.to_string()))?;

    Ok(STANDARD.encode(qr_png))
}

const BACKUP_CODE_ALPHABET: &[u8] = b"23456789ABCDEFGHJKMNPQRSTUVWXYZ";
const BACKUP_CODE_LENGTH: usize = 8;
const BACKUP_CODE_COUNT: usize = 10;
const BACKUP_CODE_BCRYPT_COST: u32 = 10;

pub fn generate_backup_codes() -> Vec<String> {
    let mut codes = Vec::with_capacity(BACKUP_CODE_COUNT);
    let mut rng = rand::thread_rng();

    (0..BACKUP_CODE_COUNT).for_each(|_| {
        let code: String = (0..BACKUP_CODE_LENGTH)
            .map(|_| {
                let idx = rng.gen_range(0..BACKUP_CODE_ALPHABET.len());
                BACKUP_CODE_ALPHABET[idx] as char
            })
            .collect();
        codes.push(code);
    });

    codes
}

pub fn hash_backup_code(code: &str) -> Result<String, TotpError> {
    bcrypt::hash(code, BACKUP_CODE_BCRYPT_COST).map_err(|e| TotpError::HashFailed(e.to_string()))
}

pub fn verify_backup_code(code: &str, hash: &str) -> bool {
    bcrypt::verify(code, hash).unwrap_or(false)
}

pub fn is_backup_code_format(code: &str) -> bool {
    let code = code.trim().to_uppercase();
    code.len() == BACKUP_CODE_LENGTH
        && code
            .chars()
            .all(|c| BACKUP_CODE_ALPHABET.contains(&(c as u8)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_totp_secret() {
        let secret = generate_totp_secret();
        assert_eq!(secret.len(), TOTP_SECRET_LENGTH);
    }

    #[test]
    fn test_verify_totp_code() {
        let secret = generate_totp_secret();
        let totp = create_totp(secret.clone(), None, String::new()).unwrap();
        let code = totp.generate_current().unwrap();
        assert!(verify_totp_code(&secret, &code));
        assert!(!verify_totp_code(&secret, "000000"));
    }

    #[test]
    fn test_generate_totp_uri() {
        let secret = vec![0u8; 20];
        let uri = generate_totp_uri(&secret, "test@example.com", "TestPDS");
        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains("secret="));
        assert!(uri.contains("issuer=TestPDS"));
    }

    #[test]
    fn test_backup_codes() {
        let codes = generate_backup_codes();
        assert_eq!(codes.len(), BACKUP_CODE_COUNT);
        codes.iter().for_each(|code| {
            assert_eq!(code.len(), BACKUP_CODE_LENGTH);
            assert!(is_backup_code_format(code));
        });
    }

    #[test]
    fn test_backup_code_hash_verify() {
        let codes = generate_backup_codes();
        let code = &codes[0];
        let hash = hash_backup_code(code).unwrap();
        assert!(verify_backup_code(code, &hash));
        assert!(!verify_backup_code("WRONGCOD", &hash));
    }

    #[test]
    fn test_is_backup_code_format() {
        assert!(is_backup_code_format("ABCD2345"));
        assert!(is_backup_code_format("  abcd2345  "));
        assert!(!is_backup_code_format("ABCD234"));
        assert!(!is_backup_code_format("ABCD23456"));
        assert!(!is_backup_code_format("ABCD234O"));
        assert!(!is_backup_code_format("ABCD2341"));
    }
}
