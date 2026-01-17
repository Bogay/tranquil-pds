use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode_header};
use serde::{Deserialize, Serialize};

const TEST_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg1G9/WIOAqDBWQd/v
fu+G8OdNg3cVx9sdnp90JRpm8j6hRANCAAR9NOwKON6tu9NG1jtyqqsAuDDq18lc
z+h/EEbR9hbfBEuCzxKhLrlYFLDLNrE/N3KkIPlQm38hnjUO3QXW0ZhY
-----END PRIVATE KEY-----";

const TEST_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfTTsCjjerbvTRtY7cqqrALgw6tfJ
XM/ofxBG0fYW3wRLgs8SoS65WBSwyzaxPzdypCD5UJt/IZ41Dt0F1tGYWA==
-----END PUBLIC KEY-----";

const TEST_CLIENT_ID: &str = "com.example.test";
const TEST_TEAM_ID: &str = "ABCDE12345";
const TEST_KEY_ID: &str = "KEY123ABCD";

#[derive(Debug, Serialize, Deserialize)]
struct AppleClientSecretClaims {
    iss: String,
    iat: u64,
    exp: u64,
    aud: String,
    sub: String,
}

fn generate_test_client_secret() -> Result<String, String> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let exp = now + (150 * 24 * 60 * 60);

    let claims = AppleClientSecretClaims {
        iss: TEST_TEAM_ID.to_string(),
        iat: now,
        exp,
        aud: "https://appleid.apple.com".to_string(),
        sub: TEST_CLIENT_ID.to_string(),
    };

    let mut header = jsonwebtoken::Header::new(Algorithm::ES256);
    header.kid = Some(TEST_KEY_ID.to_string());

    let encoding_key = jsonwebtoken::EncodingKey::from_ec_pem(TEST_PRIVATE_KEY_PEM.as_bytes())
        .map_err(|e| format!("Failed to create encoding key: {}", e))?;

    jsonwebtoken::encode(&header, &claims, &encoding_key)
        .map_err(|e| format!("Failed to encode JWT: {}", e))
}

#[test]
fn test_apple_client_secret_generation() {
    let token = generate_test_client_secret().expect("Failed to generate client secret");

    assert!(!token.is_empty());

    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT should have 3 parts");

    let header = decode_header(&token).expect("Failed to decode header");
    assert_eq!(header.alg, Algorithm::ES256);
    assert_eq!(header.kid, Some(TEST_KEY_ID.to_string()));
}

#[test]
fn test_apple_client_secret_claims() {
    let token = generate_test_client_secret().expect("Failed to generate client secret");

    let parts: Vec<&str> = token.split('.').collect();
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("Failed to decode payload");
    let claims: AppleClientSecretClaims =
        serde_json::from_slice(&payload_bytes).expect("Failed to parse claims");

    assert_eq!(claims.iss, TEST_TEAM_ID);
    assert_eq!(claims.sub, TEST_CLIENT_ID);
    assert_eq!(claims.aud, "https://appleid.apple.com");
    assert!(claims.exp > claims.iat);

    let expected_exp_days = (claims.exp - claims.iat) / (24 * 60 * 60);
    assert_eq!(expected_exp_days, 150, "Token should expire in 150 days");
}

#[test]
fn test_apple_client_secret_signature_valid() {
    let token = generate_test_client_secret().expect("Failed to generate client secret");

    let decoding_key = DecodingKey::from_ec_pem(TEST_PUBLIC_KEY_PEM.as_bytes())
        .expect("Failed to create decoding key");

    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_audience(&["https://appleid.apple.com"]);
    validation.set_issuer(&[TEST_TEAM_ID]);

    let token_data =
        jsonwebtoken::decode::<AppleClientSecretClaims>(&token, &decoding_key, &validation)
            .expect("Failed to decode and verify token");

    assert_eq!(token_data.claims.iss, TEST_TEAM_ID);
    assert_eq!(token_data.claims.sub, TEST_CLIENT_ID);
    assert_eq!(token_data.claims.aud, "https://appleid.apple.com");
}

#[test]
fn test_apple_private_key_validation() {
    let result = jsonwebtoken::EncodingKey::from_ec_pem(TEST_PRIVATE_KEY_PEM.as_bytes());
    assert!(
        result.is_ok(),
        "Should parse valid PKCS#8 P-256 private key"
    );

    let invalid_pem = "-----BEGIN PRIVATE KEY-----\ninvalid\n-----END PRIVATE KEY-----";
    let result = jsonwebtoken::EncodingKey::from_ec_pem(invalid_pem.as_bytes());
    assert!(result.is_err(), "Should reject invalid private key");
}

#[test]
fn test_apple_private_key_escaped_newlines() {
    let escaped_pem = TEST_PRIVATE_KEY_PEM.replace('\n', "\\n");
    let unescaped = escaped_pem.replace("\\n", "\n");

    let result = jsonwebtoken::EncodingKey::from_ec_pem(unescaped.as_bytes());
    assert!(result.is_ok(), "Should handle escaped newlines in PEM");
}
