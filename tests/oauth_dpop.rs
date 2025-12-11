use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bspds::oauth::dpop::{DPoPVerifier, compute_jwk_thumbprint, DPoPJwk};
use chrono::Utc;
use serde_json::json;

fn create_dpop_proof(
    method: &str,
    uri: &str,
    nonce: Option<&str>,
    ath: Option<&str>,
    iat_offset_secs: i64,
) -> String {
    use p256::ecdsa::{SigningKey, Signature, signature::Signer};
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    let signing_key = SigningKey::random(&mut rand::thread_rng());
    let verifying_key = signing_key.verifying_key();
    let point = verifying_key.to_encoded_point(false);

    let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
    let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());

    let jwk = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": x,
        "y": y
    });

    let header = json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": jwk
    });

    let mut payload = json!({
        "jti": format!("unique-{}", Utc::now().timestamp_nanos_opt().unwrap_or(0)),
        "htm": method,
        "htu": uri,
        "iat": Utc::now().timestamp() + iat_offset_secs
    });

    if let Some(n) = nonce {
        payload["nonce"] = json!(n);
    }

    if let Some(a) = ath {
        payload["ath"] = json!(a);
    }

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap());
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap());

    let signing_input = format!("{}.{}", header_b64, payload_b64);
    let signature: Signature = signing_key.sign(signing_input.as_bytes());
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    format!("{}.{}", signing_input, signature_b64)
}

#[test]
fn test_dpop_nonce_generation() {
    let secret = b"test-dpop-secret-32-bytes-long!!";
    let verifier = DPoPVerifier::new(secret);

    let nonce1 = verifier.generate_nonce();
    let nonce2 = verifier.generate_nonce();

    assert!(!nonce1.is_empty());
    assert!(!nonce2.is_empty());
}

#[test]
fn test_dpop_nonce_validation_success() {
    let secret = b"test-dpop-secret-32-bytes-long!!";
    let verifier = DPoPVerifier::new(secret);

    let nonce = verifier.generate_nonce();
    let result = verifier.validate_nonce(&nonce);

    assert!(result.is_ok(), "Valid nonce should pass: {:?}", result);
}

#[test]
fn test_dpop_nonce_wrong_secret() {
    let secret1 = b"test-dpop-secret-32-bytes-long!!";
    let secret2 = b"different-secret-32-bytes-long!!";

    let verifier1 = DPoPVerifier::new(secret1);
    let verifier2 = DPoPVerifier::new(secret2);

    let nonce = verifier1.generate_nonce();
    let result = verifier2.validate_nonce(&nonce);

    assert!(result.is_err(), "Nonce from different secret should fail");
}

#[test]
fn test_dpop_nonce_invalid_format() {
    let secret = b"test-dpop-secret-32-bytes-long!!";
    let verifier = DPoPVerifier::new(secret);

    assert!(verifier.validate_nonce("invalid").is_err());
    assert!(verifier.validate_nonce("").is_err());
    assert!(verifier.validate_nonce("!!!not-base64!!!").is_err());
}

#[test]
fn test_jwk_thumbprint_ec_p256() {
    let jwk = DPoPJwk {
        kty: "EC".to_string(),
        crv: Some("P-256".to_string()),
        x: Some("WbbXrPhtCg66wuF0NLhzXxF5PFzNZ7wNJm9M_1pCcXY".to_string()),
        y: Some("DubR6_2kU1H5EYhbcNpYZGy1EY6GEKKxv6PYx8VW0rA".to_string()),
    };

    let thumbprint = compute_jwk_thumbprint(&jwk);
    assert!(thumbprint.is_ok());

    let tp = thumbprint.unwrap();
    assert!(!tp.is_empty());
    assert!(tp.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_'));
}

#[test]
fn test_jwk_thumbprint_ec_secp256k1() {
    let jwk = DPoPJwk {
        kty: "EC".to_string(),
        crv: Some("secp256k1".to_string()),
        x: Some("some_x_value".to_string()),
        y: Some("some_y_value".to_string()),
    };

    let thumbprint = compute_jwk_thumbprint(&jwk);
    assert!(thumbprint.is_ok());
}

#[test]
fn test_jwk_thumbprint_okp_ed25519() {
    let jwk = DPoPJwk {
        kty: "OKP".to_string(),
        crv: Some("Ed25519".to_string()),
        x: Some("some_x_value".to_string()),
        y: None,
    };

    let thumbprint = compute_jwk_thumbprint(&jwk);
    assert!(thumbprint.is_ok());
}

#[test]
fn test_jwk_thumbprint_missing_crv() {
    let jwk = DPoPJwk {
        kty: "EC".to_string(),
        crv: None,
        x: Some("x".to_string()),
        y: Some("y".to_string()),
    };

    let thumbprint = compute_jwk_thumbprint(&jwk);
    assert!(thumbprint.is_err());
}

#[test]
fn test_jwk_thumbprint_missing_x() {
    let jwk = DPoPJwk {
        kty: "EC".to_string(),
        crv: Some("P-256".to_string()),
        x: None,
        y: Some("y".to_string()),
    };

    let thumbprint = compute_jwk_thumbprint(&jwk);
    assert!(thumbprint.is_err());
}

#[test]
fn test_jwk_thumbprint_missing_y_for_ec() {
    let jwk = DPoPJwk {
        kty: "EC".to_string(),
        crv: Some("P-256".to_string()),
        x: Some("x".to_string()),
        y: None,
    };

    let thumbprint = compute_jwk_thumbprint(&jwk);
    assert!(thumbprint.is_err());
}

#[test]
fn test_jwk_thumbprint_unsupported_key_type() {
    let jwk = DPoPJwk {
        kty: "RSA".to_string(),
        crv: None,
        x: None,
        y: None,
    };

    let thumbprint = compute_jwk_thumbprint(&jwk);
    assert!(thumbprint.is_err());
}

#[test]
fn test_jwk_thumbprint_deterministic() {
    let jwk = DPoPJwk {
        kty: "EC".to_string(),
        crv: Some("P-256".to_string()),
        x: Some("WbbXrPhtCg66wuF0NLhzXxF5PFzNZ7wNJm9M_1pCcXY".to_string()),
        y: Some("DubR6_2kU1H5EYhbcNpYZGy1EY6GEKKxv6PYx8VW0rA".to_string()),
    };

    let tp1 = compute_jwk_thumbprint(&jwk).unwrap();
    let tp2 = compute_jwk_thumbprint(&jwk).unwrap();

    assert_eq!(tp1, tp2, "Thumbprint should be deterministic");
}

#[test]
fn test_dpop_proof_invalid_format() {
    let secret = b"test-dpop-secret-32-bytes-long!!";
    let verifier = DPoPVerifier::new(secret);

    let result = verifier.verify_proof("not.enough.parts", "POST", "https://example.com", None);
    assert!(result.is_err());

    let result = verifier.verify_proof("invalid", "POST", "https://example.com", None);
    assert!(result.is_err());
}

#[test]
fn test_dpop_proof_invalid_typ() {
    let secret = b"test-dpop-secret-32-bytes-long!!";
    let verifier = DPoPVerifier::new(secret);

    let header = json!({
        "typ": "JWT",
        "alg": "ES256",
        "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": "x",
            "y": "y"
        }
    });

    let payload = json!({
        "jti": "unique",
        "htm": "POST",
        "htu": "https://example.com",
        "iat": Utc::now().timestamp()
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap());
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap());
    let proof = format!("{}.{}.sig", header_b64, payload_b64);

    let result = verifier.verify_proof(&proof, "POST", "https://example.com", None);
    assert!(result.is_err());
}

#[test]
fn test_dpop_proof_method_mismatch() {
    let secret = b"test-dpop-secret-32-bytes-long!!";
    let verifier = DPoPVerifier::new(secret);

    let proof = create_dpop_proof("POST", "https://example.com/token", None, None, 0);

    let result = verifier.verify_proof(&proof, "GET", "https://example.com/token", None);
    assert!(result.is_err());
}

#[test]
fn test_dpop_proof_uri_mismatch() {
    let secret = b"test-dpop-secret-32-bytes-long!!";
    let verifier = DPoPVerifier::new(secret);

    let proof = create_dpop_proof("POST", "https://example.com/token", None, None, 0);

    let result = verifier.verify_proof(&proof, "POST", "https://other.com/token", None);
    assert!(result.is_err());
}

#[test]
fn test_dpop_proof_iat_too_old() {
    let secret = b"test-dpop-secret-32-bytes-long!!";
    let verifier = DPoPVerifier::new(secret);

    let proof = create_dpop_proof("POST", "https://example.com/token", None, None, -600);

    let result = verifier.verify_proof(&proof, "POST", "https://example.com/token", None);
    assert!(result.is_err());
}

#[test]
fn test_dpop_proof_iat_future() {
    let secret = b"test-dpop-secret-32-bytes-long!!";
    let verifier = DPoPVerifier::new(secret);

    let proof = create_dpop_proof("POST", "https://example.com/token", None, None, 600);

    let result = verifier.verify_proof(&proof, "POST", "https://example.com/token", None);
    assert!(result.is_err());
}

#[test]
fn test_dpop_proof_ath_mismatch() {
    let secret = b"test-dpop-secret-32-bytes-long!!";
    let verifier = DPoPVerifier::new(secret);

    let proof = create_dpop_proof(
        "GET",
        "https://example.com/resource",
        None,
        Some("wrong_hash"),
        0,
    );

    let result = verifier.verify_proof(
        &proof,
        "GET",
        "https://example.com/resource",
        Some("correct_hash"),
    );
    assert!(result.is_err());
}

#[test]
fn test_dpop_proof_missing_ath_when_required() {
    let secret = b"test-dpop-secret-32-bytes-long!!";
    let verifier = DPoPVerifier::new(secret);

    let proof = create_dpop_proof("GET", "https://example.com/resource", None, None, 0);

    let result = verifier.verify_proof(
        &proof,
        "GET",
        "https://example.com/resource",
        Some("expected_hash"),
    );
    assert!(result.is_err());
}

#[test]
fn test_dpop_proof_uri_ignores_query_params() {
    let secret = b"test-dpop-secret-32-bytes-long!!";
    let verifier = DPoPVerifier::new(secret);

    let proof = create_dpop_proof("POST", "https://example.com/token", None, None, 0);

    let result = verifier.verify_proof(
        &proof,
        "POST",
        "https://example.com/token?foo=bar",
        None,
    );

    assert!(result.is_ok(), "Query params should be ignored: {:?}", result);
}
