use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use p256::ecdsa::{SigningKey, signature::Signer};
use serde_json::json;

use tranquil_pds::oauth::{
    DPoPJwk, DPoPVerifier, compute_access_token_hash, compute_jwk_thumbprint,
};

fn create_dpop_proof(
    method: &str,
    htu: &str,
    iat_offset_secs: i64,
    alg: &str,
    nonce: Option<&str>,
    ath: Option<&str>,
) -> (String, p256::ecdsa::VerifyingKey) {
    let signing_key = SigningKey::random(&mut rand::thread_rng());
    let verifying_key = *signing_key.verifying_key();
    let point = verifying_key.to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
    let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());

    let header = json!({
        "typ": "dpop+jwt",
        "alg": alg,
        "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y
        }
    });

    let iat = Utc::now().timestamp() + iat_offset_secs;
    let jti = uuid::Uuid::new_v4().to_string();

    let mut payload = json!({
        "jti": jti,
        "htm": method,
        "htu": htu,
        "iat": iat
    });

    if let Some(n) = nonce {
        payload["nonce"] = json!(n);
    }
    if let Some(a) = ath {
        payload["ath"] = json!(a);
    }

    let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());
    let signing_input = format!("{}.{}", header_b64, payload_b64);

    let signature: p256::ecdsa::Signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    let proof = format!("{}.{}.{}", header_b64, payload_b64, sig_b64);
    (proof, verifying_key)
}

fn create_dpop_proof_with_invalid_sig(method: &str, htu: &str, alg: &str) -> String {
    let signing_key = SigningKey::random(&mut rand::thread_rng());
    let verifying_key = *signing_key.verifying_key();
    let point = verifying_key.to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
    let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());

    let header = json!({
        "typ": "dpop+jwt",
        "alg": alg,
        "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y
        }
    });

    let iat = Utc::now().timestamp();
    let jti = uuid::Uuid::new_v4().to_string();

    let payload = json!({
        "jti": jti,
        "htm": method,
        "htu": htu,
        "iat": iat
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());

    let fake_sig = URL_SAFE_NO_PAD.encode(vec![0u8; 64]);

    format!("{}.{}.{}", header_b64, payload_b64, fake_sig)
}

#[test]
fn test_dpop_htu_query_params_stripped() {
    let verifier = DPoPVerifier::new(b"test-secret-32-bytes-long!!!!!!!");
    let url_with_query = "https://pds.example/xrpc/com.atproto.server.getSession?foo=bar";
    let url_without_query = "https://pds.example/xrpc/com.atproto.server.getSession";

    let (proof, _) = create_dpop_proof("GET", url_with_query, 0, "ES256", None, None);
    let result = verifier.verify_proof(&proof, "GET", url_without_query, None);
    assert!(
        result.is_ok(),
        "Query params in htu should be stripped for comparison"
    );
}

#[test]
fn test_dpop_htu_fragment_behavior() {
    let verifier = DPoPVerifier::new(b"test-secret-32-bytes-long!!!!!!!");
    let url_with_fragment = "https://pds.example/xrpc/foo#fragment";
    let url_without_fragment = "https://pds.example/xrpc/foo";

    let (proof, _) = create_dpop_proof("GET", url_with_fragment, 0, "ES256", None, None);
    let result = verifier.verify_proof(&proof, "GET", url_without_fragment, None);

    assert!(
        result.is_err(),
        "Fragment in htu should cause mismatch (currently NOT stripped)"
    );
}

#[test]
fn test_dpop_es512_algorithm_rejected() {
    let verifier = DPoPVerifier::new(b"test-secret-32-bytes-long!!!!!!!");
    let url = "https://pds.example/xrpc/foo";

    let signing_key = SigningKey::random(&mut rand::thread_rng());
    let verifying_key = *signing_key.verifying_key();
    let point = verifying_key.to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
    let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());

    let header = json!({
        "typ": "dpop+jwt",
        "alg": "ES512",
        "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y
        }
    });

    let payload = json!({
        "jti": uuid::Uuid::new_v4().to_string(),
        "htm": "GET",
        "htu": url,
        "iat": Utc::now().timestamp()
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());
    let signing_input = format!("{}.{}", header_b64, payload_b64);
    let signature: p256::ecdsa::Signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
    let proof = format!("{}.{}.{}", header_b64, payload_b64, sig_b64);

    let result = verifier.verify_proof(&proof, "GET", url, None);
    assert!(result.is_err(), "ES512 should be rejected as unsupported");
}

#[test]
fn test_dpop_iat_clock_skew_within_bounds() {
    let verifier = DPoPVerifier::new(b"test-secret-32-bytes-long!!!!!!!");
    let url = "https://pds.example/xrpc/foo";

    let (proof_299s_future, _) = create_dpop_proof("GET", url, 299, "ES256", None, None);
    let result = verifier.verify_proof(&proof_299s_future, "GET", url, None);
    assert!(
        result.is_ok(),
        "299s in future should be within clock skew tolerance"
    );

    let (proof_299s_past, _) = create_dpop_proof("GET", url, -299, "ES256", None, None);
    let result = verifier.verify_proof(&proof_299s_past, "GET", url, None);
    assert!(
        result.is_ok(),
        "299s in past should be within clock skew tolerance"
    );
}

#[test]
fn test_dpop_iat_clock_skew_beyond_bounds() {
    let verifier = DPoPVerifier::new(b"test-secret-32-bytes-long!!!!!!!");
    let url = "https://pds.example/xrpc/foo";

    let (proof_301s_future, _) = create_dpop_proof("GET", url, 310, "ES256", None, None);
    let result = verifier.verify_proof(&proof_301s_future, "GET", url, None);
    assert!(
        result.is_err(),
        "310s in future should exceed clock skew tolerance"
    );

    let (proof_301s_past, _) = create_dpop_proof("GET", url, -310, "ES256", None, None);
    let result = verifier.verify_proof(&proof_301s_past, "GET", url, None);
    assert!(
        result.is_err(),
        "310s in past should exceed clock skew tolerance"
    );
}

#[test]
fn test_dpop_http_method_case_insensitive() {
    let verifier = DPoPVerifier::new(b"test-secret-32-bytes-long!!!!!!!");
    let url = "https://pds.example/xrpc/foo";

    let (proof_lowercase, _) = create_dpop_proof("get", url, 0, "ES256", None, None);
    let result = verifier.verify_proof(&proof_lowercase, "GET", url, None);
    assert!(
        result.is_ok(),
        "HTTP method comparison should be case-insensitive"
    );

    let (proof_mixed, _) = create_dpop_proof("GeT", url, 0, "ES256", None, None);
    let result = verifier.verify_proof(&proof_mixed, "GET", url, None);
    assert!(
        result.is_ok(),
        "HTTP method comparison should be case-insensitive"
    );
}

#[test]
fn test_dpop_http_method_mismatch() {
    let verifier = DPoPVerifier::new(b"test-secret-32-bytes-long!!!!!!!");
    let url = "https://pds.example/xrpc/foo";

    let (proof_post, _) = create_dpop_proof("POST", url, 0, "ES256", None, None);
    let result = verifier.verify_proof(&proof_post, "GET", url, None);
    assert!(result.is_err(), "HTTP method mismatch should fail");
}

#[test]
fn test_dpop_invalid_signature() {
    let verifier = DPoPVerifier::new(b"test-secret-32-bytes-long!!!!!!!");
    let url = "https://pds.example/xrpc/foo";

    let proof = create_dpop_proof_with_invalid_sig("GET", url, "ES256");
    let result = verifier.verify_proof(&proof, "GET", url, None);
    assert!(result.is_err(), "Invalid signature should be rejected");
}

#[test]
fn test_dpop_malformed_base64() {
    let verifier = DPoPVerifier::new(b"test-secret-32-bytes-long!!!!!!!");
    let result = verifier.verify_proof("not.valid.base64!!!", "GET", "https://example.com", None);
    assert!(result.is_err(), "Malformed base64 should be rejected");
}

#[test]
fn test_dpop_missing_parts() {
    let verifier = DPoPVerifier::new(b"test-secret-32-bytes-long!!!!!!!");

    let result = verifier.verify_proof("onlyonepart", "GET", "https://example.com", None);
    assert!(
        result.is_err(),
        "DPoP with missing parts should be rejected"
    );

    let result = verifier.verify_proof("two.parts", "GET", "https://example.com", None);
    assert!(
        result.is_err(),
        "DPoP with only two parts should be rejected"
    );
}

#[test]
fn test_dpop_invalid_typ() {
    let verifier = DPoPVerifier::new(b"test-secret-32-bytes-long!!!!!!!");
    let url = "https://pds.example/xrpc/foo";

    let signing_key = SigningKey::random(&mut rand::thread_rng());
    let verifying_key = *signing_key.verifying_key();
    let point = verifying_key.to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
    let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());

    let header = json!({
        "typ": "jwt",
        "alg": "ES256",
        "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y
        }
    });

    let payload = json!({
        "jti": uuid::Uuid::new_v4().to_string(),
        "htm": "GET",
        "htu": url,
        "iat": Utc::now().timestamp()
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());
    let signing_input = format!("{}.{}", header_b64, payload_b64);
    let signature: p256::ecdsa::Signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
    let proof = format!("{}.{}.{}", header_b64, payload_b64, sig_b64);

    let result = verifier.verify_proof(&proof, "GET", url, None);
    assert!(result.is_err(), "Invalid typ claim should be rejected");
}

#[test]
fn test_dpop_unsupported_algorithm() {
    let verifier = DPoPVerifier::new(b"test-secret-32-bytes-long!!!!!!!");
    let url = "https://pds.example/xrpc/foo";

    let signing_key = SigningKey::random(&mut rand::thread_rng());
    let verifying_key = *signing_key.verifying_key();
    let point = verifying_key.to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
    let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());

    let header = json!({
        "typ": "dpop+jwt",
        "alg": "RS256",
        "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y
        }
    });

    let payload = json!({
        "jti": uuid::Uuid::new_v4().to_string(),
        "htm": "GET",
        "htu": url,
        "iat": Utc::now().timestamp()
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());
    let signing_input = format!("{}.{}", header_b64, payload_b64);
    let signature: p256::ecdsa::Signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
    let proof = format!("{}.{}.{}", header_b64, payload_b64, sig_b64);

    let result = verifier.verify_proof(&proof, "GET", url, None);
    assert!(result.is_err(), "Unsupported algorithm should be rejected");
}

#[test]
fn test_dpop_access_token_hash() {
    let token = "test-access-token";
    let hash = compute_access_token_hash(token);
    assert!(!hash.is_empty());

    let hash2 = compute_access_token_hash(token);
    assert_eq!(hash, hash2, "Same token should produce same hash");

    let hash3 = compute_access_token_hash("different-token");
    assert_ne!(hash, hash3, "Different token should produce different hash");
}

#[test]
fn test_dpop_nonce_generation_and_validation() {
    let verifier = DPoPVerifier::new(b"test-secret-32-bytes-long!!!!!!!");
    let nonce = verifier.generate_nonce();
    assert!(!nonce.is_empty());

    let result = verifier.validate_nonce(&nonce);
    assert!(result.is_ok(), "Freshly generated nonce should be valid");
}

#[test]
fn test_dpop_nonce_invalid_encoding() {
    let verifier = DPoPVerifier::new(b"test-secret-32-bytes-long!!!!!!!");
    let result = verifier.validate_nonce("not-valid-base64!!!");
    assert!(result.is_err(), "Invalid base64 nonce should be rejected");
}

#[test]
fn test_dpop_nonce_too_short() {
    let verifier = DPoPVerifier::new(b"test-secret-32-bytes-long!!!!!!!");
    let short_nonce = URL_SAFE_NO_PAD.encode(vec![0u8; 10]);
    let result = verifier.validate_nonce(&short_nonce);
    assert!(result.is_err(), "Too short nonce should be rejected");
}

#[test]
fn test_dpop_nonce_tampered_signature() {
    let verifier = DPoPVerifier::new(b"test-secret-32-bytes-long!!!!!!!");
    let nonce = verifier.generate_nonce();

    let nonce_bytes = URL_SAFE_NO_PAD.decode(&nonce).unwrap();
    let mut tampered = nonce_bytes.clone();
    tampered[10] ^= 0xFF;
    let tampered_nonce = URL_SAFE_NO_PAD.encode(&tampered);

    let result = verifier.validate_nonce(&tampered_nonce);
    assert!(result.is_err(), "Tampered nonce should be rejected");
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

    let thumbprint2 = compute_jwk_thumbprint(&jwk).unwrap();
    assert_eq!(
        thumbprint, thumbprint2,
        "Same JWK should produce same thumbprint"
    );
}

#[test]
fn test_jwk_thumbprint_okp() {
    let jwk = DPoPJwk {
        kty: "OKP".to_string(),
        crv: Some("Ed25519".to_string()),
        x: Some("test_x".to_string()),
        y: None,
    };
    let thumbprint = compute_jwk_thumbprint(&jwk).unwrap();
    assert!(!thumbprint.is_empty());
}

#[test]
fn test_jwk_thumbprint_unsupported_kty() {
    let jwk = DPoPJwk {
        kty: "RSA".to_string(),
        crv: None,
        x: None,
        y: None,
    };
    let result = compute_jwk_thumbprint(&jwk);
    assert!(result.is_err(), "Unsupported key type should error");
}

#[test]
fn test_jwk_thumbprint_missing_fields() {
    let jwk = DPoPJwk {
        kty: "EC".to_string(),
        crv: None,
        x: None,
        y: None,
    };
    let result = compute_jwk_thumbprint(&jwk);
    assert!(result.is_err(), "Missing crv should error");
}

#[test]
fn test_dpop_uri_normalization_preserves_port() {
    let verifier = DPoPVerifier::new(b"test-secret-32-bytes-long!!!!!!!");
    let url_with_port = "https://pds.example:8080/xrpc/foo";

    let (proof, _) = create_dpop_proof("GET", url_with_port, 0, "ES256", None, None);
    let result = verifier.verify_proof(&proof, "GET", url_with_port, None);
    assert!(result.is_ok(), "URL with port should work");

    let url_without_port = "https://pds.example/xrpc/foo";
    let result = verifier.verify_proof(&proof, "GET", url_without_port, None);
    assert!(result.is_err(), "Different port should fail");
}

#[test]
fn test_dpop_uri_normalization_preserves_path() {
    let verifier = DPoPVerifier::new(b"test-secret-32-bytes-long!!!!!!!");
    let url = "https://pds.example/xrpc/com.atproto.server.getSession";

    let (proof, _) = create_dpop_proof("GET", url, 0, "ES256", None, None);

    let different_path = "https://pds.example/xrpc/com.atproto.server.refreshSession";
    let result = verifier.verify_proof(&proof, "GET", different_path, None);
    assert!(result.is_err(), "Different path should fail");
}

#[test]
fn test_dpop_htu_must_be_full_url_not_path() {
    let verifier = DPoPVerifier::new(b"test-secret-32-bytes-long!!!!!!!");
    let full_url = "https://pds.example/xrpc/com.atproto.server.getSession";
    let path_only = "/xrpc/com.atproto.server.getSession";

    let (proof_with_path, _) = create_dpop_proof("GET", path_only, 0, "ES256", None, None);
    let result = verifier.verify_proof(&proof_with_path, "GET", full_url, None);
    assert!(
        result.is_err(),
        "htu with path-only should not match full URL"
    );

    let (proof_with_full, _) = create_dpop_proof("GET", full_url, 0, "ES256", None, None);
    let result = verifier.verify_proof(&proof_with_full, "GET", full_url, None);
    assert!(result.is_ok(), "htu with full URL should match");
}

#[test]
fn test_dpop_htu_scheme_must_match() {
    let verifier = DPoPVerifier::new(b"test-secret-32-bytes-long!!!!!!!");
    let https_url = "https://pds.example/xrpc/foo";
    let http_url = "http://pds.example/xrpc/foo";

    let (proof, _) = create_dpop_proof("GET", http_url, 0, "ES256", None, None);
    let result = verifier.verify_proof(&proof, "GET", https_url, None);
    assert!(result.is_err(), "HTTP vs HTTPS scheme mismatch should fail");
}

#[test]
fn test_dpop_htu_host_must_match() {
    let verifier = DPoPVerifier::new(b"test-secret-32-bytes-long!!!!!!!");
    let url1 = "https://pds1.example/xrpc/foo";
    let url2 = "https://pds2.example/xrpc/foo";

    let (proof, _) = create_dpop_proof("GET", url1, 0, "ES256", None, None);
    let result = verifier.verify_proof(&proof, "GET", url2, None);
    assert!(result.is_err(), "Different host should fail");
}

#[test]
fn test_dpop_server_must_check_full_url_not_path() {
    let verifier = DPoPVerifier::new(b"test-secret-32-bytes-long!!!!!!!");
    let full_url = "https://pds.example/xrpc/com.atproto.server.getSession";
    let path_only = "/xrpc/com.atproto.server.getSession";

    let (proof, _) = create_dpop_proof("GET", full_url, 0, "ES256", None, None);
    let result = verifier.verify_proof(&proof, "GET", path_only, None);
    assert!(
        result.is_err(),
        "Server checking path-only against full URL htu should fail"
    );
}
