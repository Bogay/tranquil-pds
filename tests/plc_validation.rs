use bspds::plc::{
    PlcError, PlcOperation, PlcService, PlcValidationContext,
    cid_for_cbor, sign_operation, signing_key_to_did_key,
    validate_plc_operation, validate_plc_operation_for_submission,
    verify_operation_signature,
};
use k256::ecdsa::SigningKey;
use serde_json::json;
use std::collections::HashMap;
fn create_valid_operation() -> serde_json::Value {
    let key = SigningKey::random(&mut rand::thread_rng());
    let did_key = signing_key_to_did_key(&key);
    let op = json!({
        "type": "plc_operation",
        "rotationKeys": [did_key.clone()],
        "verificationMethods": {
            "atproto": did_key.clone()
        },
        "alsoKnownAs": ["at://test.handle"],
        "services": {
            "atproto_pds": {
                "type": "AtprotoPersonalDataServer",
                "endpoint": "https://pds.example.com"
            }
        },
        "prev": null
    });
    sign_operation(&op, &key).unwrap()
}
#[test]
fn test_validate_plc_operation_valid() {
    let op = create_valid_operation();
    let result = validate_plc_operation(&op);
    assert!(result.is_ok());
}
#[test]
fn test_validate_plc_operation_missing_type() {
    let op = json!({
        "rotationKeys": [],
        "verificationMethods": {},
        "alsoKnownAs": [],
        "services": {},
        "sig": "test"
    });
    let result = validate_plc_operation(&op);
    assert!(matches!(result, Err(PlcError::InvalidResponse(msg)) if msg.contains("Missing type")));
}
#[test]
fn test_validate_plc_operation_invalid_type() {
    let op = json!({
        "type": "invalid_type",
        "sig": "test"
    });
    let result = validate_plc_operation(&op);
    assert!(matches!(result, Err(PlcError::InvalidResponse(msg)) if msg.contains("Invalid type")));
}
#[test]
fn test_validate_plc_operation_missing_sig() {
    let op = json!({
        "type": "plc_operation",
        "rotationKeys": [],
        "verificationMethods": {},
        "alsoKnownAs": [],
        "services": {}
    });
    let result = validate_plc_operation(&op);
    assert!(matches!(result, Err(PlcError::InvalidResponse(msg)) if msg.contains("Missing sig")));
}
#[test]
fn test_validate_plc_operation_missing_rotation_keys() {
    let op = json!({
        "type": "plc_operation",
        "verificationMethods": {},
        "alsoKnownAs": [],
        "services": {},
        "sig": "test"
    });
    let result = validate_plc_operation(&op);
    assert!(matches!(result, Err(PlcError::InvalidResponse(msg)) if msg.contains("rotationKeys")));
}
#[test]
fn test_validate_plc_operation_missing_verification_methods() {
    let op = json!({
        "type": "plc_operation",
        "rotationKeys": [],
        "alsoKnownAs": [],
        "services": {},
        "sig": "test"
    });
    let result = validate_plc_operation(&op);
    assert!(matches!(result, Err(PlcError::InvalidResponse(msg)) if msg.contains("verificationMethods")));
}
#[test]
fn test_validate_plc_operation_missing_also_known_as() {
    let op = json!({
        "type": "plc_operation",
        "rotationKeys": [],
        "verificationMethods": {},
        "services": {},
        "sig": "test"
    });
    let result = validate_plc_operation(&op);
    assert!(matches!(result, Err(PlcError::InvalidResponse(msg)) if msg.contains("alsoKnownAs")));
}
#[test]
fn test_validate_plc_operation_missing_services() {
    let op = json!({
        "type": "plc_operation",
        "rotationKeys": [],
        "verificationMethods": {},
        "alsoKnownAs": [],
        "sig": "test"
    });
    let result = validate_plc_operation(&op);
    assert!(matches!(result, Err(PlcError::InvalidResponse(msg)) if msg.contains("services")));
}
#[test]
fn test_validate_rotation_key_required() {
    let key = SigningKey::random(&mut rand::thread_rng());
    let did_key = signing_key_to_did_key(&key);
    let server_key = "did:key:zServer123";
    let op = json!({
        "type": "plc_operation",
        "rotationKeys": [did_key.clone()],
        "verificationMethods": {"atproto": did_key.clone()},
        "alsoKnownAs": ["at://test.handle"],
        "services": {
            "atproto_pds": {
                "type": "AtprotoPersonalDataServer",
                "endpoint": "https://pds.example.com"
            }
        },
        "sig": "test"
    });
    let ctx = PlcValidationContext {
        server_rotation_key: server_key.to_string(),
        expected_signing_key: did_key.clone(),
        expected_handle: "test.handle".to_string(),
        expected_pds_endpoint: "https://pds.example.com".to_string(),
    };
    let result = validate_plc_operation_for_submission(&op, &ctx);
    assert!(matches!(result, Err(PlcError::InvalidResponse(msg)) if msg.contains("rotation key")));
}
#[test]
fn test_validate_signing_key_match() {
    let key = SigningKey::random(&mut rand::thread_rng());
    let did_key = signing_key_to_did_key(&key);
    let wrong_key = "did:key:zWrongKey456";
    let op = json!({
        "type": "plc_operation",
        "rotationKeys": [did_key.clone()],
        "verificationMethods": {"atproto": wrong_key},
        "alsoKnownAs": ["at://test.handle"],
        "services": {
            "atproto_pds": {
                "type": "AtprotoPersonalDataServer",
                "endpoint": "https://pds.example.com"
            }
        },
        "sig": "test"
    });
    let ctx = PlcValidationContext {
        server_rotation_key: did_key.clone(),
        expected_signing_key: did_key.clone(),
        expected_handle: "test.handle".to_string(),
        expected_pds_endpoint: "https://pds.example.com".to_string(),
    };
    let result = validate_plc_operation_for_submission(&op, &ctx);
    assert!(matches!(result, Err(PlcError::InvalidResponse(msg)) if msg.contains("signing key")));
}
#[test]
fn test_validate_handle_match() {
    let key = SigningKey::random(&mut rand::thread_rng());
    let did_key = signing_key_to_did_key(&key);
    let op = json!({
        "type": "plc_operation",
        "rotationKeys": [did_key.clone()],
        "verificationMethods": {"atproto": did_key.clone()},
        "alsoKnownAs": ["at://wrong.handle"],
        "services": {
            "atproto_pds": {
                "type": "AtprotoPersonalDataServer",
                "endpoint": "https://pds.example.com"
            }
        },
        "sig": "test"
    });
    let ctx = PlcValidationContext {
        server_rotation_key: did_key.clone(),
        expected_signing_key: did_key.clone(),
        expected_handle: "test.handle".to_string(),
        expected_pds_endpoint: "https://pds.example.com".to_string(),
    };
    let result = validate_plc_operation_for_submission(&op, &ctx);
    assert!(matches!(result, Err(PlcError::InvalidResponse(msg)) if msg.contains("handle")));
}
#[test]
fn test_validate_pds_service_type() {
    let key = SigningKey::random(&mut rand::thread_rng());
    let did_key = signing_key_to_did_key(&key);
    let op = json!({
        "type": "plc_operation",
        "rotationKeys": [did_key.clone()],
        "verificationMethods": {"atproto": did_key.clone()},
        "alsoKnownAs": ["at://test.handle"],
        "services": {
            "atproto_pds": {
                "type": "WrongServiceType",
                "endpoint": "https://pds.example.com"
            }
        },
        "sig": "test"
    });
    let ctx = PlcValidationContext {
        server_rotation_key: did_key.clone(),
        expected_signing_key: did_key.clone(),
        expected_handle: "test.handle".to_string(),
        expected_pds_endpoint: "https://pds.example.com".to_string(),
    };
    let result = validate_plc_operation_for_submission(&op, &ctx);
    assert!(matches!(result, Err(PlcError::InvalidResponse(msg)) if msg.contains("type")));
}
#[test]
fn test_validate_pds_endpoint_match() {
    let key = SigningKey::random(&mut rand::thread_rng());
    let did_key = signing_key_to_did_key(&key);
    let op = json!({
        "type": "plc_operation",
        "rotationKeys": [did_key.clone()],
        "verificationMethods": {"atproto": did_key.clone()},
        "alsoKnownAs": ["at://test.handle"],
        "services": {
            "atproto_pds": {
                "type": "AtprotoPersonalDataServer",
                "endpoint": "https://wrong.endpoint.com"
            }
        },
        "sig": "test"
    });
    let ctx = PlcValidationContext {
        server_rotation_key: did_key.clone(),
        expected_signing_key: did_key.clone(),
        expected_handle: "test.handle".to_string(),
        expected_pds_endpoint: "https://pds.example.com".to_string(),
    };
    let result = validate_plc_operation_for_submission(&op, &ctx);
    assert!(matches!(result, Err(PlcError::InvalidResponse(msg)) if msg.contains("endpoint")));
}
#[test]
fn test_verify_signature_secp256k1() {
    let key = SigningKey::random(&mut rand::thread_rng());
    let did_key = signing_key_to_did_key(&key);
    let op = json!({
        "type": "plc_operation",
        "rotationKeys": [did_key.clone()],
        "verificationMethods": {},
        "alsoKnownAs": [],
        "services": {},
        "prev": null
    });
    let signed = sign_operation(&op, &key).unwrap();
    let rotation_keys = vec![did_key];
    let result = verify_operation_signature(&signed, &rotation_keys);
    assert!(result.is_ok());
    assert!(result.unwrap());
}
#[test]
fn test_verify_signature_wrong_key() {
    let key = SigningKey::random(&mut rand::thread_rng());
    let other_key = SigningKey::random(&mut rand::thread_rng());
    let other_did_key = signing_key_to_did_key(&other_key);
    let op = json!({
        "type": "plc_operation",
        "rotationKeys": [],
        "verificationMethods": {},
        "alsoKnownAs": [],
        "services": {},
        "prev": null
    });
    let signed = sign_operation(&op, &key).unwrap();
    let wrong_rotation_keys = vec![other_did_key];
    let result = verify_operation_signature(&signed, &wrong_rotation_keys);
    assert!(result.is_ok());
    assert!(!result.unwrap());
}
#[test]
fn test_verify_signature_invalid_did_key_format() {
    let key = SigningKey::random(&mut rand::thread_rng());
    let op = json!({
        "type": "plc_operation",
        "rotationKeys": [],
        "verificationMethods": {},
        "alsoKnownAs": [],
        "services": {},
        "prev": null
    });
    let signed = sign_operation(&op, &key).unwrap();
    let invalid_keys = vec!["not-a-did-key".to_string()];
    let result = verify_operation_signature(&signed, &invalid_keys);
    assert!(result.is_ok());
    assert!(!result.unwrap());
}
#[test]
fn test_tombstone_validation() {
    let op = json!({
        "type": "plc_tombstone",
        "prev": "bafyreig6xxxxxyyyyyzzzzzz",
        "sig": "test"
    });
    let result = validate_plc_operation(&op);
    assert!(result.is_ok());
}
#[test]
fn test_cid_for_cbor_deterministic() {
    let value = json!({
        "alpha": 1,
        "beta": 2
    });
    let cid1 = cid_for_cbor(&value).unwrap();
    let cid2 = cid_for_cbor(&value).unwrap();
    assert_eq!(cid1, cid2, "CID generation should be deterministic");
    assert!(cid1.starts_with("bafyrei"), "CID should start with bafyrei (dag-cbor + sha256)");
}
#[test]
fn test_cid_different_for_different_data() {
    let value1 = json!({"data": 1});
    let value2 = json!({"data": 2});
    let cid1 = cid_for_cbor(&value1).unwrap();
    let cid2 = cid_for_cbor(&value2).unwrap();
    assert_ne!(cid1, cid2, "Different data should produce different CIDs");
}
#[test]
fn test_signing_key_to_did_key_format() {
    let key = SigningKey::random(&mut rand::thread_rng());
    let did_key = signing_key_to_did_key(&key);
    assert!(did_key.starts_with("did:key:z"), "Should start with did:key:z");
    assert!(did_key.len() > 50, "Did key should be reasonably long");
}
#[test]
fn test_signing_key_to_did_key_unique() {
    let key1 = SigningKey::random(&mut rand::thread_rng());
    let key2 = SigningKey::random(&mut rand::thread_rng());
    let did1 = signing_key_to_did_key(&key1);
    let did2 = signing_key_to_did_key(&key2);
    assert_ne!(did1, did2, "Different keys should produce different did:keys");
}
#[test]
fn test_signing_key_to_did_key_consistent() {
    let key = SigningKey::random(&mut rand::thread_rng());
    let did1 = signing_key_to_did_key(&key);
    let did2 = signing_key_to_did_key(&key);
    assert_eq!(did1, did2, "Same key should produce same did:key");
}
#[test]
fn test_sign_operation_removes_existing_sig() {
    let key = SigningKey::random(&mut rand::thread_rng());
    let op = json!({
        "type": "plc_operation",
        "rotationKeys": [],
        "verificationMethods": {},
        "alsoKnownAs": [],
        "services": {},
        "prev": null,
        "sig": "old_signature"
    });
    let signed = sign_operation(&op, &key).unwrap();
    let new_sig = signed.get("sig").and_then(|v| v.as_str()).unwrap();
    assert_ne!(new_sig, "old_signature", "Should replace old signature");
}
#[test]
fn test_validate_plc_operation_not_object() {
    let result = validate_plc_operation(&json!("not an object"));
    assert!(matches!(result, Err(PlcError::InvalidResponse(_))));
}
#[test]
fn test_validate_for_submission_tombstone_passes() {
    let key = SigningKey::random(&mut rand::thread_rng());
    let did_key = signing_key_to_did_key(&key);
    let op = json!({
        "type": "plc_tombstone",
        "prev": "bafyreig6xxxxxyyyyyzzzzzz",
        "sig": "test"
    });
    let ctx = PlcValidationContext {
        server_rotation_key: did_key.clone(),
        expected_signing_key: did_key,
        expected_handle: "test.handle".to_string(),
        expected_pds_endpoint: "https://pds.example.com".to_string(),
    };
    let result = validate_plc_operation_for_submission(&op, &ctx);
    assert!(result.is_ok(), "Tombstone should pass submission validation");
}
#[test]
fn test_verify_signature_missing_sig() {
    let op = json!({
        "type": "plc_operation",
        "rotationKeys": [],
        "verificationMethods": {},
        "alsoKnownAs": [],
        "services": {}
    });
    let result = verify_operation_signature(&op, &[]);
    assert!(matches!(result, Err(PlcError::InvalidResponse(msg)) if msg.contains("sig")));
}
#[test]
fn test_verify_signature_invalid_base64() {
    let op = json!({
        "type": "plc_operation",
        "rotationKeys": [],
        "verificationMethods": {},
        "alsoKnownAs": [],
        "services": {},
        "sig": "not-valid-base64!!!"
    });
    let result = verify_operation_signature(&op, &[]);
    assert!(matches!(result, Err(PlcError::InvalidResponse(_))));
}
#[test]
fn test_plc_operation_struct() {
    let mut services = HashMap::new();
    services.insert("atproto_pds".to_string(), PlcService {
        service_type: "AtprotoPersonalDataServer".to_string(),
        endpoint: "https://pds.example.com".to_string(),
    });
    let mut verification_methods = HashMap::new();
    verification_methods.insert("atproto".to_string(), "did:key:zTest123".to_string());
    let op = PlcOperation {
        op_type: "plc_operation".to_string(),
        rotation_keys: vec!["did:key:zTest123".to_string()],
        verification_methods,
        also_known_as: vec!["at://test.handle".to_string()],
        services,
        prev: None,
        sig: Some("test".to_string()),
    };
    let json_value = serde_json::to_value(&op).unwrap();
    assert_eq!(json_value["type"], "plc_operation");
    assert!(json_value["rotationKeys"].is_array());
}
