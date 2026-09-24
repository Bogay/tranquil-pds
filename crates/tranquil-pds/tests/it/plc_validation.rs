use k256::ecdsa::SigningKey;
use serde_json::json;
use std::collections::HashMap;
use tranquil_pds::plc::{
    PlcError, PlcOpType, PlcOperation, PlcService, PlcValidationContext, cid_for_cbor,
    sign_operation, signing_key_to_did_key, validate_plc_operation,
    validate_plc_operation_for_submission, verify_operation_signature,
};

fn create_valid_operation() -> serde_json::Value {
    let key = SigningKey::random(&mut rand::thread_rng());
    let did_key = signing_key_to_did_key(&key);
    let op = json!({
        "type": "plc_operation",
        "rotationKeys": [did_key.clone()],
        "verificationMethods": { "atproto": did_key.clone() },
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
fn test_plc_operation_basic_validation() {
    let op = create_valid_operation();
    assert!(validate_plc_operation(&op).is_ok());

    let missing_type = json!({ "rotationKeys": [], "verificationMethods": {}, "alsoKnownAs": [], "services": {}, "sig": "test" });
    assert!(
        matches!(validate_plc_operation(&missing_type), Err(PlcError::InvalidResponse(msg)) if msg.contains("Missing type"))
    );

    let invalid_type = json!({ "type": "invalid_type", "sig": "test" });
    assert!(
        matches!(validate_plc_operation(&invalid_type), Err(PlcError::InvalidResponse(msg)) if msg.contains("Invalid type"))
    );

    let missing_sig = json!({ "type": "plc_operation", "rotationKeys": [], "verificationMethods": {}, "alsoKnownAs": [], "services": {} });
    assert!(
        matches!(validate_plc_operation(&missing_sig), Err(PlcError::InvalidResponse(msg)) if msg.contains("Missing sig"))
    );

    let missing_rotation = json!({ "type": "plc_operation", "verificationMethods": {}, "alsoKnownAs": [], "services": {}, "sig": "test" });
    assert!(
        matches!(validate_plc_operation(&missing_rotation), Err(PlcError::InvalidResponse(msg)) if msg.contains("rotationKeys"))
    );

    let missing_verification = json!({ "type": "plc_operation", "rotationKeys": [], "alsoKnownAs": [], "services": {}, "sig": "test" });
    assert!(
        matches!(validate_plc_operation(&missing_verification), Err(PlcError::InvalidResponse(msg)) if msg.contains("verificationMethods"))
    );

    let missing_aka = json!({ "type": "plc_operation", "rotationKeys": [], "verificationMethods": {}, "services": {}, "sig": "test" });
    assert!(
        matches!(validate_plc_operation(&missing_aka), Err(PlcError::InvalidResponse(msg)) if msg.contains("alsoKnownAs"))
    );

    let missing_services = json!({ "type": "plc_operation", "rotationKeys": [], "verificationMethods": {}, "alsoKnownAs": [], "sig": "test" });
    assert!(
        matches!(validate_plc_operation(&missing_services), Err(PlcError::InvalidResponse(msg)) if msg.contains("services"))
    );

    assert!(matches!(
        validate_plc_operation(&json!("not an object")),
        Err(PlcError::InvalidResponse(_))
    ));
}

#[test]
fn test_plc_submission_validation() {
    let key = SigningKey::random(&mut rand::thread_rng());
    let did_key = signing_key_to_did_key(&key);
    let server_key = "did:key:zServer123";

    let base_op = |rotation_key: &str,
                   signing_key: &str,
                   handle: &str,
                   service_type: &str,
                   endpoint: &str| {
        json!({
            "type": "plc_operation",
            "rotationKeys": [rotation_key],
            "verificationMethods": {"atproto": signing_key},
            "alsoKnownAs": [format!("at://{}", handle)],
            "services": { "atproto_pds": { "type": service_type, "endpoint": endpoint } },
            "sig": "test"
        })
    };

    let ctx = PlcValidationContext {
        server_rotation_key: server_key.to_string(),
        expected_signing_key: did_key.clone(),
        expected_handle: "test.handle".to_string(),
        expected_pds_endpoint: "https://pds.example.com".to_string(),
    };

    let op = base_op(
        &did_key,
        &did_key,
        "test.handle",
        "AtprotoPersonalDataServer",
        "https://pds.example.com",
    );
    assert!(
        matches!(validate_plc_operation_for_submission(&op, &ctx), Err(PlcError::InvalidResponse(msg)) if msg.contains("rotation key"))
    );

    let ctx_with_user_key = PlcValidationContext {
        server_rotation_key: did_key.clone(),
        expected_signing_key: did_key.clone(),
        expected_handle: "test.handle".to_string(),
        expected_pds_endpoint: "https://pds.example.com".to_string(),
    };

    let wrong_signing = base_op(
        &did_key,
        "did:key:zWrongKey",
        "test.handle",
        "AtprotoPersonalDataServer",
        "https://pds.example.com",
    );
    assert!(
        matches!(validate_plc_operation_for_submission(&wrong_signing, &ctx_with_user_key), Err(PlcError::InvalidResponse(msg)) if msg.contains("signing key"))
    );

    let wrong_handle = base_op(
        &did_key,
        &did_key,
        "wrong.handle",
        "AtprotoPersonalDataServer",
        "https://pds.example.com",
    );
    assert!(
        matches!(validate_plc_operation_for_submission(&wrong_handle, &ctx_with_user_key), Err(PlcError::InvalidResponse(msg)) if msg.contains("handle"))
    );

    let wrong_service_type = base_op(
        &did_key,
        &did_key,
        "test.handle",
        "WrongServiceType",
        "https://pds.example.com",
    );
    assert!(
        matches!(validate_plc_operation_for_submission(&wrong_service_type, &ctx_with_user_key), Err(PlcError::InvalidResponse(msg)) if msg.contains("type"))
    );

    let wrong_endpoint = base_op(
        &did_key,
        &did_key,
        "test.handle",
        "AtprotoPersonalDataServer",
        "https://wrong.endpoint.com",
    );
    assert!(
        matches!(validate_plc_operation_for_submission(&wrong_endpoint, &ctx_with_user_key), Err(PlcError::InvalidResponse(msg)) if msg.contains("endpoint"))
    );
}

#[test]
fn test_signature_verification() {
    let key = SigningKey::random(&mut rand::thread_rng());
    let did_key = signing_key_to_did_key(&key);
    let op = json!({
        "type": "plc_operation", "rotationKeys": [did_key.clone()],
        "verificationMethods": {}, "alsoKnownAs": [], "services": {}, "prev": null
    });
    let signed = sign_operation(&op, &key).unwrap();
    let result = verify_operation_signature(&signed, std::slice::from_ref(&did_key));
    assert!(result.is_ok() && result.unwrap());

    let other_key = SigningKey::random(&mut rand::thread_rng());
    let other_did = signing_key_to_did_key(&other_key);
    let result = verify_operation_signature(&signed, &[other_did]);
    assert!(result.is_ok() && !result.unwrap());

    let result = verify_operation_signature(&signed, &["not-a-did-key".to_string()]);
    assert!(result.is_ok() && !result.unwrap());

    let missing_sig = json!({ "type": "plc_operation", "rotationKeys": [], "verificationMethods": {}, "alsoKnownAs": [], "services": {} });
    assert!(
        matches!(verify_operation_signature(&missing_sig, &[]), Err(PlcError::InvalidResponse(msg)) if msg.contains("sig"))
    );

    let invalid_base64 = json!({
        "type": "plc_operation", "rotationKeys": [], "verificationMethods": {},
        "alsoKnownAs": [], "services": {}, "sig": "not-valid-base64!!!"
    });
    assert!(matches!(
        verify_operation_signature(&invalid_base64, &[]),
        Err(PlcError::InvalidResponse(_))
    ));
}

#[test]
fn test_cid_and_key_utilities() {
    let value = json!({ "alpha": 1, "beta": 2 });
    let cid1 = cid_for_cbor(&value).unwrap();
    let cid2 = cid_for_cbor(&value).unwrap();
    assert_eq!(cid1, cid2, "CID should be deterministic");
    assert!(
        cid1.starts_with("bafyrei"),
        "CID should be dag-cbor + sha256"
    );

    let value2 = json!({ "alpha": 999 });
    let cid3 = cid_for_cbor(&value2).unwrap();
    assert_ne!(cid1, cid3, "Different data should produce different CIDs");

    let key = SigningKey::random(&mut rand::thread_rng());
    let did = signing_key_to_did_key(&key);
    assert!(did.starts_with("did:key:z") && did.len() > 50);
    assert_eq!(
        did,
        signing_key_to_did_key(&key),
        "Same key should produce same did"
    );

    let key2 = SigningKey::random(&mut rand::thread_rng());
    assert_ne!(
        did,
        signing_key_to_did_key(&key2),
        "Different keys should produce different dids"
    );
}

#[test]
fn test_tombstone_operations() {
    let tombstone =
        json!({ "type": "plc_tombstone", "prev": "bafyreig6xxxxxyyyyyzzzzzz", "sig": "test" });
    assert!(validate_plc_operation(&tombstone).is_ok());

    let key = SigningKey::random(&mut rand::thread_rng());
    let did_key = signing_key_to_did_key(&key);
    let ctx = PlcValidationContext {
        server_rotation_key: did_key.clone(),
        expected_signing_key: did_key,
        expected_handle: "test.handle".to_string(),
        expected_pds_endpoint: "https://pds.example.com".to_string(),
    };
    assert!(validate_plc_operation_for_submission(&tombstone, &ctx).is_ok());
}

#[test]
fn test_sign_operation_and_struct() {
    let key = SigningKey::random(&mut rand::thread_rng());
    let op = json!({
        "type": "plc_operation", "rotationKeys": [], "verificationMethods": {},
        "alsoKnownAs": [], "services": {}, "prev": null, "sig": "old_signature"
    });
    let signed = sign_operation(&op, &key).unwrap();
    assert_ne!(
        signed.get("sig").and_then(|v| v.as_str()).unwrap(),
        "old_signature"
    );

    let mut services = HashMap::new();
    services.insert(
        "atproto_pds".to_string(),
        PlcService {
            service_type: tranquil_pds::plc::ServiceType::Pds,
            endpoint: "https://pds.example.com".to_string(),
        },
    );
    let mut verification_methods = HashMap::new();
    verification_methods.insert("atproto".to_string(), "did:key:zTest123".to_string());
    let op = PlcOperation {
        op_type: PlcOpType::Operation,
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
