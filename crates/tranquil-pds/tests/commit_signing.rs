use cid::Cid;
use jacquard_common::types::{integer::LimitedU32, string::Tid};
use jacquard_repo::commit::Commit;
use k256::ecdsa::SigningKey;
use std::str::FromStr;
use tranquil_pds::Did;

#[test]
fn test_commit_signing_produces_valid_signature() {
    let signing_key = SigningKey::random(&mut rand::thread_rng());

    let did = "did:plc:testuser123456789abcdef";
    let data_cid =
        Cid::from_str("bafyreib2rxk3ryblouj3fxza5jvx6psmwewwessc4m6g6e7pqhhkwqomfi").unwrap();
    let rev = Tid::now(LimitedU32::MIN);

    let did_typed = jacquard_common::types::string::Did::new(did).unwrap();
    let unsigned = Commit::new_unsigned(did_typed, data_cid, rev, None);
    let signed = unsigned.sign(&signing_key).unwrap();

    let pubkey_bytes = signing_key.verifying_key().to_encoded_point(true);
    let pubkey = jacquard_common::types::crypto::PublicKey {
        codec: jacquard_common::types::crypto::KeyCodec::Secp256k1,
        bytes: std::borrow::Cow::Owned(pubkey_bytes.as_bytes().to_vec()),
    };

    signed.verify(&pubkey).expect("signature should verify");
}

#[test]
fn test_commit_signing_with_prev() {
    let signing_key = SigningKey::random(&mut rand::thread_rng());

    let did = "did:plc:testuser123456789abcdef";
    let data_cid =
        Cid::from_str("bafyreib2rxk3ryblouj3fxza5jvx6psmwewwessc4m6g6e7pqhhkwqomfi").unwrap();
    let prev_cid =
        Cid::from_str("bafyreigxmvutyl3k5m4guzwxv3xf34gfxjlykgfdqkjmf32vwb5vcjxlui").unwrap();
    let rev = Tid::now(LimitedU32::MIN);

    let did_typed = jacquard_common::types::string::Did::new(did).unwrap();
    let unsigned = Commit::new_unsigned(did_typed, data_cid, rev, Some(prev_cid));
    let signed = unsigned.sign(&signing_key).unwrap();

    let pubkey_bytes = signing_key.verifying_key().to_encoded_point(true);
    let pubkey = jacquard_common::types::crypto::PublicKey {
        codec: jacquard_common::types::crypto::KeyCodec::Secp256k1,
        bytes: std::borrow::Cow::Owned(pubkey_bytes.as_bytes().to_vec()),
    };

    signed.verify(&pubkey).expect("signature should verify");
}

#[test]
fn test_unsigned_commit_has_5_fields() {
    let did = "did:plc:test";
    let data_cid =
        Cid::from_str("bafyreib2rxk3ryblouj3fxza5jvx6psmwewwessc4m6g6e7pqhhkwqomfi").unwrap();
    let rev = Tid::from_str("3masrxv55po22").unwrap();

    let did_typed = jacquard_common::types::string::Did::new(did).unwrap();
    let unsigned = Commit::new_unsigned(did_typed, data_cid, rev, None);

    let unsigned_bytes = serde_ipld_dagcbor::to_vec(&unsigned).unwrap();

    let decoded: ciborium::Value = ciborium::from_reader(&unsigned_bytes[..]).unwrap();
    if let ciborium::Value::Map(map) = decoded {
        assert_eq!(
            map.len(),
            5,
            "Unsigned commit must have exactly 5 fields (data, did, prev, rev, version) - no sig field"
        );
        let keys: Vec<String> = map
            .iter()
            .filter_map(|(k, _)| {
                if let ciborium::Value::Text(s) = k {
                    Some(s.clone())
                } else {
                    None
                }
            })
            .collect();
        assert!(keys.contains(&"data".to_string()));
        assert!(keys.contains(&"did".to_string()));
        assert!(keys.contains(&"prev".to_string()));
        assert!(keys.contains(&"rev".to_string()));
        assert!(keys.contains(&"version".to_string()));
        assert!(
            !keys.contains(&"sig".to_string()),
            "Unsigned commit must NOT contain sig field"
        );
    } else {
        panic!("Expected CBOR map");
    }
}

#[test]
fn test_create_signed_commit_helper() {
    use tranquil_pds::api::repo::record::utils::create_signed_commit;

    let signing_key = SigningKey::random(&mut rand::thread_rng());
    let did = unsafe { Did::new_unchecked("did:plc:testuser123456789abcdef") };
    let data_cid =
        Cid::from_str("bafyreib2rxk3ryblouj3fxza5jvx6psmwewwessc4m6g6e7pqhhkwqomfi").unwrap();
    let rev = Tid::now(LimitedU32::MIN).to_string();

    let (signed_bytes, sig) = create_signed_commit(&did, data_cid, &rev, None, &signing_key)
        .expect("signing should succeed");

    assert!(!signed_bytes.is_empty());
    assert_eq!(sig.len(), 64);

    let commit = Commit::from_cbor(&signed_bytes).expect("should parse as valid commit");

    let pubkey_bytes = signing_key.verifying_key().to_encoded_point(true);
    let pubkey = jacquard_common::types::crypto::PublicKey {
        codec: jacquard_common::types::crypto::KeyCodec::Secp256k1,
        bytes: std::borrow::Cow::Owned(pubkey_bytes.as_bytes().to_vec()),
    };

    commit.verify(&pubkey).expect("signature should verify");
}
