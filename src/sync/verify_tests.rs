#[cfg(test)]
mod tests {
    use crate::sync::verify::{CarVerifier, VerifyError};
    use bytes::Bytes;
    use cid::Cid;
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;

    fn make_cid(data: &[u8]) -> Cid {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();
        let multihash = multihash::Multihash::wrap(0x12, &hash).unwrap();
        Cid::new_v1(0x71, multihash)
    }

    #[test]
    fn test_verifier_creation() {
        let _verifier = CarVerifier::new();
    }

    #[test]
    fn test_verify_error_display() {
        let err = VerifyError::DidMismatch {
            commit_did: "did:plc:abc".to_string(),
            expected_did: "did:plc:xyz".to_string(),
        };
        assert!(err.to_string().contains("did:plc:abc"));
        assert!(err.to_string().contains("did:plc:xyz"));

        let err = VerifyError::InvalidSignature;
        assert!(err.to_string().contains("signature"));

        let err = VerifyError::NoSigningKey;
        assert!(err.to_string().contains("signing key"));

        let err = VerifyError::MstValidationFailed("test error".to_string());
        assert!(err.to_string().contains("test error"));
    }

    #[test]
    fn test_mst_validation_missing_root_block() {
        let verifier = CarVerifier::new();
        let blocks: HashMap<Cid, Bytes> = HashMap::new();

        let fake_cid = make_cid(b"fake data");
        let result = verifier.verify_mst_structure(&fake_cid, &blocks);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, VerifyError::BlockNotFound(_)));
    }

    #[test]
    fn test_mst_validation_invalid_cbor() {
        let verifier = CarVerifier::new();

        let bad_cbor = Bytes::from(vec![0xFF, 0xFF, 0xFF]);
        let cid = make_cid(&bad_cbor);

        let mut blocks = HashMap::new();
        blocks.insert(cid, bad_cbor);

        let result = verifier.verify_mst_structure(&cid, &blocks);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, VerifyError::InvalidCbor(_)));
    }

    #[test]
    fn test_mst_validation_empty_node() {
        let verifier = CarVerifier::new();

        let empty_node = serde_ipld_dagcbor::to_vec(&serde_json::json!({
            "e": []
        })).unwrap();
        let cid = make_cid(&empty_node);

        let mut blocks = HashMap::new();
        blocks.insert(cid, Bytes::from(empty_node));

        let result = verifier.verify_mst_structure(&cid, &blocks);
        assert!(result.is_ok());
    }

    #[test]
    fn test_mst_validation_missing_left_pointer() {
        use ipld_core::ipld::Ipld;

        let verifier = CarVerifier::new();

        let missing_left_cid = make_cid(b"missing left");
        let node = Ipld::Map(std::collections::BTreeMap::from([
            ("l".to_string(), Ipld::Link(missing_left_cid)),
            ("e".to_string(), Ipld::List(vec![])),
        ]));
        let node_bytes = serde_ipld_dagcbor::to_vec(&node).unwrap();
        let cid = make_cid(&node_bytes);

        let mut blocks = HashMap::new();
        blocks.insert(cid, Bytes::from(node_bytes));

        let result = verifier.verify_mst_structure(&cid, &blocks);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, VerifyError::BlockNotFound(_)));
        assert!(err.to_string().contains("left pointer"));
    }

    #[test]
    fn test_mst_validation_missing_subtree() {
        use ipld_core::ipld::Ipld;

        let verifier = CarVerifier::new();

        let missing_subtree_cid = make_cid(b"missing subtree");
        let record_cid = make_cid(b"record");

        let entry = Ipld::Map(std::collections::BTreeMap::from([
            ("k".to_string(), Ipld::Bytes(b"key1".to_vec())),
            ("v".to_string(), Ipld::Link(record_cid)),
            ("p".to_string(), Ipld::Integer(0)),
            ("t".to_string(), Ipld::Link(missing_subtree_cid)),
        ]));

        let node = Ipld::Map(std::collections::BTreeMap::from([
            ("e".to_string(), Ipld::List(vec![entry])),
        ]));
        let node_bytes = serde_ipld_dagcbor::to_vec(&node).unwrap();
        let cid = make_cid(&node_bytes);

        let mut blocks = HashMap::new();
        blocks.insert(cid, Bytes::from(node_bytes));

        let result = verifier.verify_mst_structure(&cid, &blocks);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, VerifyError::BlockNotFound(_)));
        assert!(err.to_string().contains("subtree"));
    }

    #[test]
    fn test_mst_validation_unsorted_keys() {
        use ipld_core::ipld::Ipld;

        let verifier = CarVerifier::new();

        let record_cid = make_cid(b"record");

        let entry1 = Ipld::Map(std::collections::BTreeMap::from([
            ("k".to_string(), Ipld::Bytes(b"zzz".to_vec())),
            ("v".to_string(), Ipld::Link(record_cid)),
            ("p".to_string(), Ipld::Integer(0)),
        ]));

        let entry2 = Ipld::Map(std::collections::BTreeMap::from([
            ("k".to_string(), Ipld::Bytes(b"aaa".to_vec())),
            ("v".to_string(), Ipld::Link(record_cid)),
            ("p".to_string(), Ipld::Integer(0)),
        ]));

        let node = Ipld::Map(std::collections::BTreeMap::from([
            ("e".to_string(), Ipld::List(vec![entry1, entry2])),
        ]));
        let node_bytes = serde_ipld_dagcbor::to_vec(&node).unwrap();
        let cid = make_cid(&node_bytes);

        let mut blocks = HashMap::new();
        blocks.insert(cid, Bytes::from(node_bytes));

        let result = verifier.verify_mst_structure(&cid, &blocks);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, VerifyError::MstValidationFailed(_)));
        assert!(err.to_string().contains("sorted"));
    }

    #[test]
    fn test_mst_validation_sorted_keys_ok() {
        use ipld_core::ipld::Ipld;

        let verifier = CarVerifier::new();

        let record_cid = make_cid(b"record");

        let entry1 = Ipld::Map(std::collections::BTreeMap::from([
            ("k".to_string(), Ipld::Bytes(b"aaa".to_vec())),
            ("v".to_string(), Ipld::Link(record_cid)),
            ("p".to_string(), Ipld::Integer(0)),
        ]));

        let entry2 = Ipld::Map(std::collections::BTreeMap::from([
            ("k".to_string(), Ipld::Bytes(b"bbb".to_vec())),
            ("v".to_string(), Ipld::Link(record_cid)),
            ("p".to_string(), Ipld::Integer(0)),
        ]));

        let entry3 = Ipld::Map(std::collections::BTreeMap::from([
            ("k".to_string(), Ipld::Bytes(b"zzz".to_vec())),
            ("v".to_string(), Ipld::Link(record_cid)),
            ("p".to_string(), Ipld::Integer(0)),
        ]));

        let node = Ipld::Map(std::collections::BTreeMap::from([
            ("e".to_string(), Ipld::List(vec![entry1, entry2, entry3])),
        ]));
        let node_bytes = serde_ipld_dagcbor::to_vec(&node).unwrap();
        let cid = make_cid(&node_bytes);

        let mut blocks = HashMap::new();
        blocks.insert(cid, Bytes::from(node_bytes));

        let result = verifier.verify_mst_structure(&cid, &blocks);
        assert!(result.is_ok());
    }

    #[test]
    fn test_mst_validation_with_valid_left_pointer() {
        use ipld_core::ipld::Ipld;

        let verifier = CarVerifier::new();

        let left_node = Ipld::Map(std::collections::BTreeMap::from([
            ("e".to_string(), Ipld::List(vec![])),
        ]));
        let left_node_bytes = serde_ipld_dagcbor::to_vec(&left_node).unwrap();
        let left_cid = make_cid(&left_node_bytes);

        let root_node = Ipld::Map(std::collections::BTreeMap::from([
            ("l".to_string(), Ipld::Link(left_cid)),
            ("e".to_string(), Ipld::List(vec![])),
        ]));
        let root_node_bytes = serde_ipld_dagcbor::to_vec(&root_node).unwrap();
        let root_cid = make_cid(&root_node_bytes);

        let mut blocks = HashMap::new();
        blocks.insert(root_cid, Bytes::from(root_node_bytes));
        blocks.insert(left_cid, Bytes::from(left_node_bytes));

        let result = verifier.verify_mst_structure(&root_cid, &blocks);
        assert!(result.is_ok());
    }

    #[test]
    fn test_mst_validation_cycle_detection() {
        let verifier = CarVerifier::new();

        let node = serde_ipld_dagcbor::to_vec(&serde_json::json!({
            "e": []
        })).unwrap();
        let cid = make_cid(&node);

        let mut blocks = HashMap::new();
        blocks.insert(cid, Bytes::from(node));

        let result = verifier.verify_mst_structure(&cid, &blocks);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_unsupported_did_method() {
        let verifier = CarVerifier::new();
        let result = verifier.resolve_did_document("did:unknown:test").await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, VerifyError::DidResolutionFailed(_)));
        assert!(err.to_string().contains("Unsupported"));
    }

    #[test]
    fn test_mst_validation_with_prefix_compression() {
        use ipld_core::ipld::Ipld;

        let verifier = CarVerifier::new();
        let record_cid = make_cid(b"record");

        let entry1 = Ipld::Map(std::collections::BTreeMap::from([
            ("k".to_string(), Ipld::Bytes(b"app.bsky.feed.post/abc".to_vec())),
            ("v".to_string(), Ipld::Link(record_cid)),
            ("p".to_string(), Ipld::Integer(0)),
        ]));

        let entry2 = Ipld::Map(std::collections::BTreeMap::from([
            ("k".to_string(), Ipld::Bytes(b"def".to_vec())),
            ("v".to_string(), Ipld::Link(record_cid)),
            ("p".to_string(), Ipld::Integer(19)),
        ]));

        let entry3 = Ipld::Map(std::collections::BTreeMap::from([
            ("k".to_string(), Ipld::Bytes(b"xyz".to_vec())),
            ("v".to_string(), Ipld::Link(record_cid)),
            ("p".to_string(), Ipld::Integer(19)),
        ]));

        let node = Ipld::Map(std::collections::BTreeMap::from([
            ("e".to_string(), Ipld::List(vec![entry1, entry2, entry3])),
        ]));
        let node_bytes = serde_ipld_dagcbor::to_vec(&node).unwrap();
        let cid = make_cid(&node_bytes);

        let mut blocks = HashMap::new();
        blocks.insert(cid, Bytes::from(node_bytes));

        let result = verifier.verify_mst_structure(&cid, &blocks);
        assert!(result.is_ok(), "Prefix-compressed keys should be validated correctly");
    }

    #[test]
    fn test_mst_validation_prefix_compression_unsorted() {
        use ipld_core::ipld::Ipld;

        let verifier = CarVerifier::new();
        let record_cid = make_cid(b"record");

        let entry1 = Ipld::Map(std::collections::BTreeMap::from([
            ("k".to_string(), Ipld::Bytes(b"app.bsky.feed.post/xyz".to_vec())),
            ("v".to_string(), Ipld::Link(record_cid)),
            ("p".to_string(), Ipld::Integer(0)),
        ]));

        let entry2 = Ipld::Map(std::collections::BTreeMap::from([
            ("k".to_string(), Ipld::Bytes(b"abc".to_vec())),
            ("v".to_string(), Ipld::Link(record_cid)),
            ("p".to_string(), Ipld::Integer(19)),
        ]));

        let node = Ipld::Map(std::collections::BTreeMap::from([
            ("e".to_string(), Ipld::List(vec![entry1, entry2])),
        ]));
        let node_bytes = serde_ipld_dagcbor::to_vec(&node).unwrap();
        let cid = make_cid(&node_bytes);

        let mut blocks = HashMap::new();
        blocks.insert(cid, Bytes::from(node_bytes));

        let result = verifier.verify_mst_structure(&cid, &blocks);
        assert!(result.is_err(), "Unsorted prefix-compressed keys should fail validation");
        let err = result.unwrap_err();
        assert!(matches!(err, VerifyError::MstValidationFailed(_)));
    }
}
