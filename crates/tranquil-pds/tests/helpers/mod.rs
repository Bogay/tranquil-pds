use chrono::Utc;
use reqwest::StatusCode;
use serde_json::{Value, json};

pub use crate::common::*;

#[allow(dead_code)]
pub async fn paginate_records(
    client: &reqwest::Client,
    base: &str,
    jwt: &str,
    did: &str,
    collection: &str,
    limit: usize,
) -> Vec<Value> {
    paginate_records_inner(client, base, jwt, did, collection, limit, None, Vec::new()).await
}

#[allow(clippy::too_many_arguments)]
async fn paginate_records_inner(
    client: &reqwest::Client,
    base: &str,
    jwt: &str,
    did: &str,
    collection: &str,
    limit: usize,
    cursor: Option<String>,
    mut acc: Vec<Value>,
) -> Vec<Value> {
    let limit_str = limit.to_string();
    let mut query: Vec<(&str, &str)> = vec![
        ("repo", did),
        ("collection", collection),
        ("limit", &limit_str),
    ];
    if let Some(ref c) = cursor {
        query.push(("cursor", c.as_str()));
    }

    let res = client
        .get(format!("{}/xrpc/com.atproto.repo.listRecords", base))
        .bearer_auth(jwt)
        .query(&query)
        .send()
        .await;

    let Ok(response) = res else { return acc };
    let Ok(body) = response.json::<Value>().await else {
        return acc;
    };

    let Some(records) = body["records"].as_array() else {
        return acc;
    };
    acc.extend(records.iter().cloned());

    match body["cursor"].as_str() {
        Some(next) => {
            Box::pin(paginate_records_inner(
                client,
                base,
                jwt,
                did,
                collection,
                limit,
                Some(next.to_string()),
                acc,
            ))
            .await
        }
        None => acc,
    }
}

#[allow(dead_code)]
pub async fn count_records(
    client: &reqwest::Client,
    base: &str,
    jwt: &str,
    did: &str,
    collection: &str,
) -> usize {
    paginate_records(client, base, jwt, did, collection, 100)
        .await
        .len()
}

fn unique_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..12].to_string()
}

#[allow(dead_code)]
pub async fn setup_new_user(handle_prefix: &str) -> (String, String) {
    let client = client();
    let uid = unique_id();
    let handle = format!("{}-{}.test", handle_prefix, uid);
    let email = format!("{}-{}@test.com", handle_prefix, uid);
    let password = "E2epass123!";
    let create_account_payload = json!({
        "handle": handle,
        "email": email,
        "password": password
    });
    let create_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            base_url().await
        ))
        .json(&create_account_payload)
        .send()
        .await
        .expect("setup_new_user: Failed to send createAccount");
    if create_res.status() != reqwest::StatusCode::OK {
        panic!(
            "setup_new_user: Failed to create account: {:?}",
            create_res.text().await
        );
    }
    let create_body: Value = create_res
        .json()
        .await
        .expect("setup_new_user: createAccount response was not JSON");
    let new_did = create_body["did"]
        .as_str()
        .expect("setup_new_user: Response had no DID")
        .to_string();
    let new_jwt = verify_new_account(&client, &new_did).await;
    (new_did, new_jwt)
}

#[allow(dead_code)]
pub async fn create_post(
    client: &reqwest::Client,
    did: &str,
    jwt: &str,
    text: &str,
) -> (String, String) {
    let collection = "app.bsky.feed.post";
    let rkey = format!("e2e_social_{}", unique_id());
    let now = Utc::now().to_rfc3339();
    let create_payload = json!({
        "repo": did,
        "collection": collection,
        "rkey": rkey,
        "record": {
            "$type": collection,
            "text": text,
            "createdAt": now
        }
    });
    let create_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .bearer_auth(jwt)
        .json(&create_payload)
        .send()
        .await
        .expect("Failed to send create post request");
    assert_eq!(
        create_res.status(),
        reqwest::StatusCode::OK,
        "Failed to create post record"
    );
    let create_body: Value = create_res
        .json()
        .await
        .expect("create post response was not JSON");
    let uri = create_body["uri"].as_str().unwrap().to_string();
    let cid = create_body["cid"].as_str().unwrap().to_string();
    (uri, cid)
}

#[allow(dead_code)]
pub async fn create_follow(
    client: &reqwest::Client,
    follower_did: &str,
    follower_jwt: &str,
    followee_did: &str,
) -> (String, String) {
    let collection = "app.bsky.graph.follow";
    let rkey = format!("e2e_follow_{}", unique_id());
    let now = Utc::now().to_rfc3339();
    let create_payload = json!({
        "repo": follower_did,
        "collection": collection,
        "rkey": rkey,
        "record": {
            "$type": collection,
            "subject": followee_did,
            "createdAt": now
        }
    });
    let create_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .bearer_auth(follower_jwt)
        .json(&create_payload)
        .send()
        .await
        .expect("Failed to send create follow request");
    assert_eq!(
        create_res.status(),
        reqwest::StatusCode::OK,
        "Failed to create follow record"
    );
    let create_body: Value = create_res
        .json()
        .await
        .expect("create follow response was not JSON");
    let uri = create_body["uri"].as_str().unwrap().to_string();
    let cid = create_body["cid"].as_str().unwrap().to_string();
    (uri, cid)
}

#[allow(dead_code)]
pub async fn create_like(
    client: &reqwest::Client,
    liker_did: &str,
    liker_jwt: &str,
    subject_uri: &str,
    subject_cid: &str,
) -> (String, String) {
    let collection = "app.bsky.feed.like";
    let rkey = format!("e2e_like_{}", unique_id());
    let now = Utc::now().to_rfc3339();
    let payload = json!({
        "repo": liker_did,
        "collection": collection,
        "rkey": rkey,
        "record": {
            "$type": collection,
            "subject": {
                "uri": subject_uri,
                "cid": subject_cid
            },
            "createdAt": now
        }
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .bearer_auth(liker_jwt)
        .json(&payload)
        .send()
        .await
        .expect("Failed to create like");
    assert_eq!(res.status(), StatusCode::OK, "Failed to create like");
    let body: Value = res.json().await.expect("Like response not JSON");
    (
        body["uri"].as_str().unwrap().to_string(),
        body["cid"].as_str().unwrap().to_string(),
    )
}

#[allow(dead_code)]
pub async fn create_repost(
    client: &reqwest::Client,
    reposter_did: &str,
    reposter_jwt: &str,
    subject_uri: &str,
    subject_cid: &str,
) -> (String, String) {
    let collection = "app.bsky.feed.repost";
    let rkey = format!("e2e_repost_{}", unique_id());
    let now = Utc::now().to_rfc3339();
    let payload = json!({
        "repo": reposter_did,
        "collection": collection,
        "rkey": rkey,
        "record": {
            "$type": collection,
            "subject": {
                "uri": subject_uri,
                "cid": subject_cid
            },
            "createdAt": now
        }
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .bearer_auth(reposter_jwt)
        .json(&payload)
        .send()
        .await
        .expect("Failed to create repost");
    assert_eq!(res.status(), StatusCode::OK, "Failed to create repost");
    let body: Value = res.json().await.expect("Repost response not JSON");
    (
        body["uri"].as_str().unwrap().to_string(),
        body["cid"].as_str().unwrap().to_string(),
    )
}

#[allow(dead_code)]
pub async fn set_account_takedown(did: &str, takedown_ref: Option<&str>) {
    let client = client();
    let (admin_jwt, _) = create_admin_account_and_login(&client).await;
    let applied = takedown_ref.is_some();
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.admin.updateSubjectStatus",
            base_url().await,
        ))
        .bearer_auth(&admin_jwt)
        .json(&json!({
            "subject": {
                "$type": "com.atproto.admin.defs#repoRef",
                "did": did
            },
            "takedown": {
                "applied": applied,
                "ref": takedown_ref
            }
        }))
        .send()
        .await
        .expect("Failed to send takedown request");
    assert_eq!(res.status(), StatusCode::OK, "Failed to set takedown");
}

#[allow(dead_code)]
pub async fn set_account_deactivated(did: &str, deactivated: bool) {
    let client = client();
    let (admin_jwt, _) = create_admin_account_and_login(&client).await;
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.admin.updateSubjectStatus",
            base_url().await,
        ))
        .bearer_auth(&admin_jwt)
        .json(&json!({
            "subject": {
                "$type": "com.atproto.admin.defs#repoRef",
                "did": did
            },
            "deactivated": {
                "applied": deactivated
            }
        }))
        .send()
        .await
        .expect("Failed to send deactivation request");
    assert_eq!(res.status(), StatusCode::OK, "Failed to set deactivation");
}

#[allow(dead_code)]
pub fn make_cid(data: &[u8]) -> cid::Cid {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(data);
    let multihash = multihash::Multihash::wrap(0x12, &hash).unwrap();
    cid::Cid::new_v1(0x71, multihash)
}

#[allow(dead_code)]
pub fn write_varint(buf: &mut Vec<u8>, value: u64) {
    buf.extend(encode_varint_bytes(value));
}

fn encode_varint_bytes(value: u64) -> Vec<u8> {
    match value < 0x80 {
        true => vec![value as u8],
        false => {
            let mut rest = encode_varint_bytes(value >> 7);
            rest.insert(0, ((value & 0x7F) as u8) | 0x80);
            rest
        }
    }
}

#[allow(dead_code)]
pub fn encode_car_block(cid: &cid::Cid, data: &[u8]) -> Vec<u8> {
    let cid_bytes = cid.to_bytes();
    let mut result = Vec::new();
    write_varint(&mut result, (cid_bytes.len() + data.len()) as u64);
    result.extend_from_slice(&cid_bytes);
    result.extend_from_slice(data);
    result
}

#[allow(dead_code)]
pub fn create_test_record() -> (Vec<u8>, cid::Cid) {
    use ipld_core::ipld::Ipld;
    use std::collections::BTreeMap;
    let record = Ipld::Map(BTreeMap::from([
        (
            "$type".to_string(),
            Ipld::String("app.bsky.feed.post".to_string()),
        ),
        (
            "text".to_string(),
            Ipld::String("Test post for verification".to_string()),
        ),
        (
            "createdAt".to_string(),
            Ipld::String("2024-01-01T00:00:00Z".to_string()),
        ),
    ]));
    let bytes = serde_ipld_dagcbor::to_vec(&record).unwrap();
    let cid = make_cid(&bytes);
    (bytes, cid)
}

#[allow(dead_code)]
pub fn create_mst_node(entries: Vec<(String, cid::Cid)>) -> (Vec<u8>, cid::Cid) {
    use ipld_core::ipld::Ipld;
    use std::collections::BTreeMap;
    let ipld_entries: Vec<Ipld> = entries
        .into_iter()
        .map(|(key, value_cid)| {
            Ipld::Map(BTreeMap::from([
                ("k".to_string(), Ipld::Bytes(key.into_bytes())),
                ("v".to_string(), Ipld::Link(value_cid)),
                ("p".to_string(), Ipld::Integer(0)),
            ]))
        })
        .collect();
    let node = Ipld::Map(BTreeMap::from([(
        "e".to_string(),
        Ipld::List(ipld_entries),
    )]));
    let bytes = serde_ipld_dagcbor::to_vec(&node).unwrap();
    let cid = make_cid(&bytes);
    (bytes, cid)
}

#[allow(dead_code)]
pub fn create_car_signed_commit(
    did: &str,
    data_cid: &cid::Cid,
    signing_key: &k256::ecdsa::SigningKey,
) -> (Vec<u8>, cid::Cid) {
    use jacquard_common::types::{integer::LimitedU32, string::Tid};
    use jacquard_repo::commit::Commit;
    let rev = Tid::now(LimitedU32::MIN);
    let did = jacquard_common::types::string::Did::new(did).expect("valid DID");
    let unsigned = Commit::new_unsigned(did, *data_cid, rev, None);
    let signed = unsigned.sign(signing_key).expect("signing failed");
    let signed_bytes = signed.to_cbor().expect("serialization failed");
    let cid = make_cid(&signed_bytes);
    (signed_bytes, cid)
}

#[allow(dead_code)]
pub fn build_car_with_signature(
    did: &str,
    signing_key: &k256::ecdsa::SigningKey,
) -> (Vec<u8>, cid::Cid) {
    let (record_bytes, record_cid) = create_test_record();
    let (mst_bytes, mst_cid) =
        create_mst_node(vec![("app.bsky.feed.post/test123".to_string(), record_cid)]);
    let (commit_bytes, commit_cid) = create_car_signed_commit(did, &mst_cid, signing_key);
    let header = iroh_car::CarHeader::new_v1(vec![commit_cid]);
    let header_bytes = header.encode().unwrap();
    let mut car = Vec::new();
    write_varint(&mut car, header_bytes.len() as u64);
    car.extend_from_slice(&header_bytes);
    car.extend(encode_car_block(&commit_cid, &commit_bytes));
    car.extend(encode_car_block(&mst_cid, &mst_bytes));
    car.extend(encode_car_block(&record_cid, &record_bytes));
    (car, commit_cid)
}

#[allow(dead_code)]
pub fn get_multikey_from_signing_key(signing_key: &k256::ecdsa::SigningKey) -> String {
    let public_key = signing_key.verifying_key();
    let compressed = public_key.to_sec1_bytes();
    let buf: Vec<u8> = encode_varint_bytes(0xE7)
        .into_iter()
        .chain(compressed.iter().copied())
        .collect();
    multibase::encode(multibase::Base::Base58Btc, buf)
}

#[allow(dead_code)]
pub async fn get_user_signing_key(did: &str) -> Option<Vec<u8>> {
    let repos = super::common::get_test_repos().await;
    let key_info = repos
        .user
        .get_user_key_by_did(&tranquil_types::Did::new(did.to_string()).ok()?)
        .await
        .ok()??;
    tranquil_pds::config::decrypt_key(&key_info.key_bytes, key_info.encryption_version).ok()
}
