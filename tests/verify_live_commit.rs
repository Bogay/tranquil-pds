use bytes::Bytes;
use cid::Cid;
use std::collections::HashMap;
use std::str::FromStr;
mod common;

#[tokio::test]
#[ignore = "depends on external live server state; run manually with --ignored"]
async fn test_verify_live_commit() {
    let client = reqwest::Client::new();
    let did = "did:plc:zp3oggo2mikqntmhrc4scby4";
    let resp = client
        .get(format!(
            "https://testpds.wizardry.systems/xrpc/com.atproto.sync.getRepo?did={}",
            did
        ))
        .send()
        .await
        .expect("Failed to fetch repo");
    assert!(
        resp.status().is_success(),
        "getRepo failed: {}",
        resp.status()
    );
    let car_bytes = resp.bytes().await.expect("Failed to read body");
    println!("CAR bytes: {} bytes", car_bytes.len());
    let mut cursor = std::io::Cursor::new(&car_bytes[..]);
    let (roots, blocks) = parse_car(&mut cursor).expect("Failed to parse CAR");
    println!("CAR roots: {:?}", roots);
    println!("CAR blocks: {}", blocks.len());
    assert!(!roots.is_empty(), "No roots in CAR");
    let root_cid = roots[0];
    let root_block = blocks.get(&root_cid).expect("Root block not found");
    let commit =
        jacquard_repo::commit::Commit::from_cbor(root_block).expect("Failed to parse commit");
    println!("Commit DID: {}", commit.did().as_str());
    println!("Commit rev: {}", commit.rev());
    println!("Commit prev: {:?}", commit.prev());
    println!("Commit sig length: {} bytes", commit.sig().len());
    let resp = client
        .get(format!("https://plc.directory/{}", did))
        .send()
        .await
        .expect("Failed to fetch DID doc");
    let did_doc_text = resp.text().await.expect("Failed to read body");
    println!("DID doc: {}", did_doc_text);
    let did_doc: jacquard::common::types::did_doc::DidDocument<'_> =
        serde_json::from_str(&did_doc_text).expect("Failed to parse DID doc");
    let pubkey = did_doc
        .atproto_public_key()
        .expect("Failed to get public key")
        .expect("No public key");
    println!("Public key codec: {:?}", pubkey.codec);
    println!("Public key bytes: {} bytes", pubkey.bytes.len());
    match commit.verify(&pubkey) {
        Ok(()) => println!("SIGNATURE VALID!"),
        Err(e) => {
            println!("SIGNATURE VERIFICATION FAILED: {:?}", e);
            let unsigned = commit_unsigned_bytes(&commit);
            println!("Unsigned bytes length: {} bytes", unsigned.len());
            panic!("Signature verification failed");
        }
    }
}

fn commit_unsigned_bytes(commit: &jacquard_repo::commit::Commit<'_>) -> Vec<u8> {
    #[derive(serde::Serialize)]
    struct UnsignedCommit<'a> {
        did: &'a str,
        version: i64,
        data: &'a cid::Cid,
        rev: &'a jacquard::types::string::Tid,
        prev: Option<&'a cid::Cid>,
        #[serde(with = "serde_bytes")]
        sig: &'a [u8],
    }
    let unsigned = UnsignedCommit {
        did: commit.did().as_str(),
        version: 3,
        data: commit.data(),
        rev: commit.rev(),
        prev: commit.prev(),
        sig: &[],
    };
    serde_ipld_dagcbor::to_vec(&unsigned).unwrap()
}

fn parse_car(
    cursor: &mut std::io::Cursor<&[u8]>,
) -> Result<(Vec<Cid>, HashMap<Cid, Bytes>), Box<dyn std::error::Error>> {
    use std::io::Read;
    fn read_varint<R: Read>(r: &mut R) -> std::io::Result<u64> {
        let mut result = 0u64;
        let mut shift = 0;
        loop {
            let mut byte = [0u8; 1];
            r.read_exact(&mut byte)?;
            result |= ((byte[0] & 0x7f) as u64) << shift;
            if byte[0] & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
        Ok(result)
    }
    let header_len = read_varint(cursor)? as usize;
    let mut header_bytes = vec![0u8; header_len];
    cursor.read_exact(&mut header_bytes)?;
    #[derive(serde::Deserialize)]
    struct CarHeader {
        version: u64,
        roots: Vec<cid::Cid>,
    }
    let header: CarHeader = serde_ipld_dagcbor::from_slice(&header_bytes)?;
    let mut blocks = HashMap::new();
    loop {
        let block_len = match read_varint(cursor) {
            Ok(len) => len as usize,
            Err(_) => break,
        };
        if block_len == 0 {
            break;
        }
        let mut block_data = vec![0u8; block_len];
        if cursor.read_exact(&mut block_data).is_err() {
            break;
        }
        let cid_bytes = &block_data[..];
        let (cid, cid_len) = parse_cid(cid_bytes)?;
        let content = Bytes::copy_from_slice(&block_data[cid_len..]);
        blocks.insert(cid, content);
    }
    Ok((header.roots, blocks))
}
fn parse_cid(bytes: &[u8]) -> Result<(Cid, usize), Box<dyn std::error::Error>> {
    if bytes[0] == 0x01 {
        let codec = bytes[1];
        let hash_type = bytes[2];
        let hash_len = bytes[3] as usize;
        let cid_len = 4 + hash_len;
        let cid = Cid::new_v1(
            codec as u64,
            cid::multihash::Multihash::from_bytes(&bytes[2..cid_len])?,
        );
        Ok((cid, cid_len))
    } else {
        Err("Unsupported CID version".into())
    }
}
