use bytes::Bytes;
use cid::Cid;
use ipld_core::ipld::Ipld;
use iroh_car::CarReader;
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use std::io::Cursor;
use std::sync::Arc;
use thiserror::Error;
use tracing::debug;
use tranquil_db::{ImportBlock, ImportRecord, ImportRepoError, RepoRepository};
use tranquil_types::CidLink;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum ImportError {
    #[error("CAR parsing error: {0}")]
    CarParse(String),
    #[error("Expected exactly one root in CAR file")]
    InvalidRootCount,
    #[error("Block not found: {0}")]
    BlockNotFound(String),
    #[error("Invalid CBOR: {0}")]
    InvalidCbor(String),
    #[error("Database error: {0}")]
    Database(String),
    #[error("Block store error: {0}")]
    BlockStore(String),
    #[error("Import size limit exceeded")]
    SizeLimitExceeded,
    #[error("Repo not found")]
    RepoNotFound,
    #[error("Concurrent modification detected")]
    ConcurrentModification,
    #[error("Invalid commit structure: {0}")]
    InvalidCommit(String),
    #[error("Verification failed: {0}")]
    VerificationFailed(#[from] super::verify::VerifyError),
    #[error("DID mismatch: CAR is for {car_did}, but authenticated as {auth_did}")]
    DidMismatch { car_did: String, auth_did: String },
}

impl From<ImportRepoError> for ImportError {
    fn from(e: ImportRepoError) -> Self {
        match e {
            ImportRepoError::RepoNotFound => ImportError::RepoNotFound,
            ImportRepoError::ConcurrentModification => ImportError::ConcurrentModification,
            ImportRepoError::Database(msg) => ImportError::Database(msg),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BlobRef {
    pub cid: String,
    pub mime_type: Option<String>,
}

pub async fn parse_car(data: &[u8]) -> Result<(Cid, HashMap<Cid, Bytes>), ImportError> {
    let cursor = Cursor::new(data);
    let mut reader = CarReader::new(cursor)
        .await
        .map_err(|e| ImportError::CarParse(e.to_string()))?;
    let header = reader.header();
    let roots = header.roots();
    if roots.len() != 1 {
        return Err(ImportError::InvalidRootCount);
    }
    let root = roots[0];
    let mut blocks = HashMap::new();
    while let Ok(Some((cid, block))) = reader.next_block().await {
        blocks.insert(cid, Bytes::from(block));
    }
    if !blocks.contains_key(&root) {
        return Err(ImportError::BlockNotFound(root.to_string()));
    }
    Ok((root, blocks))
}

pub fn find_blob_refs_ipld(value: &Ipld, depth: usize) -> Vec<BlobRef> {
    if depth > 32 {
        return vec![];
    }
    match value {
        Ipld::List(arr) => arr
            .iter()
            .flat_map(|v| find_blob_refs_ipld(v, depth + 1))
            .collect(),
        Ipld::Map(obj) => {
            if let Some(Ipld::String(type_str)) = obj.get("$type")
                && type_str == "blob"
            {
                let cid_str = if let Some(Ipld::Link(link_cid)) = obj.get("ref") {
                    Some(link_cid.to_string())
                } else if let Some(Ipld::Map(ref_obj)) = obj.get("ref")
                    && let Some(Ipld::String(link)) = ref_obj.get("$link")
                {
                    Some(link.clone())
                } else {
                    None
                };

                if let Some(cid) = cid_str {
                    let mime = obj.get("mimeType").and_then(|v| {
                        if let Ipld::String(s) = v {
                            Some(s.clone())
                        } else {
                            None
                        }
                    });
                    return vec![BlobRef {
                        cid,
                        mime_type: mime,
                    }];
                }
            }
            obj.values()
                .flat_map(|v| find_blob_refs_ipld(v, depth + 1))
                .collect()
        }
        _ => vec![],
    }
}

pub fn find_blob_refs(value: &JsonValue, depth: usize) -> Vec<BlobRef> {
    if depth > 32 {
        return vec![];
    }
    match value {
        JsonValue::Array(arr) => arr
            .iter()
            .flat_map(|v| find_blob_refs(v, depth + 1))
            .collect(),
        JsonValue::Object(obj) => {
            if let Some(JsonValue::String(type_str)) = obj.get("$type")
                && type_str == "blob"
                && let Some(JsonValue::Object(ref_obj)) = obj.get("ref")
                && let Some(JsonValue::String(link)) = ref_obj.get("$link")
            {
                let mime = obj
                    .get("mimeType")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                return vec![BlobRef {
                    cid: link.clone(),
                    mime_type: mime,
                }];
            }
            obj.values()
                .flat_map(|v| find_blob_refs(v, depth + 1))
                .collect()
        }
        _ => vec![],
    }
}

pub fn extract_links(value: &Ipld, links: &mut Vec<Cid>) {
    match value {
        Ipld::Link(cid) => {
            links.push(*cid);
        }
        Ipld::Map(map) => {
            map.values().for_each(|v| extract_links(v, links));
        }
        Ipld::List(arr) => {
            arr.iter().for_each(|v| extract_links(v, links));
        }
        _ => {}
    }
}

#[derive(Debug)]
pub struct ImportedRecord {
    pub collection: String,
    pub rkey: String,
    pub cid: Cid,
    pub blob_refs: Vec<BlobRef>,
}

pub fn walk_mst(
    blocks: &HashMap<Cid, Bytes>,
    root_cid: &Cid,
) -> Result<Vec<ImportedRecord>, ImportError> {
    let mut records = Vec::new();
    walk_mst_node(blocks, root_cid, &[], &mut records)?;
    Ok(records)
}

fn walk_mst_node(
    blocks: &HashMap<Cid, Bytes>,
    cid: &Cid,
    prev_key: &[u8],
    records: &mut Vec<ImportedRecord>,
) -> Result<(), ImportError> {
    use super::mst::{entries, left_child, parse_mst_entry, reconstruct_key};

    let block = blocks
        .get(cid)
        .ok_or_else(|| ImportError::BlockNotFound(cid.to_string()))?;
    let node: Ipld = serde_ipld_dagcbor::from_slice(block)
        .map_err(|e| ImportError::InvalidCbor(e.to_string()))?;

    if let Some(left_cid) = left_child(&node) {
        walk_mst_node(blocks, &left_cid, prev_key, records)?;
    }

    let mut current_key = prev_key.to_vec();

    if let Some(entry_list) = entries(&node) {
        entry_list
            .iter()
            .filter_map(parse_mst_entry)
            .try_for_each(|entry| {
                if let Some(ref suffix) = entry.key_suffix {
                    reconstruct_key(&mut current_key, entry.prefix_len, suffix);
                }

                if let Some(tree_cid) = entry.subtree {
                    walk_mst_node(blocks, &tree_cid, &current_key, records)?;
                }

                if let Some(record_cid) = entry.value
                    && let Ok(full_key) = String::from_utf8(current_key.clone())
                    && let Some(record_block) = blocks.get(&record_cid)
                    && let Ok(record_value) = serde_ipld_dagcbor::from_slice::<Ipld>(record_block)
                {
                    let blob_refs = find_blob_refs_ipld(&record_value, 0);
                    let parts: Vec<&str> = full_key.split('/').collect();
                    if parts.len() >= 2 {
                        let collection = parts[..parts.len() - 1].join("/");
                        let rkey = parts[parts.len() - 1].to_string();
                        records.push(ImportedRecord {
                            collection,
                            rkey,
                            cid: record_cid,
                            blob_refs,
                        });
                    }
                }

                Ok::<_, ImportError>(())
            })?;
    }
    Ok(())
}

pub struct CommitInfo {
    pub rev: Option<String>,
    pub prev: Option<String>,
}

pub struct ImportResult {
    pub records: Vec<ImportedRecord>,
    pub data_cid: Cid,
}

fn extract_commit_info(commit: &Ipld) -> Result<(Cid, CommitInfo), ImportError> {
    let obj = match commit {
        Ipld::Map(m) => m,
        _ => {
            return Err(ImportError::InvalidCommit(
                "Commit must be a map".to_string(),
            ));
        }
    };
    let data_cid = obj
        .get("data")
        .and_then(|d| {
            if let Ipld::Link(cid) = d {
                Some(*cid)
            } else {
                None
            }
        })
        .ok_or_else(|| ImportError::InvalidCommit("Missing data field".to_string()))?;
    let rev = obj.get("rev").and_then(|r| {
        if let Ipld::String(s) = r {
            Some(s.clone())
        } else {
            None
        }
    });
    let prev = obj.get("prev").and_then(|p| {
        if let Ipld::Link(cid) = p {
            Some(cid.to_string())
        } else if let Ipld::Null = p {
            None
        } else {
            None
        }
    });
    Ok((data_cid, CommitInfo { rev, prev }))
}

pub async fn apply_import(
    repo_repo: &Arc<dyn RepoRepository>,
    user_id: Uuid,
    root: Cid,
    blocks: HashMap<Cid, Bytes>,
    max_blocks: usize,
    expected_root_cid: Option<&CidLink>,
) -> Result<ImportResult, ImportError> {
    if blocks.len() > max_blocks {
        return Err(ImportError::SizeLimitExceeded);
    }
    let root_block = blocks
        .get(&root)
        .ok_or_else(|| ImportError::BlockNotFound(root.to_string()))?;
    let commit: Ipld = serde_ipld_dagcbor::from_slice(root_block)
        .map_err(|e| ImportError::InvalidCbor(e.to_string()))?;
    let (data_cid, _commit_info) = extract_commit_info(&commit)?;
    let records = walk_mst(&blocks, &data_cid)?;
    debug!(
        "Importing {} blocks and {} records for user {}",
        blocks.len(),
        records.len(),
        user_id
    );

    let import_blocks: Vec<ImportBlock> = blocks
        .iter()
        .map(|(cid, data)| ImportBlock {
            cid_bytes: cid.to_bytes(),
            data: data.to_vec(),
        })
        .collect();

    let import_records: Vec<ImportRecord> = records
        .iter()
        .filter_map(|r| {
            let collection = r.collection.parse().ok()?;
            let rkey = r.rkey.parse().ok()?;
            let record_cid = r.cid.to_string().parse().ok()?;
            Some(ImportRecord {
                collection,
                rkey,
                record_cid,
            })
        })
        .collect();

    repo_repo
        .import_repo_data(user_id, &import_blocks, &import_records, expected_root_cid)
        .await?;

    debug!(
        "Successfully imported {} blocks and {} records",
        blocks.len(),
        records.len()
    );
    Ok(ImportResult { records, data_cid })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_blob_refs() {
        let record = serde_json::json!({
            "$type": "app.bsky.feed.post",
            "text": "Hello world",
            "embed": {
                "$type": "app.bsky.embed.images",
                "images": [
                    {
                        "alt": "Test image",
                        "image": {
                            "$type": "blob",
                            "ref": {
                                "$link": "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"
                            },
                            "mimeType": "image/jpeg",
                            "size": 12345
                        }
                    }
                ]
            }
        });
        let blob_refs = find_blob_refs(&record, 0);
        assert_eq!(blob_refs.len(), 1);
        assert_eq!(
            blob_refs[0].cid,
            "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"
        );
        assert_eq!(blob_refs[0].mime_type, Some("image/jpeg".to_string()));
    }

    #[test]
    fn test_find_blob_refs_no_blobs() {
        let record = serde_json::json!({
            "$type": "app.bsky.feed.post",
            "text": "Hello world"
        });
        let blob_refs = find_blob_refs(&record, 0);
        assert!(blob_refs.is_empty());
    }

    #[test]
    fn test_find_blob_refs_depth_limit() {
        fn deeply_nested(depth: usize) -> JsonValue {
            if depth == 0 {
                serde_json::json!({
                    "$type": "blob",
                    "ref": { "$link": "bafkreitest" },
                    "mimeType": "image/png"
                })
            } else {
                serde_json::json!({ "nested": deeply_nested(depth - 1) })
            }
        }
        let deep = deeply_nested(40);
        let blob_refs = find_blob_refs(&deep, 0);
        assert!(blob_refs.is_empty());
    }
}
