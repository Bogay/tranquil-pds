use bytes::Bytes;
use cid::Cid;
use ipld_core::ipld::Ipld;
use iroh_car::CarReader;
use serde_json::Value as JsonValue;
use sqlx::PgPool;
use std::collections::HashMap;
use std::io::Cursor;
use thiserror::Error;
use tracing::debug;
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
    Database(#[from] sqlx::Error),
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
            if let Some(Ipld::String(type_str)) = obj.get("$type") {
                if type_str == "blob" {
                    if let Some(Ipld::Link(link_cid)) = obj.get("ref") {
                        let mime = obj
                            .get("mimeType")
                            .and_then(|v| if let Ipld::String(s) = v { Some(s.clone()) } else { None });
                        return vec![BlobRef {
                            cid: link_cid.to_string(),
                            mime_type: mime,
                        }];
                    }
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
            if let Some(JsonValue::String(type_str)) = obj.get("$type") {
                if type_str == "blob" {
                    if let Some(JsonValue::Object(ref_obj)) = obj.get("ref") {
                        if let Some(JsonValue::String(link)) = ref_obj.get("$link") {
                            let mime = obj
                                .get("mimeType")
                                .and_then(|v| v.as_str())
                                .map(String::from);
                            return vec![BlobRef {
                                cid: link.clone(),
                                mime_type: mime,
                            }];
                        }
                    }
                }
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
            for v in map.values() {
                extract_links(v, links);
            }
        }
        Ipld::List(arr) => {
            for v in arr {
                extract_links(v, links);
            }
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
    let mut stack = vec![*root_cid];
    let mut visited = std::collections::HashSet::new();
    while let Some(cid) = stack.pop() {
        if visited.contains(&cid) {
            continue;
        }
        visited.insert(cid);
        let block = blocks
            .get(&cid)
            .ok_or_else(|| ImportError::BlockNotFound(cid.to_string()))?;
        let value: Ipld = serde_ipld_dagcbor::from_slice(block)
            .map_err(|e| ImportError::InvalidCbor(e.to_string()))?;
        if let Ipld::Map(ref obj) = value {
            if let Some(Ipld::List(entries)) = obj.get("e") {
                for entry in entries {
                    if let Ipld::Map(entry_obj) = entry {
                        let key = entry_obj.get("k").and_then(|k| {
                            if let Ipld::Bytes(b) = k {
                                String::from_utf8(b.clone()).ok()
                            } else if let Ipld::String(s) = k {
                                Some(s.clone())
                            } else {
                                None
                            }
                        });
                        let record_cid = entry_obj.get("v").and_then(|v| {
                            if let Ipld::Link(cid) = v {
                                Some(*cid)
                            } else {
                                None
                            }
                        });
                        if let (Some(key), Some(record_cid)) = (key, record_cid) {
                            if let Some(record_block) = blocks.get(&record_cid) {
                                if let Ok(record_value) =
                                    serde_ipld_dagcbor::from_slice::<Ipld>(record_block)
                                {
                                    let blob_refs = find_blob_refs_ipld(&record_value, 0);
                                    let parts: Vec<&str> = key.split('/').collect();
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
                            }
                        }
                        if let Some(Ipld::Link(tree_cid)) = entry_obj.get("t") {
                            stack.push(*tree_cid);
                        }
                    }
                }
            }
            if let Some(Ipld::Link(left_cid)) = obj.get("l") {
                stack.push(*left_cid);
            }
        }
    }
    Ok(records)
}

pub struct CommitInfo {
    pub rev: Option<String>,
    pub prev: Option<String>,
}

fn extract_commit_info(commit: &Ipld) -> Result<(Cid, CommitInfo), ImportError> {
    let obj = match commit {
        Ipld::Map(m) => m,
        _ => return Err(ImportError::InvalidCommit("Commit must be a map".to_string())),
    };
    let data_cid = obj
        .get("data")
        .and_then(|d| if let Ipld::Link(cid) = d { Some(*cid) } else { None })
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
    db: &PgPool,
    user_id: Uuid,
    root: Cid,
    blocks: HashMap<Cid, Bytes>,
    max_blocks: usize,
) -> Result<Vec<ImportedRecord>, ImportError> {
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
    let mut tx = db.begin().await?;
    let repo = sqlx::query!(
        "SELECT repo_root_cid FROM repos WHERE user_id = $1 FOR UPDATE NOWAIT",
        user_id
    )
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        if let sqlx::Error::Database(ref db_err) = e {
            if db_err.code().as_deref() == Some("55P03") {
                return ImportError::ConcurrentModification;
            }
        }
        ImportError::Database(e)
    })?;
    if repo.is_none() {
        return Err(ImportError::RepoNotFound);
    }
    let block_chunks: Vec<Vec<(&Cid, &Bytes)>> = blocks
        .iter()
        .collect::<Vec<_>>()
        .chunks(100)
        .map(|c| c.to_vec())
        .collect();
    for chunk in block_chunks {
        for (cid, data) in chunk {
            let cid_bytes = cid.to_bytes();
            sqlx::query!(
                "INSERT INTO blocks (cid, data) VALUES ($1, $2) ON CONFLICT (cid) DO NOTHING",
                &cid_bytes,
                data.as_ref()
            )
            .execute(&mut *tx)
            .await?;
        }
    }
    let root_str = root.to_string();
    sqlx::query!(
        "UPDATE repos SET repo_root_cid = $1, updated_at = NOW() WHERE user_id = $2",
        root_str,
        user_id
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query!("DELETE FROM records WHERE repo_id = $1", user_id)
        .execute(&mut *tx)
        .await?;
    for record in &records {
        let record_cid_str = record.cid.to_string();
        sqlx::query!(
            r#"
            INSERT INTO records (repo_id, collection, rkey, record_cid)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (repo_id, collection, rkey) DO UPDATE SET record_cid = $4
            "#,
            user_id,
            record.collection,
            record.rkey,
            record_cid_str
        )
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    debug!(
        "Successfully imported {} blocks and {} records",
        blocks.len(),
        records.len()
    );
    Ok(records)
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
