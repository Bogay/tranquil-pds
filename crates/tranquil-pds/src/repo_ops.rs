use crate::api::error::ApiError;
use crate::cid_types::{CommitCid, RecordCid};
use crate::repo::TrackingBlockStore;
use crate::state::AppState;
use crate::types::{Did, Handle, Nsid, Rkey};
use backon::{ExponentialBuilder, Retryable};
use bytes::Bytes;
use cid::Cid;
use jacquard_common::smol_str::SmolStr;
use jacquard_common::types::{integer::LimitedU32, string::Tid};
use jacquard_repo::commit::Commit;
use jacquard_repo::mst::util::compute_cid;
use jacquard_repo::mst::{Mst, VerifiedWriteOp};
use jacquard_repo::storage::BlockStore;
use k256::ecdsa::SigningKey;
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::OwnedMutexGuard;
use tracing::{error, warn};
use tranquil_db_traits::SequenceNumber;
use uuid::Uuid;

#[derive(Debug)]
pub enum CommitError {
    InvalidDid(String),
    InvalidTid(String),
    SigningFailed(String),
    SerializationFailed(String),
    KeyNotFound,
    KeyDecryptionFailed(String),
    InvalidKey(String),
    BlockStoreFailed(String),
    RepoNotFound,
    ConcurrentModification,
    DatabaseError(String),
    UserNotFound,
    CommitParseFailed(String),
    MstOperationFailed(String),
    RecordSerializationFailed(String),
    InvalidCid(String),
    RecordAlreadyExists(String),
}

impl std::fmt::Display for CommitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidDid(e) => write!(f, "Invalid DID: {}", e),
            Self::InvalidTid(e) => write!(f, "Invalid TID: {}", e),
            Self::SigningFailed(e) => write!(f, "Failed to sign commit: {}", e),
            Self::SerializationFailed(e) => write!(f, "Failed to serialize signed commit: {}", e),
            Self::KeyNotFound => write!(f, "Signing key not found"),
            Self::KeyDecryptionFailed(e) => write!(f, "Failed to decrypt signing key: {}", e),
            Self::InvalidKey(e) => write!(f, "Invalid signing key: {}", e),
            Self::BlockStoreFailed(e) => write!(f, "Block store operation failed: {}", e),
            Self::RepoNotFound => write!(f, "Repo not found"),
            Self::ConcurrentModification => {
                write!(f, "Repo has been modified since last read")
            }
            Self::DatabaseError(e) => write!(f, "Database error: {}", e),
            Self::UserNotFound => write!(f, "User not found"),
            Self::CommitParseFailed(e) => write!(f, "Failed to parse commit: {}", e),
            Self::MstOperationFailed(e) => write!(f, "MST operation failed: {}", e),
            Self::RecordSerializationFailed(e) => {
                write!(f, "Failed to serialize record: {}", e)
            }
            Self::InvalidCid(e) => write!(f, "Invalid CID: {}", e),
            Self::RecordAlreadyExists(key) => write!(f, "Record already exists at {}", key),
        }
    }
}

impl std::error::Error for CommitError {}

impl From<CommitError> for ApiError {
    fn from(err: CommitError) -> Self {
        match err {
            CommitError::ConcurrentModification => {
                ApiError::InvalidSwap(Some("Repo has been modified".into()))
            }
            CommitError::RepoNotFound => ApiError::RepoNotFound(None),
            CommitError::UserNotFound => ApiError::RepoNotFound(Some("User not found".into())),
            CommitError::RecordAlreadyExists(key) => {
                ApiError::InvalidRequest(format!("Record already exists at {key}"))
            }
            other => {
                error!("Commit failed: {}", other);
                ApiError::InternalError(Some("Failed to commit changes".into()))
            }
        }
    }
}

pub async fn get_current_root_cid(state: &AppState, user_id: Uuid) -> Result<CommitCid, ApiError> {
    let root_cid_str = state
        .repos
        .repo
        .get_repo_root_cid_by_user_id(user_id)
        .await
        .map_err(|e| {
            error!("DB error fetching repo root: {}", e);
            ApiError::InternalError(None)
        })?
        .ok_or_else(|| ApiError::InternalError(Some("Repo root not found".into())))?;
    CommitCid::from_str(&root_cid_str)
        .map_err(|_| ApiError::InternalError(Some("Invalid repo root CID".into())))
}

pub fn extract_blob_cids(record: &Value) -> Vec<String> {
    crate::sync::import::find_blob_refs(record, 0)
        .into_iter()
        .map(|b| b.cid)
        .collect()
}

use crate::types::AtUri;
use tranquil_db_traits::{Backlink, BacklinkPath};

pub fn extract_backlinks(uri: &AtUri, record: &Value) -> Vec<Backlink> {
    let record_type = record
        .get("$type")
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    match record_type {
        "app.bsky.graph.follow" | "app.bsky.graph.block" => record
            .get("subject")
            .and_then(|v| v.as_str())
            .filter(|s| s.starts_with("did:"))
            .map(|subject| {
                vec![Backlink {
                    uri: uri.clone(),
                    path: BacklinkPath::Subject,
                    link_to: subject.to_string(),
                }]
            })
            .unwrap_or_default(),
        "app.bsky.feed.like" | "app.bsky.feed.repost" => record
            .get("subject")
            .and_then(|v| v.get("uri"))
            .and_then(|v| v.as_str())
            .filter(|s| s.starts_with("at://"))
            .map(|subject_uri| {
                vec![Backlink {
                    uri: uri.clone(),
                    path: BacklinkPath::SubjectUri,
                    link_to: subject_uri.to_string(),
                }]
            })
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

pub struct RepoWriteContext {
    pub tracking_store: TrackingBlockStore,
    pub current_root_cid: Cid,
    pub prev_commit_bytes: Bytes,
    pub prev_data_cid: Cid,
    pub write_lock: OwnedMutexGuard<()>,
}

pub struct FinalizeParams<'a> {
    pub did: &'a Did,
    pub user_id: Uuid,
    pub controller_did: Option<&'a Did>,
    pub delegation_detail: Option<serde_json::Value>,
    pub ops: Vec<RecordOp>,
    pub blob_cids: &'a [String],
    pub backlinks_to_add: Vec<Backlink>,
    pub backlinks_to_remove: Vec<AtUri>,
}

pub async fn begin_repo_write(
    state: &AppState,
    user_id: Uuid,
    swap_commit: Option<&str>,
) -> Result<(RepoWriteContext, Mst<TrackingBlockStore>), ApiError> {
    let write_lock = state.repo_write_locks.lock(user_id).await;

    let root_cid_str = state
        .repos
        .repo
        .get_repo_root_cid_by_user_id(user_id)
        .await
        .map_err(|e| {
            error!("DB error fetching repo root: {}", e);
            ApiError::InternalError(None)
        })?
        .ok_or_else(|| ApiError::InternalError(Some("Repo root not found".into())))?;

    let current_root_cid = Cid::from_str(root_cid_str.as_str())
        .map_err(|_| ApiError::InternalError(Some("Invalid repo root CID".into())))?;

    if let Some(expected) = swap_commit {
        let expected_cid = Cid::from_str(expected)
            .map_err(|_| ApiError::InvalidSwap(Some("Invalid swap commit CID".into())))?;
        if expected_cid != current_root_cid {
            return Err(ApiError::InvalidSwap(Some("Repo has been modified".into())));
        }
    }

    let tracking_store = TrackingBlockStore::new(state.block_store.clone());
    let commit_bytes = tracking_store
        .get(&current_root_cid)
        .await
        .map_err(|e| {
            error!("Failed to load commit block: {}", e);
            ApiError::InternalError(None)
        })?
        .ok_or_else(|| ApiError::InternalError(Some("Commit block not found".into())))?;

    let prev_data_cid = Commit::from_cbor(&commit_bytes)
        .map_err(|e| {
            error!("Failed to parse commit: {}", e);
            ApiError::InternalError(None)
        })?
        .data;

    let mst = Mst::load(Arc::new(tracking_store.clone()), prev_data_cid, None);

    let ctx = RepoWriteContext {
        tracking_store,
        current_root_cid,
        prev_commit_bytes: commit_bytes,
        prev_data_cid,
        write_lock,
    };

    Ok((ctx, mst))
}

pub async fn finalize_repo_write(
    state: &AppState,
    ctx: RepoWriteContext,
    mst: Mst<TrackingBlockStore>,
    params: FinalizeParams<'_>,
) -> Result<CommitResult, ApiError> {
    let new_mst_root = mst.persist().await.map_err(|e| {
        error!("MST persist failed: {}", e);
        ApiError::InternalError(None)
    })?;

    let written_bytes = ctx.tracking_store.take_written_blocks();
    let new_tree_cids: Vec<Cid> = written_bytes.keys().copied().collect();

    let storage_for_proof = Arc::new(ctx.tracking_store.clone());
    let original_settled = Mst::load(storage_for_proof.clone(), ctx.prev_data_cid, None);
    let new_settled = Mst::load(storage_for_proof.clone(), new_mst_root, None);

    let mut inverse_trace = new_settled.clone();
    let mut non_invertible: Vec<String> = Vec::new();
    let mut invert_errors: Vec<String> = Vec::new();
    for op in params.ops.iter().rev() {
        let (collection, rkey) = op.collection_rkey();
        let key = SmolStr::new(format!("{}/{}", collection, rkey));
        let verified = match op {
            RecordOp::Create { cid, .. } => VerifiedWriteOp::Create {
                key,
                cid: *cid.as_cid(),
            },
            RecordOp::Update { cid, prev, .. } => VerifiedWriteOp::Update {
                key,
                cid: *cid.as_cid(),
                prev: *prev.as_cid(),
            },
            RecordOp::Delete { prev, .. } => VerifiedWriteOp::Delete {
                key,
                prev: *prev.as_cid(),
            },
        };
        match inverse_trace.invert_op(verified.clone()).await {
            Ok(true) => {}
            Ok(false) => non_invertible.push(format!("{:?}", verified)),
            Err(e) => invert_errors.push(format!("{:?} -> {:?}", verified, e)),
        }
    }
    if !non_invertible.is_empty() {
        warn!(
            user_id = %params.user_id,
            count = non_invertible.len(),
            ops = ?non_invertible,
            "firehose proof walk: ops not invertible on new MST, consumer will reject frame"
        );
    }
    if !invert_errors.is_empty() {
        warn!(
            user_id = %params.user_id,
            count = invert_errors.len(),
            failures = ?invert_errors,
            "firehose proof walk: invert_op errored, cover blocks may be incomplete"
        );
    }

    let read_cid_set: HashSet<Cid> = ctx.tracking_store.get_read_cids().into_iter().collect();
    let missing_read_cids: Vec<Cid> = read_cid_set
        .iter()
        .copied()
        .filter(|cid| !written_bytes.contains_key(cid))
        .collect();
    let mut relevant: BTreeMap<Cid, Bytes> = BTreeMap::new();
    if !missing_read_cids.is_empty() {
        let fetched = ctx
            .tracking_store
            .get_many(&missing_read_cids)
            .await
            .map_err(|e| {
                error!("fetch cover read bytes: {e}");
                ApiError::InternalError(None)
            })?;
        for (cid, maybe) in missing_read_cids.into_iter().zip(fetched) {
            if let Some(bytes) = maybe {
                relevant.insert(cid, bytes);
            }
        }
    }

    let obsolete_cids = match original_settled.diff(&new_settled).await {
        Ok(diff) => {
            let mut obsolete: Vec<Cid> =
                Vec::with_capacity(1 + diff.removed_mst_blocks.len() + diff.removed_cids.len());
            obsolete.push(ctx.current_root_cid);
            obsolete.extend(diff.removed_mst_blocks);
            obsolete.extend(diff.removed_cids);
            obsolete
        }
        Err(e) => {
            error!(
                "MST diff failed during finalize_repo_write: {e}. \
                 Proceeding with commit CID only; leaked blocks \
                 will be reclaimed by reachability GC."
            );
            vec![ctx.current_root_cid]
        }
    };

    let mut block_bytes = written_bytes;
    block_bytes.extend(relevant);

    let result = commit_and_log(
        state,
        CommitParams {
            did: params.did,
            user_id: params.user_id,
            current_root_cid: Some(ctx.current_root_cid),
            prev_commit_bytes: Some(ctx.prev_commit_bytes),
            prev_data_cid: Some(ctx.prev_data_cid),
            new_mst_root,
            ops: params.ops,
            block_bytes,
            new_tree_cids,
            blobs: params.blob_cids,
            obsolete_cids,
            backlinks_to_add: params.backlinks_to_add,
            backlinks_to_remove: params.backlinks_to_remove,
        },
    )
    .await?;

    if let Some(controller_did) = params.controller_did
        && let Some(detail) = params.delegation_detail
        && let Err(e) = state
            .repos
            .delegation
            .log_delegation_action(
                params.did,
                controller_did,
                Some(controller_did),
                tranquil_db_traits::DelegationActionType::RepoWrite,
                Some(detail),
                None,
                None,
            )
            .await
    {
        tracing::warn!("Failed to log delegation audit: {:?}", e);
    }

    Ok(result)
}

pub fn create_signed_commit(
    did: &Did,
    data: Cid,
    rev: &str,
    prev: Option<Cid>,
    signing_key: &SigningKey,
) -> Result<(Vec<u8>, Bytes), CommitError> {
    let did = jacquard_common::types::string::Did::new(did.as_str())
        .map_err(|e| CommitError::InvalidDid(format!("{:?}", e)))?;
    let rev = jacquard_common::types::string::Tid::from_str(rev)
        .map_err(|e| CommitError::InvalidTid(format!("{:?}", e)))?;
    let unsigned = Commit::new_unsigned(did, data, rev, prev);
    let signed = unsigned
        .sign(signing_key)
        .map_err(|e| CommitError::SigningFailed(format!("{:?}", e)))?;
    let sig_bytes = signed.sig().clone();
    let signed_bytes = signed
        .to_cbor()
        .map_err(|e| CommitError::SerializationFailed(e.to_string()))?;
    Ok((signed_bytes, sig_bytes))
}

pub enum RecordOp {
    Create {
        collection: Nsid,
        rkey: Rkey,
        cid: RecordCid,
    },
    Update {
        collection: Nsid,
        rkey: Rkey,
        cid: RecordCid,
        prev: RecordCid,
    },
    Delete {
        collection: Nsid,
        rkey: Rkey,
        prev: RecordCid,
    },
}

impl RecordOp {
    pub fn collection_rkey(&self) -> (&Nsid, &Rkey) {
        match self {
            Self::Create {
                collection, rkey, ..
            }
            | Self::Update {
                collection, rkey, ..
            }
            | Self::Delete {
                collection, rkey, ..
            } => (collection, rkey),
        }
    }
}

pub struct CommitResult {
    pub commit_cid: Cid,
    pub rev: String,
}

pub struct CommitParams<'a> {
    pub did: &'a Did,
    pub user_id: Uuid,
    pub current_root_cid: Option<Cid>,
    pub prev_commit_bytes: Option<Bytes>,
    pub prev_data_cid: Option<Cid>,
    pub new_mst_root: Cid,
    pub ops: Vec<RecordOp>,
    pub block_bytes: std::collections::HashMap<Cid, Bytes>,
    pub new_tree_cids: Vec<Cid>,
    pub blobs: &'a [String],
    pub obsolete_cids: Vec<Cid>,
    pub backlinks_to_add: Vec<Backlink>,
    pub backlinks_to_remove: Vec<AtUri>,
}

pub async fn commit_and_log(
    state: &AppState,
    params: CommitParams<'_>,
) -> Result<CommitResult, CommitError> {
    use tranquil_db_traits::{
        ApplyCommitError, ApplyCommitInput, CommitEventData, EventBlockInline, RecordDelete,
        RecordUpsert, RepoEventType,
    };

    let CommitParams {
        did,
        user_id,
        current_root_cid,
        prev_commit_bytes,
        prev_data_cid,
        new_mst_root,
        ops,
        mut block_bytes,
        new_tree_cids,
        blobs,
        obsolete_cids,
        backlinks_to_add,
        backlinks_to_remove,
    } = params;
    debug_assert_eq!(
        current_root_cid.is_some(),
        prev_commit_bytes.is_some(),
        "current_root_cid and prev_commit_bytes must be both Some (non-genesis) or both None (genesis)"
    );
    let key_row = state
        .repos
        .user
        .get_user_key_by_id(user_id)
        .await
        .map_err(|e| CommitError::DatabaseError(format!("Failed to fetch signing key: {}", e)))?
        .ok_or(CommitError::KeyNotFound)?;
    let key_bytes = crate::config::decrypt_key(&key_row.key_bytes, key_row.encryption_version)
        .map_err(|e| CommitError::KeyDecryptionFailed(e.to_string()))?;
    let signing_key =
        SigningKey::from_slice(&key_bytes).map_err(|e| CommitError::InvalidKey(e.to_string()))?;
    let rev = Tid::now(LimitedU32::MIN);
    let rev_str = rev.to_string();
    let (new_commit_bytes, _sig) =
        create_signed_commit(did, new_mst_root, &rev_str, current_root_cid, &signing_key)?;
    let new_root_cid =
        compute_cid(&new_commit_bytes).map_err(|e| CommitError::BlockStoreFailed(e.to_string()))?;

    let commit_bytes_owned = Bytes::from(new_commit_bytes.clone());
    state
        .block_store
        .put(&new_commit_bytes)
        .await
        .map_err(|e| CommitError::BlockStoreFailed(format!("failed to write commit block: {e}")))?;

    block_bytes.insert(new_root_cid, commit_bytes_owned);

    if let (Some(prev_root), Some(prev_bytes)) = (current_root_cid, prev_commit_bytes) {
        block_bytes.entry(prev_root).or_insert(prev_bytes);
    }

    let all_block_cids: Vec<Vec<u8>> = new_tree_cids
        .iter()
        .chain(std::iter::once(&new_root_cid))
        .map(|c| c.to_bytes())
        .collect();

    let obsolete_bytes: Vec<Vec<u8>> = obsolete_cids.iter().map(|c| c.to_bytes()).collect();

    let final_ops: HashMap<(&Nsid, &Rkey), &RecordOp> = ops
        .iter()
        .map(|op| (op.collection_rkey(), op))
        .collect();

    let final_record_uris: HashSet<AtUri> = final_ops
        .iter()
        .filter(|(_, op)| !matches!(op, RecordOp::Delete { .. }))
        .map(|((c, r), _)| AtUri::from_parts(did, c, r))
        .collect();

    let record_upserts: Vec<RecordUpsert> = final_ops
        .values()
        .filter_map(|op| match op {
            RecordOp::Create {
                collection,
                rkey,
                cid,
            }
            | RecordOp::Update {
                collection,
                rkey,
                cid,
                ..
            } => Some(RecordUpsert {
                collection: collection.clone(),
                rkey: rkey.clone(),
                cid: crate::types::CidLink::from(cid.as_cid()),
            }),
            RecordOp::Delete { .. } => None,
        })
        .collect();

    let record_deletes: Vec<RecordDelete> = final_ops
        .values()
        .filter_map(|op| match op {
            RecordOp::Delete {
                collection, rkey, ..
            } => Some(RecordDelete {
                collection: collection.clone(),
                rkey: rkey.clone(),
            }),
            _ => None,
        })
        .collect();

    let backlinks_to_add: Vec<Backlink> = backlinks_to_add
        .into_iter()
        .filter(|b| final_record_uris.contains(&b.uri))
        .map(|b| ((b.uri.clone(), b.path), b))
        .collect::<HashMap<_, _>>()
        .into_values()
        .collect();

    let backlinks_to_remove: Vec<AtUri> = backlinks_to_remove
        .into_iter()
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();

    let ops_json: Vec<serde_json::Value> = ops
        .iter()
        .map(|op| match op {
            RecordOp::Create {
                collection,
                rkey,
                cid,
            } => json!({
                "action": "create",
                "path": format!("{}/{}", collection, rkey),
                "cid": cid.to_string()
            }),
            RecordOp::Update {
                collection,
                rkey,
                cid,
                prev,
            } => json!({
                "action": "update",
                "path": format!("{}/{}", collection, rkey),
                "cid": cid.to_string(),
                "prev": prev.to_string(),
            }),
            RecordOp::Delete {
                collection,
                rkey,
                prev,
            } => json!({
                "action": "delete",
                "path": format!("{}/{}", collection, rkey),
                "cid": null,
                "prev": prev.to_string(),
            }),
        })
        .collect();

    let inline_blocks: Vec<EventBlockInline> = block_bytes
        .iter()
        .map(|(cid, data)| EventBlockInline {
            cid_bytes: cid.to_bytes(),
            data: data.to_vec(),
        })
        .collect();

    let commit_event = CommitEventData {
        did: did.clone(),
        event_type: RepoEventType::Commit,
        commit_cid: Some(crate::types::CidLink::from(new_root_cid)),
        prev_cid: current_root_cid.map(crate::types::CidLink::from),
        ops: Some(json!(ops_json)),
        blobs: Some(blobs.to_vec()),
        blocks: Some(inline_blocks),
        prev_data_cid: prev_data_cid.map(crate::types::CidLink::from),
        rev: Some(rev_str.clone()),
    };

    let input = ApplyCommitInput {
        user_id,
        did: did.clone(),
        expected_root_cid: current_root_cid.map(crate::types::CidLink::from),
        new_root_cid: crate::types::CidLink::from(new_root_cid),
        new_rev: rev_str.clone(),
        new_block_cids: all_block_cids,
        obsolete_block_cids: obsolete_bytes,
        record_upserts,
        record_deletes,
        backlinks_to_add,
        backlinks_to_remove,
        commit_event,
    };

    let _result = state
        .repos
        .repo
        .apply_commit(input)
        .await
        .map_err(|e| match e {
            ApplyCommitError::RepoNotFound => CommitError::RepoNotFound,
            ApplyCommitError::ConcurrentModification => CommitError::ConcurrentModification,
            ApplyCommitError::Database(msg) => CommitError::DatabaseError(msg),
        })?;

    let apply_result = (|| {
        let bs = state.block_store.clone();
        let decrements = obsolete_cids.clone();
        async move { bs.decrement_refs(&decrements).await }
    })
    .retry(
        ExponentialBuilder::default()
            .with_min_delay(std::time::Duration::from_millis(50))
            .with_max_delay(std::time::Duration::from_secs(2))
            .with_max_times(5),
    )
    .await;

    if let Err(e) = apply_result {
        let leaked: Vec<String> = obsolete_cids.iter().map(Cid::to_string).collect();
        tracing::error!(
            error = %e,
            user_id = %user_id,
            new_root = %new_root_cid,
            leaked_cids = ?leaked,
            "blockstore decrement_refs failed after metastore commit succeeded \
             and exhausted retries; blocks may leak refcounts"
        );
    }

    Ok(CommitResult {
        commit_cid: new_root_cid,
        rev: rev_str,
    })
}
pub async fn create_record_internal(
    state: &AppState,
    did: &Did,
    collection: &Nsid,
    rkey: &Rkey,
    record: &serde_json::Value,
) -> Result<(String, Cid), CommitError> {
    let user_id: Uuid = state
        .repos
        .user
        .get_id_by_did(did)
        .await
        .map_err(|e| CommitError::DatabaseError(e.to_string()))?
        .ok_or(CommitError::UserNotFound)?;

    let to_commit_err = |e: ApiError| CommitError::DatabaseError(format!("{:?}", e));

    let (ctx, mst) = begin_repo_write(state, user_id, None)
        .await
        .map_err(to_commit_err)?;

    let key = format!("{}/{}", collection, rkey);
    if mst
        .get(&key)
        .await
        .map_err(|e| CommitError::MstOperationFailed(e.to_string()))?
        .is_some()
    {
        return Err(CommitError::RecordAlreadyExists(key));
    }

    let record_ipld = crate::util::json_to_ipld(record);
    let mut record_bytes = Vec::new();
    serde_ipld_dagcbor::to_writer(&mut record_bytes, &record_ipld)
        .map_err(|e| CommitError::RecordSerializationFailed(e.to_string()))?;
    let record_cid = ctx
        .tracking_store
        .put(&record_bytes)
        .await
        .map_err(|e| CommitError::BlockStoreFailed(e.to_string()))?;
    let new_mst = mst
        .add(&key, record_cid)
        .await
        .map_err(|e| CommitError::MstOperationFailed(e.to_string()))?;

    let op = RecordOp::Create {
        collection: collection.clone(),
        rkey: rkey.clone(),
        cid: RecordCid::from(record_cid),
    };
    let blob_cids = extract_blob_cids(record);
    let record_uri = AtUri::from_parts(did.as_str(), collection.as_str(), rkey.as_str());
    let backlinks = extract_backlinks(&record_uri, record);

    let result = finalize_repo_write(
        state,
        ctx,
        new_mst,
        FinalizeParams {
            did,
            user_id,
            controller_did: None,
            delegation_detail: None,
            ops: vec![op],
            blob_cids: &blob_cids,
            backlinks_to_add: backlinks,
            backlinks_to_remove: vec![],
        },
    )
    .await
    .map_err(to_commit_err)?;

    let uri = format!("at://{}/{}/{}", did, collection, rkey);
    Ok((uri, result.commit_cid))
}

pub async fn sequence_identity_event(
    state: &AppState,
    did: &Did,
    handle: Option<&Handle>,
) -> Result<SequenceNumber, CommitError> {
    state
        .repos
        .repo
        .insert_identity_event(did, handle)
        .await
        .map_err(|e| CommitError::DatabaseError(format!("identity event: {}", e)))
}
pub async fn sequence_account_event(
    state: &AppState,
    did: &Did,
    status: tranquil_db_traits::AccountStatus,
) -> Result<SequenceNumber, CommitError> {
    state
        .repos
        .repo
        .insert_account_event(did, status)
        .await
        .map_err(|e| CommitError::DatabaseError(format!("account event: {}", e)))
}
pub async fn sequence_sync_event(
    state: &AppState,
    did: &Did,
    commit_cid: &str,
    rev: Option<&str>,
) -> Result<SequenceNumber, CommitError> {
    let cid_link: crate::types::CidLink = commit_cid
        .parse()
        .map_err(|_| CommitError::InvalidCid(commit_cid.to_string()))?;
    let commit_cid_parsed =
        Cid::from_str(commit_cid).map_err(|e| CommitError::InvalidCid(e.to_string()))?;
    let commit_bytes = state
        .block_store
        .get(&commit_cid_parsed)
        .await
        .map_err(|e| CommitError::BlockStoreFailed(format!("{:?}", e)))?
        .ok_or(CommitError::BlockStoreFailed(
            "Commit block not found for sync event".into(),
        ))?;
    state
        .repos
        .repo
        .insert_sync_event(did, &cid_link, rev, &commit_bytes)
        .await
        .map_err(|e| CommitError::DatabaseError(format!("sync event: {}", e)))
}

pub async fn sequence_genesis_commit(
    state: &AppState,
    did: &Did,
    commit_cid: &Cid,
    mst_root_cid: &Cid,
    rev: &str,
) -> Result<SequenceNumber, CommitError> {
    let commit_cid_link = crate::types::CidLink::from(commit_cid);
    let mst_root_cid_link = crate::types::CidLink::from(mst_root_cid);
    let commit_bytes = state
        .block_store
        .get(commit_cid)
        .await
        .map_err(|e| CommitError::BlockStoreFailed(format!("{:?}", e)))?
        .ok_or(CommitError::BlockStoreFailed(
            "Genesis commit block not found".into(),
        ))?;
    let mst_root_bytes = state
        .block_store
        .get(mst_root_cid)
        .await
        .map_err(|e| CommitError::BlockStoreFailed(format!("{:?}", e)))?
        .ok_or(CommitError::BlockStoreFailed(
            "Genesis MST root block not found".into(),
        ))?;
    state
        .repos
        .repo
        .insert_genesis_commit_event(
            did,
            &commit_cid_link,
            &mst_root_cid_link,
            rev,
            &commit_bytes,
            &mst_root_bytes,
        )
        .await
        .map_err(|e| CommitError::DatabaseError(format!("genesis commit event: {}", e)))
}
