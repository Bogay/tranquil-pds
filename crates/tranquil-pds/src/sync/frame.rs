use crate::sync::firehose::SequencedEvent;
use cid::Cid;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Serialize, Deserialize)]
pub struct FrameHeader {
    pub op: i64,
    pub t: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CommitFrame {
    pub seq: i64,
    pub rebase: bool,
    #[serde(rename = "tooBig")]
    pub too_big: bool,
    pub repo: String,
    pub commit: Cid,
    pub rev: String,
    pub since: Option<String>,
    #[serde(with = "serde_bytes")]
    pub blocks: Vec<u8>,
    pub ops: Vec<RepoOp>,
    pub blobs: Vec<Cid>,
    pub time: String,
    #[serde(rename = "prevData", skip_serializing_if = "Option::is_none")]
    pub prev_data: Option<Cid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JsonRepoOp {
    action: String,
    path: String,
    cid: Option<String>,
    prev: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RepoOp {
    pub action: String,
    pub path: String,
    pub cid: Option<Cid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev: Option<Cid>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IdentityFrame {
    pub did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    pub seq: i64,
    pub time: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountFrame {
    pub did: String,
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    pub seq: i64,
    pub time: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SyncFrame {
    pub did: String,
    pub rev: String,
    #[serde(with = "serde_bytes")]
    pub blocks: Vec<u8>,
    pub seq: i64,
    pub time: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InfoFrame {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorFrameHeader {
    pub op: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorFrameBody {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone)]
pub enum CommitFrameError {
    InvalidCommitCid(String),
    InvalidBlobCid(String),
}

impl std::fmt::Display for CommitFrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCommitCid(s) => write!(f, "Invalid commit CID: {}", s),
            Self::InvalidBlobCid(s) => write!(f, "Invalid blob CID: {}", s),
        }
    }
}

impl std::error::Error for CommitFrameError {}

pub struct CommitFrameBuilder {
    seq: i64,
    did: String,
    commit_cid: Cid,
    prev_cid: Option<Cid>,
    ops_json: serde_json::Value,
    blob_cids: Vec<Cid>,
    time: chrono::DateTime<chrono::Utc>,
    rev: Option<String>,
}

impl CommitFrameBuilder {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        seq: i64,
        did: String,
        commit_cid_str: &str,
        prev_cid_str: Option<&str>,
        ops_json: serde_json::Value,
        blob_strs: Vec<String>,
        time: chrono::DateTime<chrono::Utc>,
        rev: Option<String>,
    ) -> Result<Self, CommitFrameError> {
        let commit_cid = Cid::from_str(commit_cid_str)
            .map_err(|_| CommitFrameError::InvalidCommitCid(commit_cid_str.to_string()))?;
        let prev_cid = prev_cid_str.map(Cid::from_str).transpose().map_err(|_| {
            CommitFrameError::InvalidCommitCid(prev_cid_str.unwrap_or("").to_string())
        })?;
        let blob_cids: Vec<Cid> = blob_strs
            .iter()
            .filter_map(|s| Cid::from_str(s).ok())
            .collect();
        Ok(Self {
            seq,
            did,
            commit_cid,
            prev_cid,
            ops_json,
            blob_cids,
            time,
            rev,
        })
    }

    pub fn build(self) -> CommitFrame {
        let json_ops: Vec<JsonRepoOp> =
            serde_json::from_value(self.ops_json).unwrap_or_else(|_| vec![]);
        let ops: Vec<RepoOp> = json_ops
            .into_iter()
            .map(|op| RepoOp {
                action: op.action,
                path: op.path,
                cid: op.cid.and_then(|s| Cid::from_str(&s).ok()),
                prev: op.prev.and_then(|s| Cid::from_str(&s).ok()),
            })
            .collect();
        let rev = self.rev.unwrap_or_else(placeholder_rev);
        let since = self.prev_cid.as_ref().map(|_| rev.clone());
        CommitFrame {
            seq: self.seq,
            rebase: false,
            too_big: false,
            repo: self.did,
            commit: self.commit_cid,
            rev,
            since,
            blocks: Vec::new(),
            ops,
            blobs: self.blob_cids,
            time: format_atproto_time(self.time),
            prev_data: None,
        }
    }
}

fn placeholder_rev() -> String {
    use jacquard::types::{integer::LimitedU32, string::Tid};
    Tid::now(LimitedU32::MIN).to_string()
}

fn format_atproto_time(dt: chrono::DateTime<chrono::Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

impl TryFrom<SequencedEvent> for CommitFrame {
    type Error = CommitFrameError;

    fn try_from(event: SequencedEvent) -> Result<Self, Self::Error> {
        let commit_cid = event.commit_cid.ok_or_else(|| {
            CommitFrameError::InvalidCommitCid("Missing commit_cid in event".to_string())
        })?;
        let builder = CommitFrameBuilder::new(
            event.seq,
            event.did.to_string(),
            commit_cid.as_str(),
            event.prev_cid.as_ref().map(|c| c.as_str()),
            event.ops.unwrap_or_default(),
            event.blobs.unwrap_or_default(),
            event.created_at,
            event.rev,
        )?;
        Ok(builder.build())
    }
}
