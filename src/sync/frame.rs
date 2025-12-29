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

pub struct CommitFrameBuilder {
    pub seq: i64,
    pub did: String,
    pub commit_cid_str: String,
    pub prev_cid_str: Option<String>,
    pub ops_json: serde_json::Value,
    pub blobs: Vec<String>,
    pub time: chrono::DateTime<chrono::Utc>,
    pub rev: Option<String>,
}

impl CommitFrameBuilder {
    pub fn build(self) -> Result<CommitFrame, &'static str> {
        let commit_cid = Cid::from_str(&self.commit_cid_str).map_err(|_| "Invalid commit CID")?;
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
        let blobs: Vec<Cid> = self
            .blobs
            .iter()
            .filter_map(|s| Cid::from_str(s).ok())
            .collect();
        let rev = self.rev.unwrap_or_else(placeholder_rev);
        let since = self.prev_cid_str.as_ref().map(|_| rev.clone());
        Ok(CommitFrame {
            seq: self.seq,
            rebase: false,
            too_big: false,
            repo: self.did,
            commit: commit_cid,
            rev,
            since,
            blocks: Vec::new(),
            ops,
            blobs,
            time: format_atproto_time(self.time),
            prev_data: None,
        })
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
    type Error = &'static str;

    fn try_from(event: SequencedEvent) -> Result<Self, Self::Error> {
        let builder = CommitFrameBuilder {
            seq: event.seq,
            did: event.did,
            commit_cid_str: event.commit_cid.ok_or("Missing commit_cid in event")?,
            prev_cid_str: event.prev_cid,
            ops_json: event.ops.unwrap_or_default(),
            blobs: event.blobs.unwrap_or_default(),
            time: event.created_at,
            rev: event.rev,
        };
        builder.build()
    }
}
