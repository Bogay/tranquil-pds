use serde::{Deserialize, Serialize};
use crate::sync::firehose::SequencedEvent;

#[derive(Debug, Serialize, Deserialize)]
pub struct Frame {
    #[serde(rename = "op")]
    pub op: i64,
    #[serde(rename = "d")]
    pub data: FrameData,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FrameData {
    Commit(Box<CommitFrame>),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CommitFrame {
    pub seq: i64,
    pub rebase: bool,
    #[serde(rename = "tooBig")]
    pub too_big: bool,
    pub repo: String,
    pub commit: String,
    pub prev: Option<String>,
    #[serde(with = "serde_bytes")]
    pub blocks: Vec<u8>,
    pub ops: Vec<RepoOp>,
    pub blobs: Vec<String>,
    pub time: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RepoOp {
    pub action: String,
    pub path: String,
    pub cid: Option<String>,
}

impl From<SequencedEvent> for CommitFrame {
    fn from(event: SequencedEvent) -> Self {
        let ops = serde_json::from_value::<Vec<RepoOp>>(event.ops.unwrap_or_default())
            .unwrap_or_else(|_| vec![]);

        CommitFrame {
            seq: event.seq,
            rebase: false,
            too_big: false,
            repo: event.did,
            commit: event.commit_cid.unwrap_or_default(),
            prev: event.prev_cid,
            blocks: Vec::new(),
            ops,
            blobs: event.blobs.unwrap_or_default(),
            time: event.created_at.to_rfc3339(),
        }
    }
}
