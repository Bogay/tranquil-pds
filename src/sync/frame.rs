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

impl TryFrom<SequencedEvent> for CommitFrame {
    type Error = &'static str;

    fn try_from(event: SequencedEvent) -> Result<Self, Self::Error> {
        let ops = serde_json::from_value::<Vec<RepoOp>>(event.ops.unwrap_or_default())
            .unwrap_or_else(|_| vec![]);

        let commit_cid = event.commit_cid.ok_or("Missing commit_cid in event")?;

        Ok(CommitFrame {
            seq: event.seq,
            rebase: false,
            too_big: false,
            repo: event.did,
            commit: commit_cid,
            prev: event.prev_cid,
            blocks: Vec::new(),
            ops,
            blobs: event.blobs.unwrap_or_default(),
            time: event.created_at.to_rfc3339(),
        })
    }
}
