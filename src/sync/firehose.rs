use serde::{Deserialize, Serialize};
use serde_json::Value;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequencedEvent {
    pub seq: i64,
    pub did: String,
    pub created_at: DateTime<Utc>,
    pub event_type: String,
    pub commit_cid: Option<String>,
    pub prev_cid: Option<String>,
    pub prev_data_cid: Option<String>,
    pub ops: Option<Value>,
    pub blobs: Option<Vec<String>>,
    pub blocks_cids: Option<Vec<String>>,
    pub handle: Option<String>,
    pub active: Option<bool>,
    pub status: Option<String>,
}
