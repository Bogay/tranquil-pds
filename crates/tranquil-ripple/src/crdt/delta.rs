use super::lww_map::LwwDelta;
use super::g_counter::GCounterDelta;
use serde::{Deserialize, Serialize};

const SCHEMA_VERSION: u8 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrdtDelta {
    #[serde(default = "default_version")]
    pub version: u8,
    pub source_node: u64,
    pub cache_delta: Option<LwwDelta>,
    pub rate_limit_deltas: Vec<GCounterDelta>,
}

fn default_version() -> u8 {
    1
}

impl CrdtDelta {
    pub fn is_empty(&self) -> bool {
        self.cache_delta
            .as_ref()
            .map_or(true, |d| d.entries.is_empty())
            && self.rate_limit_deltas.is_empty()
    }

    pub fn is_compatible(&self) -> bool {
        self.version == SCHEMA_VERSION
    }
}
