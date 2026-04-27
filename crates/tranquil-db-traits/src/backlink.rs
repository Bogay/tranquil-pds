use std::fmt;
use std::str::FromStr;

use async_trait::async_trait;
use tranquil_types::{AtUri, Nsid};
use uuid::Uuid;

use crate::DbError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BacklinkPath {
    Subject,
    SubjectUri,
}

impl BacklinkPath {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Subject => "subject",
            Self::SubjectUri => "subject.uri",
        }
    }
}

impl fmt::Display for BacklinkPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct BacklinkPathParseError(String);

impl fmt::Display for BacklinkPathParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown backlink path: {}", self.0)
    }
}

impl std::error::Error for BacklinkPathParseError {}

impl FromStr for BacklinkPath {
    type Err = BacklinkPathParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "subject" => Ok(Self::Subject),
            "subject.uri" => Ok(Self::SubjectUri),
            _ => Err(BacklinkPathParseError(s.to_owned())),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Backlink {
    pub uri: AtUri,
    pub path: BacklinkPath,
    pub link_to: String,
}

#[async_trait]
pub trait BacklinkRepository: Send + Sync {
    async fn get_backlink_conflicts(
        &self,
        repo_id: Uuid,
        collection: &Nsid,
        backlinks: &[Backlink],
    ) -> Result<Vec<AtUri>, DbError>;

    async fn add_backlinks(&self, repo_id: Uuid, backlinks: &[Backlink]) -> Result<(), DbError>;

    async fn remove_backlinks_by_uri(&self, uri: &AtUri) -> Result<(), DbError>;

    async fn remove_backlinks_by_repo(&self, repo_id: Uuid) -> Result<(), DbError>;
}
