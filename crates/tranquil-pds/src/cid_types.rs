use cid::Cid;
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CommitCid(Cid);

impl CommitCid {
    pub fn new(cid: Cid) -> Self {
        Self(cid)
    }

    pub fn as_cid(&self) -> &Cid {
        &self.0
    }

    pub fn into_cid(self) -> Cid {
        self.0
    }
}

impl From<Cid> for CommitCid {
    fn from(cid: Cid) -> Self {
        Self(cid)
    }
}

impl From<CommitCid> for Cid {
    fn from(commit_cid: CommitCid) -> Self {
        commit_cid.0
    }
}

impl FromStr for CommitCid {
    type Err = cid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Cid::from_str(s).map(Self)
    }
}

impl fmt::Display for CommitCid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<Cid> for CommitCid {
    fn as_ref(&self) -> &Cid {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecordCid(Cid);

impl RecordCid {
    pub fn new(cid: Cid) -> Self {
        Self(cid)
    }

    pub fn as_cid(&self) -> &Cid {
        &self.0
    }

    pub fn into_cid(self) -> Cid {
        self.0
    }
}

impl From<Cid> for RecordCid {
    fn from(cid: Cid) -> Self {
        Self(cid)
    }
}

impl From<RecordCid> for Cid {
    fn from(record_cid: RecordCid) -> Self {
        record_cid.0
    }
}

impl FromStr for RecordCid {
    type Err = cid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Cid::from_str(s).map(Self)
    }
}

impl fmt::Display for RecordCid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<Cid> for RecordCid {
    fn as_ref(&self) -> &Cid {
        &self.0
    }
}
