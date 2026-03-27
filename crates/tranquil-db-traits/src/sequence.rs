use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SequenceNumber(i64);

impl SequenceNumber {
    pub const ZERO: Self = Self(0);
    pub const UNSET: Self = Self(-1);

    pub fn new(n: i64) -> Option<Self> {
        if n >= 0 { Some(Self(n)) } else { None }
    }

    pub fn from_raw(n: i64) -> Self {
        Self(n)
    }

    pub fn as_i64(&self) -> i64 {
        self.0
    }

    pub fn is_valid(&self) -> bool {
        self.0 >= 0
    }

    pub fn as_u64(&self) -> Option<u64> {
        u64::try_from(self.0).ok()
    }
}

impl fmt::Display for SequenceNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<i64> for SequenceNumber {
    fn from(n: i64) -> Self {
        Self(n)
    }
}

impl From<SequenceNumber> for i64 {
    fn from(seq: SequenceNumber) -> Self {
        seq.0
    }
}

impl Serialize for SequenceNumber {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SequenceNumber {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let n = i64::deserialize(deserializer)?;
        Ok(Self(n))
    }
}

pub fn deserialize_optional_sequence<'de, D>(
    deserializer: D,
) -> Result<Option<SequenceNumber>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<i64> = Option::deserialize(deserializer)?;
    Ok(opt.map(SequenceNumber::from_raw))
}
