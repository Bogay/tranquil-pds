use serde::{Deserialize, Deserializer};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PaginationDirection {
    #[default]
    Forward,
    Backward,
}

impl PaginationDirection {
    pub fn from_optional_bool(value: Option<bool>) -> Self {
        match value {
            Some(true) => Self::Backward,
            Some(false) | None => Self::Forward,
        }
    }

    pub fn is_reverse(&self) -> bool {
        matches!(self, Self::Backward)
    }
}

pub fn deserialize_pagination_direction<'de, D>(
    deserializer: D,
) -> Result<PaginationDirection, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<bool> = Option::deserialize(deserializer)?;
    Ok(PaginationDirection::from_optional_bool(opt))
}
