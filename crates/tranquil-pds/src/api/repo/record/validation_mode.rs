use serde::{Deserialize, Deserializer};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ValidationMode {
    Skip,
    #[default]
    Infer,
    Strict,
}

impl ValidationMode {
    pub fn from_optional_bool(value: Option<bool>) -> Self {
        match value {
            Some(false) => Self::Skip,
            Some(true) => Self::Strict,
            None => Self::Infer,
        }
    }

    pub fn should_skip(&self) -> bool {
        matches!(self, Self::Skip)
    }

    pub fn requires_lexicon(&self) -> bool {
        matches!(self, Self::Strict)
    }
}

pub fn deserialize_validation_mode<'de, D>(deserializer: D) -> Result<ValidationMode, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<bool> = Option::deserialize(deserializer)?;
    Ok(ValidationMode::from_optional_bool(opt))
}
