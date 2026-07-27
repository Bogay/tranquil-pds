#[derive(Debug, thiserror::Error)]
pub enum TemplateError {
    #[error("{0}")]
    Message(String),
}

impl TemplateError {
    pub(super) fn msg(s: impl Into<String>) -> Self {
        Self::Message(s.into())
    }
}
