use serde_json::json;

pub(super) const HTML_BODY_META_KEY: &str = "html_body";

#[derive(Debug, Clone)]
pub struct RenderedTemplate {
    pub subject: String,
    pub body: String,
    pub html_body: Option<String>,
}

impl RenderedTemplate {
    /// Metadata value for `enqueue_comms`, or `None` when there is no HTML part.
    pub fn metadata(&self) -> Option<serde_json::Value> {
        self.html_body
            .as_ref()
            .map(|html| json!({ HTML_BODY_META_KEY: html }))
    }
}

/// Extract HTML body from queue metadata, if present.
pub fn html_body_from_metadata(metadata: &Option<serde_json::Value>) -> Option<&str> {
    metadata
        .as_ref()
        .and_then(|v| v.get(HTML_BODY_META_KEY))
        .and_then(|v| v.as_str())
}
