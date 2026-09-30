#[derive(Debug, Clone)]
pub struct RenderedTemplate {
    pub subject: String,
    pub body: String,
    pub html_body: Option<String>,
}
