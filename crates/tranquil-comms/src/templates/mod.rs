mod error;
mod ids;
mod rendered;
mod store;

#[cfg(test)]
mod tests;

use std::path::Path;
use std::sync::OnceLock;

use tranquil_types::Locale;

pub use error::TemplateError;
pub use ids::{REQUIRED_TEMPLATE_IDS, TemplateId};
pub use rendered::RenderedTemplate;
pub use store::TemplateStore;

static RUNTIME_TEMPLATE_STORE: OnceLock<TemplateStore> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Part {
    Subject,
    Body,
}

impl Part {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Subject => "subject",
            Self::Body => "body",
        }
    }
}

/// Load templates from config without installing the global cache.
fn load_from_config(cfg: &tranquil_config::CommsConfig) -> Result<TemplateStore, TemplateError> {
    let Some(dir) = cfg
        .templates_dir
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return Ok(TemplateStore::empty());
    };

    if cfg.template_locales.is_empty() {
        return Err(TemplateError::msg(
            "comms.template_locales must be non-empty when comms.templates_dir is set",
        ));
    }

    TemplateStore::load(
        Path::new(dir),
        &cfg.template_locales,
        cfg.fallback_to_builtin,
    )
}

/// Check that configured notification templates are complete (does not install the global cache).
///
/// When we set `templates_dir`, Tranquil loads + compiles in the disk templates for `template_locales`. It won't do so if a required file is missing or has invalid `Handlebars` syntax.
pub fn validate(cfg: &tranquil_config::CommsConfig) -> Result<(), TemplateError> {
    load_from_config(cfg).map(|_| ())
}

/// Load and cache notification templates from config. Call once at process startup.
///
/// Without `templates_dir`, every notification will come from the built in strings. With it set, disk templates will be used for the configured locales instead!
pub fn init(cfg: &tranquil_config::CommsConfig) -> Result<(), TemplateError> {
    let store = load_from_config(cfg)?;
    RUNTIME_TEMPLATE_STORE
        .set(store)
        .map_err(|_| TemplateError::msg("comms templates already initialized"))?;
    Ok(())
}

pub fn render_part(
    id: TemplateId,
    part: Part,
    locale: Locale,
    builtin: &'static str,
    vars: &[(&str, &str)],
) -> Result<String, TemplateError> {
    match RUNTIME_TEMPLATE_STORE.get() {
        Some(store) => store.resolve(id, part, locale.as_str(), builtin, vars),
        None => Ok(crate::locale::render(builtin, vars)),
    }
}

pub fn render_html(
    id: TemplateId,
    locale: Locale,
    vars: &[(&str, &str)],
) -> Result<Option<String>, TemplateError> {
    match RUNTIME_TEMPLATE_STORE.get() {
        Some(store) => store.resolve_html(id, locale.as_str(), vars),
        None => Ok(None),
    }
}
