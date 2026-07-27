mod error;
mod ids;
mod rendered;
mod store;

#[cfg(test)]
mod tests;

use std::path::Path;
use std::sync::OnceLock;

pub use error::TemplateError;
pub use ids::{REQUIRED_TEMPLATE_IDS, TemplateId};
pub use rendered::{RenderedTemplate, html_body_from_metadata};
pub use store::TemplateStore;

static RUNTIME_TEMPLATE_STORE: OnceLock<TemplateStore> = OnceLock::new();

/// Load templates from config without installing the global cache.
fn load_from_config(cfg: &tranquil_config::CommsConfig) -> Result<TemplateStore, TemplateError> {
    let Some(dir) = cfg
        .templates_dir
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return TemplateStore::builtins_only();
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
/// Always compiles builtin Handlebars strings. When `templates_dir` is set, also
/// loads and compiles on-disk templates for `template_locales`.
pub fn validate(cfg: &tranquil_config::CommsConfig) -> Result<(), TemplateError> {
    load_from_config(cfg).map(|_| ())
}

/// Load and cache notification templates from config. Call once at process startup.
///
/// Always initializes with compiled builtins. When `templates_dir` is set, also
/// loads disk templates and fails if any required file is missing or has invalid
/// Handlebars syntax.
pub fn init(cfg: &tranquil_config::CommsConfig) -> Result<(), TemplateError> {
    let store = load_from_config(cfg)?;
    RUNTIME_TEMPLATE_STORE
        .set(store)
        .map_err(|_| TemplateError::msg("comms templates already initialized"))?;
    Ok(())
}

fn runtime_template_store() -> Result<&'static TemplateStore, TemplateError> {
    RUNTIME_TEMPLATE_STORE
        .get()
        .ok_or_else(|| TemplateError::msg("comms templates not initialized"))
}

/// Resolve subject/body/(optional HTML) for a notification using the global template cache.
pub fn render(
    id: TemplateId,
    locale: &str,
    vars: &[(&str, &str)],
) -> Result<RenderedTemplate, TemplateError> {
    runtime_template_store()?.render(id, locale, vars)
}
