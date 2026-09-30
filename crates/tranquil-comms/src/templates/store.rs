use std::collections::HashSet;
use std::fs;
use std::path::Path;

use handlebars::Handlebars;
use serde_json::{Map, Value, json};

use super::Part;
use super::error::TemplateError;
use super::ids::{REQUIRED_TEMPLATE_IDS, TemplateId};

fn template_name(prefix: &str, locale: &str, id: &str, part: &str) -> String {
    format!("{prefix}/{locale}/{id}.{part}")
}

fn vars_to_context(vars: &[(&str, &str)]) -> Value {
    let mut map = Map::new();
    for (key, value) in vars {
        map.insert((*key).to_string(), json!(value));
    }
    Value::Object(map)
}

/// Compiled on-disk notif templates for configured locales.
pub struct TemplateStore {
    plain: Handlebars<'static>,
    html: Handlebars<'static>,
    disk_locales: HashSet<String>,
    disk_enabled: bool,
    fallback_to_builtin: bool,
}

impl TemplateStore {
    fn new_registries() -> (Handlebars<'static>, Handlebars<'static>) {
        let mut plain = Handlebars::new();
        plain.register_escape_fn(handlebars::no_escape);
        plain.set_strict_mode(false);
        let mut html = Handlebars::new();
        html.set_strict_mode(false);
        (plain, html)
    }

    fn register_handlebars(
        registry: &mut Handlebars<'static>,
        name: &str,
        source: &str,
    ) -> Result<(), TemplateError> {
        registry
            .register_template_string(name, source)
            .map_err(|e| TemplateError::msg(format!("invalid Handlebars template {name:?}: {e}")))
    }

    /// No on-disk templates! Every render shall fall back to built in strings.
    pub fn empty() -> Self {
        let (plain, html) = Self::new_registries();
        Self {
            plain,
            html,
            disk_locales: HashSet::new(),
            disk_enabled: false,
            fallback_to_builtin: true,
        }
    }

    pub fn load(
        root: &Path,
        locales: &[String],
        fallback_to_builtin: bool,
    ) -> Result<Self, TemplateError> {
        if !root.is_dir() {
            return Err(TemplateError::msg(format!(
                "comms templates_dir {} is not a directory",
                root.display()
            )));
        }

        let (mut plain, mut html) = Self::new_registries();

        let mut disk_locales = HashSet::new();

        for locale_raw in locales {
            let locale = locale_raw.trim();
            if locale.is_empty() {
                return Err(TemplateError::msg(
                    "comms.template_locales entries must be non-empty",
                ));
            }
            if locale.chars().any(|c| c == '/' || c == '\\' || c == '.') {
                return Err(TemplateError::msg(format!(
                    "comms.template_locales entry {locale_raw:?} must be a plain locale code \
                     (no path separators or dots)"
                )));
            }
            let locale_dir = root.join(locale);
            if !locale_dir.is_dir() {
                return Err(TemplateError::msg(format!(
                    "missing comms template locale directory: {}",
                    locale_dir.display()
                )));
            }

            for id in REQUIRED_TEMPLATE_IDS {
                let subject_path = locale_dir.join(format!("{id}.subject.txt"));
                let body_txt_path = locale_dir.join(format!("{id}.body.txt"));
                let body_html_path = locale_dir.join(format!("{id}.body.html"));

                let subject = read_required(&subject_path)?;
                let body_txt = read_required(&body_txt_path)?;
                let body_html = read_optional(&body_html_path)?;

                let subject_name = template_name("disk", locale, id, Part::Subject.as_str());
                let body_name = template_name("disk", locale, id, Part::Body.as_str());
                let html_name = template_name("disk", locale, id, "html");

                Self::register_handlebars(&mut plain, &subject_name, &subject)?;
                Self::register_handlebars(&mut plain, &body_name, &body_txt)?;
                if let Some(body_html) = body_html {
                    Self::register_handlebars(&mut html, &html_name, &body_html)?;
                }
            }
            disk_locales.insert(locale.to_string());
        }

        Ok(Self {
            plain,
            html,
            disk_locales,
            disk_enabled: true,
            fallback_to_builtin,
        })
    }

    pub fn has_locale(&self, locale: &str) -> bool {
        self.disk_locales.contains(locale)
    }

    fn render_by_name(
        registry: &Handlebars<'static>,
        name: &str,
        data: &Value,
    ) -> Result<String, TemplateError> {
        registry
            .render(name, data)
            .map_err(|e| TemplateError::msg(format!("failed to render template {name:?}: {e}")))
    }

    pub(super) fn render_part(
        &self,
        id: TemplateId,
        part: Part,
        locale: &str,
        vars: &[(&str, &str)],
    ) -> Result<String, TemplateError> {
        let name = template_name("disk", locale, id.as_str(), part.as_str());
        Self::render_by_name(&self.plain, &name, &vars_to_context(vars))
    }

    pub(super) fn resolve(
        &self,
        id: TemplateId,
        part: Part,
        locale: &str,
        builtin: &'static str,
        vars: &[(&str, &str)],
    ) -> Result<String, TemplateError> {
        if self.has_locale(locale) {
            self.render_part(id, part, locale, vars)
        } else if !self.disk_enabled || self.fallback_to_builtin {
            Ok(crate::locale::render(builtin, vars))
        } else {
            Err(TemplateError::msg(format!(
                "no comms templates for locale {locale:?} and fallback_to_builtin is false"
            )))
        }
    }

    pub(super) fn resolve_html(
        &self,
        id: TemplateId,
        locale: &str,
        vars: &[(&str, &str)],
    ) -> Result<Option<String>, TemplateError> {
        if self.disk_enabled && self.has_locale(locale) {
            self.render_html(id, locale, vars)
        } else {
            Ok(None)
        }
    }

    pub(super) fn render_html(
        &self,
        id: TemplateId,
        locale: &str,
        vars: &[(&str, &str)],
    ) -> Result<Option<String>, TemplateError> {
        let name = template_name("disk", locale, id.as_str(), "html");
        if !self.html.has_template(&name) {
            return Ok(None);
        }
        Self::render_by_name(&self.html, &name, &vars_to_context(vars)).map(Some)
    }
}

fn read_required(path: &Path) -> Result<String, TemplateError> {
    fs::read_to_string(path)
        .map(|s| s.trim_end_matches(['\r', '\n']).to_string())
        .map_err(|e| TemplateError::msg(format!("failed to read {}: {e}", path.display())))
}

fn read_optional(path: &Path) -> Result<Option<String>, TemplateError> {
    match fs::read_to_string(path) {
        Ok(s) => Ok(Some(s.trim_end_matches(['\r', '\n']).to_string())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(TemplateError::msg(format!(
            "failed to read {}: {e}",
            path.display()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_optional() {
        let path = Path::new("tests/templates/en/welcome.body.html");
        let result = read_optional(path);
        assert!(result.is_ok());
    }
}
