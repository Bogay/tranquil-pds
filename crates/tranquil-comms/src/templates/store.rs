use std::collections::HashSet;
use std::fs;
use std::path::Path;

use handlebars::Handlebars;
use serde_json::{Map, Value, json};

use super::error::TemplateError;
use super::ids::{REQUIRED_TEMPLATE_IDS, TemplateId};
use super::rendered::RenderedTemplate;
use crate::locale::validate_locale;
use tranquil_types::Locale;

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

/// Compiled notification templates (builtins always; disk overrides when configured).
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

    fn register_builtins(plain: &mut Handlebars<'static>) -> Result<(), TemplateError> {
        for locale in Locale::ALL.iter().map(|l| l.as_str()) {
            for id in TemplateId::ALL {
                let parts = id.builtin_parts(locale);
                let subject_name = template_name("builtin", locale, id.as_str(), "subject");
                let body_name = template_name("builtin", locale, id.as_str(), "body");
                Self::register_handlebars(plain, &subject_name, parts.subject)?;
                Self::register_handlebars(plain, &body_name, parts.body)?;
            }
        }
        Ok(())
    }

    /// Built-in Handlebars templates only (no `templates_dir`).
    pub fn builtins_only() -> Result<Self, TemplateError> {
        let (mut plain, html) = Self::new_registries();
        Self::register_builtins(&mut plain)?;
        Ok(Self {
            plain,
            html,
            disk_locales: HashSet::new(),
            disk_enabled: false,
            fallback_to_builtin: true,
        })
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
        Self::register_builtins(&mut plain)?;

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

                let subject_name = template_name("disk", locale, id, "subject");
                let body_name = template_name("disk", locale, id, "body");
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

    pub fn fallback_to_builtin(&self) -> bool {
        self.fallback_to_builtin
    }

    fn render_named(
        registry: &Handlebars<'static>,
        name: &str,
        data: &Value,
    ) -> Result<String, TemplateError> {
        registry
            .render(name, data)
            .map_err(|e| TemplateError::msg(format!("failed to render template {name:?}: {e}")))
    }

    fn render_builtin(
        &self,
        id: TemplateId,
        locale: &str,
        data: &Value,
    ) -> Result<RenderedTemplate, TemplateError> {
        let subject_name: String = template_name("builtin", locale, id.as_str(), "subject");
        let body_name = template_name("builtin", locale, id.as_str(), "body");
        Ok(RenderedTemplate {
            subject: Self::render_named(&self.plain, &subject_name, data)?,
            body: Self::render_named(&self.plain, &body_name, data)?,
            html_body: None,
        })
    }

    fn render_disk(
        &self,
        id: TemplateId,
        locale: &str,
        data: &Value,
    ) -> Result<RenderedTemplate, TemplateError> {
        let subject_name = template_name("disk", locale, id.as_str(), "subject");
        let body_name = template_name("disk", locale, id.as_str(), "body");
        let html_name = template_name("disk", locale, id.as_str(), "html");
        let html_body = if self.html.has_template(&html_name) {
            Some(Self::render_named(&self.html, &html_name, data)?)
        } else {
            None
        };
        Ok(RenderedTemplate {
            subject: Self::render_named(&self.plain, &subject_name, data)?,
            body: Self::render_named(&self.plain, &body_name, data)?,
            html_body,
        })
    }

    pub fn render(
        &self,
        id: TemplateId,
        locale: &str,
        vars: &[(&str, &str)],
    ) -> Result<RenderedTemplate, TemplateError> {
        let locale = validate_locale(locale);
        let data = vars_to_context(vars);

        if self.has_locale(locale) {
            self.render_disk(id, locale, &data)
        } else if !self.disk_enabled || self.fallback_to_builtin {
            self.render_builtin(id, locale, &data)
        } else {
            Err(TemplateError::msg(format!(
                "no comms templates for locale {locale:?} and fallback_to_builtin is false"
            )))
        }
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

// tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_optional() {
        let path = Path::new("test/templates/builtin/en/welcome.body.html");
        let result = read_optional(path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_html_body_is_none_when_no_html_exists() {
        let store = TemplateStore::builtins_only().unwrap();
        let result = store.render(TemplateId::Welcome, "en", &[]);
        assert!(result.is_ok());
        assert!(result.unwrap().html_body.is_none());
    }

    #[test]
    fn test_html_body_is_some_when_html_exists() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/templates");
        let store = TemplateStore::load(&root, &["en".to_string()], false).unwrap();
        let rendered = store.render(TemplateId::Welcome, "en", &[]).unwrap();
        assert!(rendered.html_body.is_some());
        assert!(
            rendered
                .html_body
                .unwrap()
                .contains("<p>Hello <b>html</b>.</p>")
        );
    }

    #[test]
    fn test_html_body_is_none_when_html_does_not_exist() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/templates-txt");
        let store = TemplateStore::load(&root, &["en".to_string()], false).unwrap();
        let rendered = store.render(TemplateId::Welcome, "en", &[]).unwrap();
        assert!(rendered.html_body.is_none());
        assert_eq!(rendered.subject, "Hello World");
        assert_eq!(rendered.body, "Hello World");
    }
}
