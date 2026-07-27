use std::fs;
use std::io::Write;
use std::path::Path;

use super::*;

fn write_complete_locale(dir: &Path, locale: &str) {
    let locale_dir = dir.join(locale);
    fs::create_dir_all(&locale_dir).unwrap();
    for id in REQUIRED_TEMPLATE_IDS {
        write_file(
            &locale_dir.join(format!("{id}.subject.txt")),
            &format!("{id} subject {{{{hostname}}}}"),
        );
        write_file(
            &locale_dir.join(format!("{id}.body.txt")),
            &format!("{id} body handle={{{{handle}}}} code={{{{code}}}}"),
        );
        write_file(
            &locale_dir.join(format!("{id}.body.html")),
            &format!("<p>{id} <b>{{{{handle}}}}</b> code={{{{code}}}}</p>"),
        );
    }
}

fn write_file(path: &Path, contents: &str) {
    let mut f = fs::File::create(path).unwrap();
    f.write_all(contents.as_bytes()).unwrap();
}

fn tempfile_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "tranquil-comms-templates-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn example_templates_tree_loads() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/notification-templates");
    let store = TemplateStore::load(&root, &["en".into()], true).unwrap();
    let rendered = store
        .render(
            TemplateId::Welcome,
            "en",
            &[("hostname", "example.com"), ("handle", "alice")],
        )
        .unwrap();
    assert!(rendered.subject.contains("example.com"));
    assert!(rendered.body.contains("@alice"));
    assert!(rendered.html_body.unwrap().contains("alice"));
}

fn example_store() -> TemplateStore {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/notification-templates");
    TemplateStore::load(&root, &["en".into()], true).unwrap()
}

#[test]
fn example_welcome_handle_conditional() {
    let store = example_store();

    let with_handle = store
        .render(
            TemplateId::Welcome,
            "en",
            &[("hostname", "example.com"), ("handle", "alice")],
        )
        .unwrap();
    assert!(with_handle.body.contains("Welcome to example.com, @alice!"));
    assert!(with_handle.body.contains("Your handle is @alice."));
    assert!(!with_handle.body.contains("Set your handle"));
    let html = with_handle.html_body.unwrap();
    assert!(html.contains("@alice"));
    assert!(!html.contains("Set your handle to personalize"));

    let no_handle = store
        .render(TemplateId::Welcome, "en", &[("hostname", "example.com")])
        .unwrap();
    assert!(no_handle.body.contains("Welcome to example.com!"));
    assert!(!no_handle.body.contains("Welcome to example.com, @"));
    assert!(
        no_handle
            .body
            .contains("Set your handle to personalize your account.")
    );
    let html = no_handle.html_body.unwrap();
    assert!(html.contains("Set your handle to personalize your account."));
}

#[test]
fn example_email_update_verify_link_conditional() {
    let store = example_store();
    let verify_link = "https://example.com/oneclick?token=abc123";

    let with_link = store
        .render(
            TemplateId::EmailUpdate,
            "en",
            &[
                ("hostname", "example.com"),
                ("handle", "alice"),
                ("code", "123456"),
                ("verify_page", "https://example.com/app/verify"),
                ("verify_link", verify_link),
            ],
        )
        .unwrap();
    assert!(with_link.body.contains("verify in one click"));
    assert!(with_link.body.contains(verify_link));
    let html = with_link.html_body.unwrap();
    assert!(html.contains("live dangerously"));
    assert!(html.contains(&format!("href=\"{verify_link}\"")));

    let no_link = store
        .render(
            TemplateId::EmailUpdate,
            "en",
            &[
                ("hostname", "example.com"),
                ("handle", "alice"),
                ("code", "123456"),
                ("verify_page", "https://example.com/app/verify"),
            ],
        )
        .unwrap();
    assert!(!no_link.body.contains("live dangerously"));
    assert!(!no_link.body.contains(verify_link));
    let html = no_link.html_body.unwrap();
    assert!(!html.contains("live dangerously"));
    assert!(!html.contains("href="));
}

#[test]
fn example_signup_verification_else_if_branches() {
    let store = example_store();

    let via_page = store
        .render(
            TemplateId::SignupVerification,
            "en",
            &[
                ("hostname", "example.com"),
                ("code", "654321"),
                ("verify_page", "https://example.com/app/verify"),
            ],
        )
        .unwrap();
    assert!(
        via_page
            .body
            .contains("Copy the code above and enter it at:")
    );
    assert!(via_page.body.contains("https://example.com/app/verify"));
    assert!(!via_page.body.contains("Or verify directly:"));

    let via_link = store
        .render(
            TemplateId::SignupVerification,
            "en",
            &[
                ("hostname", "example.com"),
                ("code", "654321"),
                ("verify_link", "https://example.com/app/verify?token=abc"),
            ],
        )
        .unwrap();
    assert!(via_link.body.contains("Or verify directly:"));
    assert!(
        via_link
            .body
            .contains("https://example.com/app/verify?token=abc")
    );
    assert!(!via_link.body.contains("Copy the code above"));
}

#[test]
fn example_channel_verified_conditionals() {
    let store = example_store();

    let full = store
        .render(
            TemplateId::ChannelVerified,
            "en",
            &[
                ("hostname", "example.com"),
                ("handle", "alice"),
                ("channel", "Telegram"),
            ],
        )
        .unwrap();
    assert!(full.body.contains("Hello @alice,"));
    assert!(full.body.contains("Telegram has been verified"));
    assert!(!full.body.contains("Hello there,"));
    let html = full.html_body.unwrap();
    assert!(html.contains("Hello @alice,"));
    assert!(html.contains("<strong>Telegram</strong>"));

    let bare = store
        .render(
            TemplateId::ChannelVerified,
            "en",
            &[("hostname", "example.com")],
        )
        .unwrap();
    assert!(bare.body.contains("Hello there,"));
    assert!(!bare.body.contains("@"));
    let html = bare.html_body.unwrap();
    assert!(html.contains("A channel has been verified"));
}

#[test]
fn example_legacy_login_detail_conditionals() {
    let store = example_store();

    let detailed = store
        .render(
            TemplateId::LegacyLogin,
            "en",
            &[
                ("hostname", "example.com"),
                ("handle", "alice"),
                ("timestamp", "2026-08-10 12:00:00 UTC"),
                ("ip", "203.0.113.7"),
            ],
        )
        .unwrap();
    assert!(detailed.body.contains("Time: 2026-08-10 12:00:00 UTC"));
    assert!(detailed.body.contains("IP Address: 203.0.113.7"));

    let bare = store
        .render(
            TemplateId::LegacyLogin,
            "en",
            &[("hostname", "example.com"), ("handle", "alice")],
        )
        .unwrap();
    assert!(!bare.body.contains("Time:"));
    assert!(!bare.body.contains("IP Address:"));
}

#[test]
fn load_fails_when_file_missing() {
    let tmp = tempfile_dir();
    let locale_dir = tmp.join("en");
    fs::create_dir_all(&locale_dir).unwrap();
    write_file(&locale_dir.join("welcome.subject.txt"), "x");
    let Err(err) = TemplateStore::load(&tmp, &["en".into()], true) else {
        panic!("expected load to fail when files are missing");
    };
    assert!(err.to_string().contains("failed to read"), "{err}");
}

#[test]
fn load_rejects_locale_path_traversal() {
    let tmp = tempfile_dir();
    let Err(err) = TemplateStore::load(&tmp, &["../evil".into()], true) else {
        panic!("expected load to reject path traversal locale");
    };
    assert!(err.to_string().contains("plain locale code"), "{err}");
}

#[test]
fn load_rejects_empty_locale() {
    let tmp = tempfile_dir();
    let Err(err) = TemplateStore::load(&tmp, &["  ".into()], true) else {
        panic!("expected load to reject empty locale");
    };
    assert!(err.to_string().contains("non-empty"), "{err}");
}

#[test]
fn load_fails_on_invalid_handlebars_syntax() {
    let tmp = tempfile_dir();
    write_complete_locale(&tmp, "en");
    write_file(
        &tmp.join("en").join("welcome.body.html"),
        "<p>{{#if handle}}</p>",
    );
    let Err(err) = TemplateStore::load(&tmp, &["en".into()], true) else {
        panic!("expected load to fail on invalid Handlebars");
    };
    assert!(err.to_string().contains("invalid Handlebars"), "{err}");
}

#[test]
fn render_escapes_html_values() {
    let tmp = tempfile_dir();
    write_complete_locale(&tmp, "en");
    let store = TemplateStore::load(&tmp, &["en".into()], true).unwrap();
    let rendered = store
        .render(
            TemplateId::Welcome,
            "en",
            &[("handle", "a<b>&c"), ("hostname", "ex.com"), ("code", "1")],
        )
        .unwrap();
    let html = rendered.html_body.unwrap();
    assert!(html.contains("a&lt;b&gt;&amp;c"), "{html}");
    assert!(!html.contains("a<b>&c"), "{html}");
    assert!(rendered.body.contains("a<b>&c"));
}

#[test]
fn fallback_locale_uses_builtin_when_enabled() {
    let tmp = tempfile_dir();
    write_complete_locale(&tmp, "en");
    let store = TemplateStore::load(&tmp, &["en".into()], true).unwrap();
    let rendered = store
        .render(
            TemplateId::Welcome,
            "fr",
            &[("hostname", "ex.com"), ("handle", "bob")],
        )
        .unwrap();
    assert!(rendered.html_body.is_none());
    assert!(rendered.body.contains("ex.com"));
    assert!(rendered.subject.contains("ex.com"));
}

#[test]
fn unsupported_locale_errors_when_fallback_disabled() {
    let tmp = tempfile_dir();
    write_complete_locale(&tmp, "en");
    let store = TemplateStore::load(&tmp, &["en".into()], false).unwrap();
    let Err(err) = store.render(
        TemplateId::Welcome,
        "zh",
        &[("hostname", "ex.com"), ("handle", "bob")],
    ) else {
        panic!("expected render to fail when fallback is disabled");
    };
    assert!(err.to_string().contains("fallback_to_builtin"), "{err}");
}

#[test]
fn builtins_only_renders_without_templates_dir() {
    let store = TemplateStore::builtins_only().unwrap();
    let rendered = store
        .render(
            TemplateId::Welcome,
            "en",
            &[("hostname", "ex.com"), ("handle", "bob")],
        )
        .unwrap();
    assert!(rendered.html_body.is_none());
    assert!(rendered.subject.contains("ex.com"));
    assert!(rendered.body.contains("@bob"));
    assert!(rendered.body.contains("ex.com"));
}

#[test]
fn metadata_includes_html_body() {
    let rendered = RenderedTemplate {
        subject: "s".into(),
        body: "b".into(),
        html_body: Some("<p>hi</p>".into()),
    };
    let meta = rendered.metadata().unwrap();
    assert_eq!(meta["html_body"], "<p>hi</p>");
    assert!(
        RenderedTemplate {
            subject: "s".into(),
            body: "b".into(),
            html_body: None,
        }
        .metadata()
        .is_none()
    );
}
