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
    let subject = store
        .resolve(
            TemplateId::Welcome,
            Part::Subject,
            "en",
            "",
            &[("hostname", "nel.pet"), ("handle", "nel")],
        )
        .unwrap();
    let body = store
        .resolve(
            TemplateId::Welcome,
            Part::Body,
            "en",
            "",
            &[("hostname", "nel.pet"), ("handle", "nel")],
        )
        .unwrap();
    assert!(subject.contains("nel.pet"));
    assert!(body.contains("@nel"));
    assert!(
        store
            .resolve_html(TemplateId::Welcome, "en", &[("handle", "nel")])
            .unwrap()
            .unwrap()
            .contains("nel")
    );
}

fn example_store() -> TemplateStore {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/notification-templates");
    TemplateStore::load(&root, &["en".into()], true).unwrap()
}

fn example_body(store: &TemplateStore, id: TemplateId, vars: &[(&str, &str)]) -> String {
    store.resolve(id, Part::Body, "en", "", vars).unwrap()
}

fn example_html(store: &TemplateStore, id: TemplateId, vars: &[(&str, &str)]) -> String {
    store.resolve_html(id, "en", vars).unwrap().unwrap()
}

#[test]
fn example_welcome_handle_conditional() {
    let store = example_store();

    let with_handle_vars = &[("hostname", "nel.pet"), ("handle", "nel")];
    let with_handle = example_body(&store, TemplateId::Welcome, with_handle_vars);
    assert!(with_handle.contains("Welcome to nel.pet, @nel!"));
    assert!(with_handle.contains("Your handle is @nel."));
    assert!(!with_handle.contains("Set your handle"));
    let html = example_html(&store, TemplateId::Welcome, with_handle_vars);
    assert!(html.contains("@nel"));
    assert!(!html.contains("Set your handle to personalize"));

    let no_handle_vars = &[("hostname", "nel.pet")];
    let no_handle = example_body(&store, TemplateId::Welcome, no_handle_vars);
    assert!(no_handle.contains("Welcome to nel.pet!"));
    assert!(!no_handle.contains("Welcome to nel.pet, @"));
    assert!(no_handle.contains("Set your handle to personalize your account."));
    let html = example_html(&store, TemplateId::Welcome, no_handle_vars);
    assert!(html.contains("Set your handle to personalize your account."));
}

#[test]
fn example_email_update_verify_link_conditional() {
    let store = example_store();
    let verify_link = "https://nel.pet/oneclick?token=abc123";

    let with_link = example_body(
        &store,
        TemplateId::EmailUpdate,
        &[
            ("hostname", "nel.pet"),
            ("handle", "nel"),
            ("code", "123456"),
            ("verify_page", "https://nel.pet/app/verify"),
            ("verify_link", verify_link),
        ],
    );
    assert!(with_link.contains("verify in one click"));
    assert!(with_link.contains(verify_link));
    let html = example_html(
        &store,
        TemplateId::EmailUpdate,
        &[
            ("hostname", "nel.pet"),
            ("handle", "nel"),
            ("code", "123456"),
            ("verify_page", "https://nel.pet/app/verify"),
            ("verify_link", verify_link),
        ],
    );
    assert!(html.contains("live dangerously"));
    assert!(html.contains(&format!("href=\"{verify_link}\"")));

    let no_link = example_body(
        &store,
        TemplateId::EmailUpdate,
        &[
            ("hostname", "nel.pet"),
            ("handle", "nel"),
            ("code", "123456"),
            ("verify_page", "https://nel.pet/app/verify"),
        ],
    );
    assert!(!no_link.contains("live dangerously"));
    assert!(!no_link.contains(verify_link));
    let html = example_html(
        &store,
        TemplateId::EmailUpdate,
        &[
            ("hostname", "nel.pet"),
            ("handle", "nel"),
            ("code", "123456"),
            ("verify_page", "https://nel.pet/app/verify"),
        ],
    );
    assert!(!html.contains("live dangerously"));
    assert!(!html.contains("href="));
}

#[test]
fn example_short_token_matches_approval_vars() {
    let store = example_store();
    let body = example_body(
        &store,
        TemplateId::ShortToken,
        &[
            ("handle", "nel"),
            ("code", "123456"),
            ("verify_page", "https://nel.pet/app/settings"),
            ("valid_for", "15 minutes"),
        ],
    );
    assert!(body.contains("Hello @nel,"));
    assert!(body.contains("123456"));
    assert!(body.contains("https://nel.pet/app/settings"));
    assert!(body.contains("15 minutes"));
    assert!(!body.contains('{'), "{body}");
}

#[test]
fn example_signup_verification_else_if_branches() {
    let store = example_store();

    let via_page = example_body(
        &store,
        TemplateId::SignupVerification,
        &[
            ("hostname", "nel.pet"),
            ("code", "654321"),
            ("verify_page", "https://nel.pet/app/verify"),
        ],
    );
    assert!(via_page.contains("Copy the code above and enter it at:"));
    assert!(via_page.contains("https://nel.pet/app/verify"));
    assert!(!via_page.contains("Or verify directly:"));

    let via_link = example_body(
        &store,
        TemplateId::SignupVerification,
        &[
            ("hostname", "nel.pet"),
            ("code", "654321"),
            ("verify_link", "https://nel.pet/app/verify?token=abc"),
        ],
    );
    assert!(via_link.contains("Or verify directly:"));
    assert!(via_link.contains("https://nel.pet/app/verify?token=abc"));
    assert!(!via_link.contains("Copy the code above"));
}

#[test]
fn example_channel_verified_conditionals() {
    let store = example_store();

    let full_vars = &[
        ("hostname", "nel.pet"),
        ("handle", "nel"),
        ("channel", "Telegram"),
    ];
    let full = example_body(&store, TemplateId::ChannelVerified, full_vars);
    assert!(full.contains("Hello @nel,"));
    assert!(full.contains("Telegram has been verified"));
    assert!(!full.contains("Hello there,"));
    let html = example_html(&store, TemplateId::ChannelVerified, full_vars);
    assert!(html.contains("Hello @nel,"));
    assert!(html.contains("<strong>Telegram</strong>"));

    let bare_vars = &[("hostname", "nel.pet")];
    let bare = example_body(&store, TemplateId::ChannelVerified, bare_vars);
    assert!(bare.contains("Hello there,"));
    assert!(!bare.contains("@"));
    let html = example_html(&store, TemplateId::ChannelVerified, bare_vars);
    assert!(html.contains("A channel has been verified"));
}

#[test]
fn example_legacy_login_detail_conditionals() {
    let store = example_store();

    let detailed = example_body(
        &store,
        TemplateId::LegacyLogin,
        &[
            ("hostname", "nel.pet"),
            ("handle", "nel"),
            ("timestamp", "2026-08-10 12:00:00 UTC"),
            ("ip", "203.0.113.7"),
        ],
    );
    assert!(detailed.contains("Time: 2026-08-10 12:00:00 UTC"));
    assert!(detailed.contains("IP Address: 203.0.113.7"));

    let bare = example_body(
        &store,
        TemplateId::LegacyLogin,
        &[("hostname", "nel.pet"), ("handle", "nel")],
    );
    assert!(!bare.contains("Time:"));
    assert!(!bare.contains("IP Address:"));
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
    let vars = &[("handle", "a<b>&c"), ("hostname", "nel.pet"), ("code", "1")];
    let body = store
        .resolve(TemplateId::Welcome, Part::Body, "en", "", vars)
        .unwrap();
    assert!(body.contains("a<b>&c"));
    let html = store
        .resolve_html(TemplateId::Welcome, "en", vars)
        .unwrap()
        .unwrap();
    assert!(html.contains("a&lt;b&gt;&amp;c"), "{html}");
    assert!(!html.contains("a<b>&c"), "{html}");
}

#[test]
fn fallback_locale_flat_renders_builtin_when_enabled() {
    let tmp = tempfile_dir();
    write_complete_locale(&tmp, "en");
    let store = TemplateStore::load(&tmp, &["en".into()], true).unwrap();
    let subject = store
        .resolve(
            TemplateId::Welcome,
            Part::Subject,
            "fr",
            "Bienvenue sur {hostname}",
            &[("hostname", "nel.pet"), ("handle", "nel")],
        )
        .unwrap();
    assert_eq!(subject, "Bienvenue sur nel.pet");
    assert!(
        store
            .resolve_html(TemplateId::Welcome, "fr", &[("handle", "nel")])
            .unwrap()
            .is_none()
    );
}

#[test]
fn unsupported_locale_errors_when_fallback_disabled() {
    let tmp = tempfile_dir();
    write_complete_locale(&tmp, "en");
    let store = TemplateStore::load(&tmp, &["en".into()], false).unwrap();
    let Err(err) = store.resolve(
        TemplateId::Welcome,
        Part::Subject,
        "zh",
        "welcome {hostname}",
        &[("hostname", "nel.pet"), ("handle", "nel")],
    ) else {
        panic!("expected render to fail when fallback is disabled");
    };
    assert!(err.to_string().contains("fallback_to_builtin"), "{err}");
}

#[test]
fn empty_store_flat_renders_builtin_without_templates_dir() {
    let store = TemplateStore::empty();
    let subject = store
        .resolve(
            TemplateId::Welcome,
            Part::Subject,
            "en",
            "Welcome to {hostname}",
            &[("hostname", "nel.pet")],
        )
        .unwrap();
    let body = store
        .resolve(
            TemplateId::Welcome,
            Part::Body,
            "en",
            "Welcome to {hostname}! Your handle is: @{handle}",
            &[("hostname", "nel.pet"), ("handle", "nel")],
        )
        .unwrap();
    assert_eq!(subject, "Welcome to nel.pet");
    assert_eq!(body, "Welcome to nel.pet! Your handle is: @nel");
    assert!(
        store
            .resolve_html(TemplateId::Welcome, "en", &[("handle", "nel")])
            .unwrap()
            .is_none()
    );
}
