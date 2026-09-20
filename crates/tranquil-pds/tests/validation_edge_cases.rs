use tranquil_lexicon::is_valid_did;
use tranquil_pds::api::validation::{
    HandleValidationError, MAX_SERVICE_HANDLE_LOCAL_PART, validate_short_handle,
};
use tranquil_pds::validation::{validate_collection_nsid, validate_password, validate_record_key};

#[test]
fn test_record_key_boundary_min() {
    assert!(validate_record_key("a").is_ok());
    assert!(validate_record_key("1").is_ok());
    assert!(validate_record_key("-").is_ok());
    assert!(validate_record_key("_").is_ok());
    assert!(validate_record_key("~").is_ok());
}

#[test]
fn test_record_key_boundary_max() {
    assert!(validate_record_key(&"a".repeat(512)).is_ok());
    assert!(validate_record_key(&"a".repeat(513)).is_err());
    assert!(validate_record_key(&"a".repeat(1000)).is_err());
}

#[test]
fn test_record_key_special_dot_cases() {
    assert!(validate_record_key(".").is_err());
    assert!(validate_record_key("..").is_err());
    assert!(validate_record_key("...").is_ok());
    assert!(validate_record_key("a.b").is_ok());
    assert!(validate_record_key(".a").is_ok());
    assert!(validate_record_key("a.").is_ok());
    assert!(validate_record_key("a..b").is_ok());
}

#[test]
fn test_record_key_all_valid_chars() {
    assert!(validate_record_key("abc").is_ok());
    assert!(validate_record_key("ABC").is_ok());
    assert!(validate_record_key("123").is_ok());
    assert!(validate_record_key("a-b").is_ok());
    assert!(validate_record_key("a_b").is_ok());
    assert!(validate_record_key("a~b").is_ok());
    assert!(validate_record_key("a.b").is_ok());
    assert!(validate_record_key("aA1-_.~").is_ok());
}

#[test]
fn test_record_key_invalid_chars() {
    assert!(validate_record_key("a/b").is_err());
    assert!(validate_record_key("a\\b").is_err());
    assert!(validate_record_key("a b").is_err());
    assert!(validate_record_key("a@b").is_err());
    assert!(validate_record_key("a#b").is_err());
    assert!(validate_record_key("a$b").is_err());
    assert!(validate_record_key("a%b").is_err());
    assert!(validate_record_key("a&b").is_err());
    assert!(validate_record_key("a*b").is_err());
    assert!(validate_record_key("a+b").is_err());
    assert!(validate_record_key("a=b").is_err());
    assert!(validate_record_key("a?b").is_err());
    assert!(validate_record_key("a;b").is_err());
    assert!(validate_record_key("a<b").is_err());
    assert!(validate_record_key("a>b").is_err());
    assert!(validate_record_key("a[b").is_err());
    assert!(validate_record_key("a]b").is_err());
    assert!(validate_record_key("a{b").is_err());
    assert!(validate_record_key("a}b").is_err());
    assert!(validate_record_key("a|b").is_err());
    assert!(validate_record_key("a`b").is_err());
    assert!(validate_record_key("a'b").is_err());
    assert!(validate_record_key("a\"b").is_err());
    assert!(validate_record_key("a\nb").is_err());
    assert!(validate_record_key("a\tb").is_err());
    assert!(validate_record_key("a\rb").is_err());
    assert!(validate_record_key("a\0b").is_err());
}

#[test]
fn test_record_key_unicode() {
    assert!(validate_record_key("café").is_err());
    assert!(validate_record_key("日本語").is_err());
    assert!(validate_record_key("emoji😀").is_err());
}

#[test]
fn test_password_length_boundaries() {
    let base_valid = "Aa1";

    let pass_7 = format!("{}{}", base_valid, "x".repeat(4));
    assert!(validate_password(&pass_7).is_err());

    let pass_8 = format!("{}{}", base_valid, "x".repeat(5));
    assert!(validate_password(&pass_8).is_ok());

    let pass_256 = format!("{}{}", base_valid, "x".repeat(253));
    assert!(validate_password(&pass_256).is_ok());

    let pass_257 = format!("{}{}", base_valid, "x".repeat(254));
    assert!(validate_password(&pass_257).is_err());
}

#[test]
fn test_password_missing_requirements() {
    assert!(validate_password("abcdefgh").is_err());
    assert!(validate_password("ABCDEFGH").is_err());
    assert!(validate_password("12345678").is_err());

    assert!(validate_password("abcd1234").is_err());
    assert!(validate_password("ABCD1234").is_err());
    assert!(validate_password("abcdABCD").is_err());

    assert!(validate_password("aB1xxxxx").is_ok());
}

#[test]
fn test_password_common_passwords() {
    assert!(validate_password("Password1").is_err());
    assert!(validate_password("PASSWORD1").is_err());
    assert!(validate_password("password1").is_err());
    assert!(validate_password("Qwerty123").is_err());
    assert!(validate_password("Bluesky123").is_err());
}

#[test]
fn test_password_special_chars_allowed() {
    assert!(validate_password("Aa1!@#$%").is_ok());
    assert!(validate_password("Aa1^&*()").is_ok());
    assert!(validate_password("Aa1 space").is_ok());
}

#[test]
fn test_did_validation_basic() {
    assert!(is_valid_did("did:plc:abc123"));
    assert!(is_valid_did("did:web:example.com"));
    assert!(is_valid_did(
        "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    ));
}

#[test]
fn test_did_validation_invalid() {
    assert!(!is_valid_did(""));
    assert!(!is_valid_did("did"));
    assert!(!is_valid_did("did:"));
    assert!(!is_valid_did("did::"));
    assert!(!is_valid_did("did:plc"));
    assert!(!is_valid_did("did:plc:"));
    assert!(!is_valid_did(":plc:abc"));
    assert!(!is_valid_did("plc:abc"));
}

#[test]
fn test_did_validation_method_case() {
    assert!(!is_valid_did("did:PLC:abc123"));
    assert!(!is_valid_did("did:Plc:abc123"));
    assert!(!is_valid_did("DID:plc:abc123"));
}

#[test]
fn test_did_validation_method_chars() {
    assert!(is_valid_did("did:plc1:abc"));
    assert!(!is_valid_did("did:plc-x:abc"));
    assert!(!is_valid_did("did:plc_x:abc"));
}

#[test]
fn test_collection_nsid_minimum_segments() {
    assert!(validate_collection_nsid("a.b.c").is_ok());
    assert!(validate_collection_nsid("a.b").is_err());
    assert!(validate_collection_nsid("a").is_err());
    assert!(validate_collection_nsid("").is_err());
}

#[test]
fn test_collection_nsid_many_segments() {
    assert!(validate_collection_nsid("a.b.c.d.e.f.g.h.i.j").is_ok());
}

#[test]
fn test_collection_nsid_empty_segments() {
    assert!(validate_collection_nsid("a..b.c").is_err());
    assert!(validate_collection_nsid(".a.b.c").is_err());
    assert!(validate_collection_nsid("a.b.c.").is_err());
    assert!(validate_collection_nsid("a.b..c").is_err());
}

#[test]
fn test_collection_nsid_valid_chars() {
    assert!(validate_collection_nsid("app.bsky.feed.post").is_ok());
    assert!(validate_collection_nsid("com.example.my-record").is_ok());
    assert!(validate_collection_nsid("app.example.record123").is_ok());
    assert!(validate_collection_nsid("APP.BSKY.FEED.POST").is_ok());
}

#[test]
fn test_collection_nsid_invalid_chars() {
    assert!(validate_collection_nsid("app.bsky.feed_post").is_err());
    assert!(validate_collection_nsid("app.bsky.feed/post").is_err());
    assert!(validate_collection_nsid("app.bsky.feed:post").is_err());
    assert!(validate_collection_nsid("app.bsky.feed@post").is_err());
}

#[test]
fn test_handle_boundary_lengths() {
    let min_handle = "abc";
    assert!(validate_short_handle(min_handle).is_ok());

    let under_min = "ab";
    assert!(matches!(
        validate_short_handle(under_min),
        Err(HandleValidationError::TooShort)
    ));

    let at_max = "a".repeat(MAX_SERVICE_HANDLE_LOCAL_PART);
    assert!(validate_short_handle(&at_max).is_ok());

    let over_max = "a".repeat(MAX_SERVICE_HANDLE_LOCAL_PART + 1);
    assert!(matches!(
        validate_short_handle(&over_max),
        Err(HandleValidationError::TooLong {
            max: MAX_SERVICE_HANDLE_LOCAL_PART
        })
    ));
}

#[test]
fn test_handle_hyphen_positions() {
    assert!(validate_short_handle("a-b-c").is_ok());
    assert!(validate_short_handle("a--b").is_ok());
    assert!(validate_short_handle("---").is_err());
    assert!(matches!(
        validate_short_handle("-abc"),
        Err(HandleValidationError::StartsWithInvalidChar)
    ));
    assert!(matches!(
        validate_short_handle("abc-"),
        Err(HandleValidationError::EndsWithInvalidChar)
    ));
}

#[test]
fn test_handle_case_normalization() {
    assert_eq!(validate_short_handle("ABC").unwrap(), "abc");
    assert_eq!(validate_short_handle("AbC123").unwrap(), "abc123");
    assert_eq!(validate_short_handle("MixedCase").unwrap(), "mixedcase");
}

#[test]
fn test_handle_whitespace_handling() {
    assert_eq!(validate_short_handle("  abc  ").unwrap(), "abc");
    assert!(matches!(
        validate_short_handle("a b c"),
        Err(HandleValidationError::ContainsSpaces)
    ));
    assert!(matches!(
        validate_short_handle("a\tb"),
        Err(HandleValidationError::ContainsSpaces)
    ));
    assert!(matches!(
        validate_short_handle("a\nb"),
        Err(HandleValidationError::ContainsSpaces)
    ));
}
