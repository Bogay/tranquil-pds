mod common;
use tranquil_pds::comms::{
    SendError, is_valid_phone_number, is_valid_signal_username, sanitize_header_value,
};
use tranquil_pds::image::{ImageError, ImageProcessor};

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
    assert!(
        sanitized.contains("Normal Subject")
            && sanitized.contains("Bcc:")
            && sanitized.contains("X-Injected:")
    );

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

    for malicious in [
        "+123; rm -rf /",
        "+123 && cat /etc/passwd",
        "+123`id`",
        "+123$(whoami)",
        "+123|cat /etc/shadow",
        "+123\n--help",
        "+123\r\n--version",
        "+123--help",
    ] {
        assert!(
            !is_valid_phone_number(malicious),
            "Command injection '{}' should be rejected",
            malicious
        );
    }
}

#[test]
fn test_signal_username_validation() {
    assert!(is_valid_signal_username("alice.01"));
    assert!(is_valid_signal_username("bob_smith.99"));
    assert!(is_valid_signal_username("user123.42"));
    assert!(is_valid_signal_username("lu1.01"));
    assert!(is_valid_signal_username("abc.00"));
    assert!(is_valid_signal_username("a_very_long_username_here.55"));

    assert!(!is_valid_signal_username("alice"));
    assert!(!is_valid_signal_username("alice.1"));
    assert!(!is_valid_signal_username("alice.001"));
    assert!(!is_valid_signal_username(".01"));
    assert!(!is_valid_signal_username("ab.01"));
    assert!(!is_valid_signal_username(""));
    assert!(!is_valid_signal_username("1alice.01"));
    assert!(!is_valid_signal_username("alice!.01"));
    assert!(!is_valid_signal_username("alice .01"));

    assert!(!is_valid_signal_username("a".repeat(33).as_str()));

    [
        "alice.01; rm -rf /",
        "bob.01 && cat /etc/passwd",
        "user.01`id`",
        "test.01$(whoami)",
    ]
    .iter()
    .for_each(|malicious| {
        assert!(
            !is_valid_signal_username(malicious),
            "Command injection '{}' should be rejected",
            malicious
        );
    });
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

    let res = http_client
        .get(format!("{}/xrpc/com.atproto.temp.checkSignupQueue", base))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["activated"], true);

    let (token, _did) = create_account_and_login(&http_client).await;
    let res = http_client
        .get(format!("{}/xrpc/com.atproto.temp.checkSignupQueue", base))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["activated"], true);
}
