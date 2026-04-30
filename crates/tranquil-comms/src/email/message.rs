use lettre::Message;
use lettre::message::Mailbox;
use lettre::message::header::ContentType;
use uuid::Uuid;

use super::types::EmailDomain;
use crate::sender::SendError;
use crate::types::QueuedComms;

pub(super) fn build(from: &Mailbox, qc: &QueuedComms) -> Result<Message, SendError> {
    let to: Mailbox = qc
        .recipient
        .parse()
        .map_err(|e: lettre::address::AddressError| SendError::InvalidRecipient(e.to_string()))?;
    let subject = qc.subject.as_deref().unwrap_or("Notification");
    let message_id = format!("<{}@{}>", Uuid::new_v4(), from.email.domain());
    Message::builder()
        .from(from.clone())
        .to(to)
        .subject(subject)
        .message_id(Some(message_id))
        .header(ContentType::TEXT_PLAIN)
        .body(qc.body.clone())
        .map_err(|e| SendError::MessageBuild(e.to_string()))
}

pub(super) fn recipient_domain(message: &Message) -> Result<EmailDomain, SendError> {
    let envelope = message.envelope();
    let first = envelope
        .to()
        .first()
        .ok_or_else(|| SendError::MessageBuild("envelope has no recipients".to_string()))?;
    EmailDomain::parse(first.domain())
        .map_err(|e| SendError::InvalidRecipient(format!("invalid recipient domain: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{CommsChannel, CommsStatus, CommsType};
    use chrono::Utc;
    use uuid::Uuid;

    fn from_mailbox() -> Mailbox {
        "Test Sender <noreply@nel.pet>".parse().unwrap()
    }

    fn fixture(recipient: &str, subject: Option<&str>, body: &str) -> QueuedComms {
        QueuedComms {
            id: Uuid::new_v4(),
            user_id: None,
            channel: CommsChannel::Email,
            comms_type: CommsType::Welcome,
            status: CommsStatus::Pending,
            recipient: recipient.to_string(),
            subject: subject.map(String::from),
            body: body.to_string(),
            metadata: None,
            attempts: 0,
            max_attempts: 3,
            last_error: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            scheduled_for: Utc::now(),
            processed_at: None,
        }
    }

    #[test]
    fn build_basic_message() {
        let msg = build(
            &from_mailbox(),
            &fixture("user@nel.pet", Some("Welcome"), "Hello world."),
        )
        .unwrap();
        let raw = String::from_utf8(msg.formatted()).unwrap();
        let lower = raw.to_lowercase();
        assert!(raw.contains("From: \"Test Sender\" <noreply@nel.pet>"));
        assert!(raw.contains("To: user@nel.pet"));
        assert!(raw.contains("Subject: Welcome"));
        assert!(lower.contains("content-type: text/plain"));
        assert!(raw.contains("Hello world."));
    }

    #[test]
    fn utf8_subject_is_encoded() {
        let msg = build(
            &from_mailbox(),
            &fixture("user@nel.pet", Some("héllo wörld"), "Body"),
        )
        .unwrap();
        let raw = String::from_utf8(msg.formatted()).unwrap();
        assert!(raw.contains("=?utf-8?"));
        assert!(!raw.contains("héllo"));
    }

    #[test]
    fn header_injection_rejected() {
        let result = build(
            &from_mailbox(),
            &fixture("x@nel.pet\r\nBcc: evil@x", Some("s"), "b"),
        );
        assert!(matches!(result, Err(SendError::InvalidRecipient(_))));
    }

    #[test]
    fn subject_crlf_does_not_inject_headers() {
        let msg = build(
            &from_mailbox(),
            &fixture("user@nel.pet", Some("hi\r\nBcc: evil@nel.pet"), "body"),
        )
        .expect("subject CRLF should be encoded, not rejected");
        let raw = String::from_utf8(msg.formatted()).unwrap();
        assert!(
            !raw.contains("Bcc:"),
            "CRLF in subject must not produce a Bcc header: {raw}"
        );
        assert!(
            raw.contains("Subject: ="),
            "subject with non-printable chars should be RFC 2047 encoded: {raw}"
        );
    }

    #[test]
    fn message_id_uses_from_domain() {
        let msg = build(&from_mailbox(), &fixture("user@nel.pet", Some("s"), "b")).unwrap();
        let raw = String::from_utf8(msg.formatted()).unwrap();
        let line = raw
            .lines()
            .find(|l| l.starts_with("Message-ID:") || l.starts_with("Message-Id:"))
            .expect("message-id header present");
        assert!(
            line.contains("@nel.pet>"),
            "message-id should use From domain: {line}"
        );
    }

    #[test]
    fn missing_subject_uses_default() {
        let msg = build(&from_mailbox(), &fixture("user@nel.pet", None, "Body")).unwrap();
        let raw = String::from_utf8(msg.formatted()).unwrap();
        assert!(raw.contains("Subject: Notification"));
    }

    #[test]
    fn recipient_domain_extracted() {
        let msg = build(&from_mailbox(), &fixture("user@Nel.PET", Some("s"), "b")).unwrap();
        let d = recipient_domain(&msg).unwrap();
        assert_eq!(d.as_str(), "nel.pet");
    }
}
