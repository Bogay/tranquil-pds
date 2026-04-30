use std::time::Duration;

use chrono::Utc;
use lettre::message::Mailbox;
use lettre::transport::smtp::AsyncSmtpTransport;
use lettre::transport::smtp::extension::ClientId;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tranquil_comms::email::transport::SendMode;
use tranquil_comms::email::{EmailSender, types::HeloName};
use tranquil_comms::{CommsChannel, CommsSender, CommsStatus, CommsType, QueuedComms, SendError};
use uuid::Uuid;

fn fixture(recipient: &str, subject: &str, body: &str) -> QueuedComms {
    QueuedComms {
        id: Uuid::new_v4(),
        user_id: None,
        channel: CommsChannel::Email,
        comms_type: CommsType::Welcome,
        status: CommsStatus::Pending,
        recipient: recipient.to_string(),
        subject: Some(subject.to_string()),
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

fn build_smarthost_sender(host: &str, port: u16) -> EmailSender {
    build_smarthost_sender_with_total_timeout(host, port, Duration::from_secs(10))
}

fn build_smarthost_sender_with_total_timeout(
    host: &str,
    port: u16,
    total_timeout: Duration,
) -> EmailSender {
    let from: Mailbox = "Tranquil Test <noreply@nel.pet>".parse().unwrap();
    let helo = HeloName::parse("mta.nel.pet").unwrap();
    let transport = AsyncSmtpTransport::<lettre::Tokio1Executor>::builder_dangerous(host)
        .port(port)
        .hello_name(ClientId::Domain(helo.into_inner()))
        .timeout(Some(Duration::from_secs(5)))
        .build();
    EmailSender::new(
        from,
        SendMode::Smarthost {
            transport: Box::new(transport),
            total_timeout,
        },
        None,
    )
}

async fn drive_stub(stream: TcpStream, rcpt_response: &'static [u8]) -> std::io::Result<()> {
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);
    write.write_all(b"220 stub ESMTP\r\n").await?;
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            return Ok(());
        }
        let upper = line.to_ascii_uppercase();
        let response: &[u8] = match upper.split_whitespace().next() {
            Some("EHLO") | Some("HELO") => b"250-stub\r\n250 SIZE 10240000\r\n",
            Some("MAIL") => b"250 OK\r\n",
            Some("RCPT") => rcpt_response,
            Some("DATA") => b"354 end with .\r\n",
            Some("RSET") => b"250 OK\r\n",
            Some("QUIT") => b"221 bye\r\n",
            _ => b"500 unknown\r\n",
        };
        write.write_all(response).await?;
        if upper.starts_with("QUIT") {
            return Ok(());
        }
    }
}

async fn spawn_stub(rcpt_response: &'static [u8]) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let _ = drive_stub(stream, rcpt_response).await;
    });
    port
}

#[tokio::test]
async fn rcpt_550_classifies_as_smtp_permanent() {
    let port = spawn_stub(b"550 5.1.1 user unknown\r\n").await;
    let sender = build_smarthost_sender("127.0.0.1", port);
    let result = sender.send(&fixture("nel@nel.pet", "x", "x")).await;
    match result {
        Err(SendError::SmtpPermanent(_)) => {}
        other => panic!("expected SmtpPermanent, got {other:?}"),
    }
}

#[tokio::test]
async fn rcpt_421_classifies_as_smtp_transient() {
    let port = spawn_stub(b"421 4.7.0 try again later\r\n").await;
    let sender = build_smarthost_sender("127.0.0.1", port);
    let result = sender.send(&fixture("nel@nel.pet", "x", "x")).await;
    match result {
        Err(SendError::SmtpTransient(_)) => {}
        other => panic!("expected SmtpTransient, got {other:?}"),
    }
}

#[tokio::test]
async fn invalid_recipient_classifies_as_invalid_recipient() {
    let port = spawn_stub(b"250 OK\r\n").await;
    let sender = build_smarthost_sender("127.0.0.1", port);
    let result = sender.send(&fixture("not-an-address", "x", "x")).await;
    match result {
        Err(SendError::InvalidRecipient(_)) => {}
        other => panic!("expected InvalidRecipient, got {other:?}"),
    }
}

async fn spawn_silent_stub() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
        std::future::pending::<()>().await;
    });
    port
}

#[tokio::test]
async fn smarthost_silent_relay_hits_total_timeout() {
    let port = spawn_silent_stub().await;
    let sender =
        build_smarthost_sender_with_total_timeout("127.0.0.1", port, Duration::from_millis(500));
    let start = std::time::Instant::now();
    let result = sender.send(&fixture("nel@nel.pet", "x", "x")).await;
    let elapsed = start.elapsed();
    match result {
        Err(SendError::Timeout) => {}
        other => panic!("expected Timeout, got {other:?}"),
    }
    assert!(
        elapsed < Duration::from_secs(2),
        "send returned in {elapsed:?}, expected close to 500ms total_timeout"
    );
}
