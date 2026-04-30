use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use hickory_resolver::TokioAsyncResolver;
use lettre::transport::smtp::AsyncSmtpTransport;
use lettre::transport::smtp::Error as SmtpError;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::transport::smtp::extension::ClientId;
use lettre::{AsyncTransport, Message, Tokio1Executor};
use tokio::sync::Semaphore;

use super::message::recipient_domain;
use super::mx;
use super::types::{HeloName, MxRecord};
use crate::sender::SendError;

pub enum SendMode {
    Smarthost {
        transport: Box<AsyncSmtpTransport<Tokio1Executor>>,
        total_timeout: Duration,
    },
    DirectMx {
        resolver: Arc<TokioAsyncResolver>,
        helo: HeloName,
        command_timeout: Duration,
        total_timeout: Duration,
        require_tls: bool,
        inflight: Arc<Semaphore>,
    },
}

impl std::fmt::Debug for SendMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Smarthost { total_timeout, .. } => {
                write!(f, "SendMode::Smarthost(total_timeout={total_timeout:?})")
            }
            Self::DirectMx {
                helo, require_tls, ..
            } => write!(
                f,
                "SendMode::DirectMx({}, require_tls={require_tls})",
                helo.as_str()
            ),
        }
    }
}

pub async fn dispatch(mode: &SendMode, message: Message) -> Result<(), SendError> {
    match mode {
        SendMode::Smarthost {
            transport,
            total_timeout,
        } => with_total_timeout(*total_timeout, run_send(transport, message)).await,
        SendMode::DirectMx {
            resolver,
            helo,
            command_timeout,
            total_timeout,
            require_tls,
            inflight,
        } => {
            with_total_timeout(*total_timeout, async {
                let _permit =
                    inflight.clone().acquire_owned().await.map_err(|_| {
                        SendError::SmtpTransient("send semaphore closed".to_string())
                    })?;
                send_direct(
                    resolver.as_ref(),
                    helo,
                    *command_timeout,
                    *require_tls,
                    message,
                )
                .await
            })
            .await
        }
    }
}

async fn with_total_timeout<F: std::future::Future<Output = Result<(), SendError>>>(
    total: Duration,
    fut: F,
) -> Result<(), SendError> {
    tokio::time::timeout(total, fut)
        .await
        .unwrap_or(Err(SendError::Timeout))
}

async fn run_send(
    transport: &AsyncSmtpTransport<Tokio1Executor>,
    message: Message,
) -> Result<(), SendError> {
    transport
        .send(message)
        .await
        .map(|_| ())
        .map_err(classify_smtp_error)
}

async fn send_direct(
    resolver: &TokioAsyncResolver,
    helo: &HeloName,
    command_timeout: Duration,
    require_tls: bool,
    message: Message,
) -> Result<(), SendError> {
    let domain = recipient_domain(&message)?;
    let mxs = mx::resolve(resolver, &domain).await?;
    let outcome = futures::stream::iter(mxs)
        .fold(None::<Result<(), SendError>>, |acc, mx_record| {
            let message = message.clone();
            async move {
                match &acc {
                    Some(Ok(())) | Some(Err(SendError::SmtpPermanent(_))) => acc,
                    _ => Some(
                        attempt_one_host(mx_record, helo, command_timeout, require_tls, message)
                            .await,
                    ),
                }
            }
        })
        .await;
    outcome.unwrap_or_else(|| {
        Err(SendError::SmtpTransient(format!(
            "no MX records returned for {}",
            domain.as_str()
        )))
    })
}

async fn attempt_one_host(
    mx_record: MxRecord,
    helo: &HeloName,
    command_timeout: Duration,
    require_tls: bool,
    message: Message,
) -> Result<(), SendError> {
    let host = mx_record.host.as_str().to_string();
    let tls_params = TlsParameters::new(host.clone())
        .map_err(|e| SendError::SmtpTransient(format!("TLS params for {host}: {e}")))?;
    let tls = match require_tls {
        true => Tls::Required(tls_params),
        false => Tls::Opportunistic(tls_params),
    };
    let transport: AsyncSmtpTransport<Tokio1Executor> =
        AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&host)
            .port(25)
            .tls(tls)
            .hello_name(ClientId::Domain(helo.as_str().to_string()))
            .timeout(Some(command_timeout))
            .build();
    run_send(&transport, message).await
}

fn classify_smtp_error(e: SmtpError) -> SendError {
    match () {
        _ if e.is_permanent() => SendError::SmtpPermanent(e.to_string()),
        _ if e.is_timeout() => SendError::Timeout,
        _ => SendError::SmtpTransient(e.to_string()),
    }
}
