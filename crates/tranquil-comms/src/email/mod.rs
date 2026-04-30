pub mod dkim;
pub mod message;
mod mx;
pub mod transport;
pub mod types;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use hickory_resolver::TokioAsyncResolver;
use lettre::message::Mailbox;
use lettre::transport::smtp::AsyncSmtpTransport;
use lettre::transport::smtp::PoolConfig;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::extension::ClientId;
use tokio::sync::Semaphore;
use tracing::{info, warn};

pub use self::dkim::DkimSigner;
pub use self::transport::SendMode;
use self::types::{
    DkimKeyPath, DkimSelector, EmailDomain, HeloName, SmtpHost, SmtpPassword, SmtpPort,
    SmtpUsername, TlsMode,
};
use crate::sender::{CommsSender, SendError};
use crate::types::{CommsChannel, QueuedComms};

pub struct EmailSender {
    from: Mailbox,
    mode: SendMode,
    dkim: Option<DkimSigner>,
}

impl EmailSender {
    pub fn new(from: Mailbox, mode: SendMode, dkim: Option<DkimSigner>) -> Self {
        Self { from, mode, dkim }
    }

    pub fn from_config(cfg: &tranquil_config::TranquilConfig) -> Result<Option<Self>, SendError> {
        let Some(from_address) = cfg.email.from_address.as_deref().filter(|s| !s.is_empty()) else {
            info!("Email sender disabled: MAIL_FROM_ADDRESS unset");
            return Ok(None);
        };
        let from = build_from(&cfg.email.from_name, from_address)?;
        let dkim = build_dkim(&cfg.email.dkim)?;
        let mode = match cfg
            .email
            .smarthost
            .host
            .as_deref()
            .filter(|h| !h.is_empty())
        {
            Some(host) => build_smarthost(cfg, host)?,
            None => build_direct_mx(cfg)?,
        };
        info!(?mode, dkim = dkim.is_some(), "Email sender initialized");
        Ok(Some(Self { from, mode, dkim }))
    }
}

fn config_invalid(field: &str, error: impl std::fmt::Display) -> SendError {
    SendError::ConfigInvalid(format!("{field}: {error}"))
}

fn build_from(from_name: &str, from_address: &str) -> Result<Mailbox, SendError> {
    let raw = match from_name.is_empty() {
        true => from_address.to_string(),
        false => format!("\"{}\" <{}>", from_name.replace('"', "'"), from_address),
    };
    raw.parse::<Mailbox>()
        .map_err(|e| config_invalid("MAIL_FROM_ADDRESS / MAIL_FROM_NAME", e))
}

fn build_smarthost(
    cfg: &tranquil_config::TranquilConfig,
    host_raw: &str,
) -> Result<SendMode, SendError> {
    let host = SmtpHost::parse(host_raw).map_err(|e| config_invalid("MAIL_SMARTHOST_HOST", e))?;
    let port = SmtpPort::parse(cfg.email.smarthost.port)
        .map_err(|e| config_invalid("MAIL_SMARTHOST_PORT", e))?;
    let tls = TlsMode::parse(&cfg.email.smarthost.tls)
        .map_err(|e| config_invalid("MAIL_SMARTHOST_TLS", e))?;
    let helo = resolve_helo(cfg)?;
    let pool = PoolConfig::new()
        .max_size(cfg.email.smarthost.pool_size)
        .idle_timeout(Duration::from_secs(60));
    let command_timeout = Duration::from_secs(cfg.email.smarthost.command_timeout_secs);
    let total_timeout = Duration::from_secs(cfg.email.smarthost.total_timeout_secs);

    let builder = match tls {
        TlsMode::Implicit => AsyncSmtpTransport::<lettre::Tokio1Executor>::relay(host.as_str())
            .map_err(|e| config_invalid("smarthost TLS setup", e))?,
        TlsMode::Starttls => {
            AsyncSmtpTransport::<lettre::Tokio1Executor>::starttls_relay(host.as_str())
                .map_err(|e| config_invalid("smarthost TLS setup", e))?
        }
        TlsMode::None => {
            AsyncSmtpTransport::<lettre::Tokio1Executor>::builder_dangerous(host.as_str())
        }
    };
    let builder = builder
        .port(port.as_u16())
        .hello_name(ClientId::Domain(helo.into_inner()))
        .timeout(Some(command_timeout))
        .pool_config(pool);
    let builder = match (
        cfg.email.smarthost.username.as_deref(),
        cfg.email.smarthost.password.as_deref(),
    ) {
        (Some(u), Some(p)) => {
            let username =
                SmtpUsername::parse(u).map_err(|e| config_invalid("MAIL_SMARTHOST_USERNAME", e))?;
            let password =
                SmtpPassword::parse(p).map_err(|e| config_invalid("MAIL_SMARTHOST_PASSWORD", e))?;
            builder.credentials(Credentials::new(
                username.into_inner(),
                password.expose().to_string(),
            ))
        }
        _ => builder,
    };
    Ok(SendMode::Smarthost {
        transport: Box::new(builder.build()),
        total_timeout,
    })
}

fn build_direct_mx(cfg: &tranquil_config::TranquilConfig) -> Result<SendMode, SendError> {
    let helo = resolve_helo(cfg)?;
    let resolver = TokioAsyncResolver::tokio_from_system_conf()
        .map(Arc::new)
        .map_err(|e| config_invalid("system DNS configuration", e))?;
    let max_concurrent = cfg.email.direct_mx.max_concurrent_sends.max(1);
    Ok(SendMode::DirectMx {
        resolver,
        helo,
        command_timeout: Duration::from_secs(cfg.email.direct_mx.command_timeout_secs),
        total_timeout: Duration::from_secs(cfg.email.direct_mx.total_timeout_secs),
        require_tls: cfg.email.direct_mx.require_tls,
        inflight: Arc::new(Semaphore::new(max_concurrent)),
    })
}

fn resolve_helo(cfg: &tranquil_config::TranquilConfig) -> Result<HeloName, SendError> {
    let raw = cfg
        .email
        .helo_name
        .clone()
        .unwrap_or_else(|| cfg.server.hostname_without_port().to_string());
    HeloName::parse(&raw).map_err(|e| config_invalid(&format!("HELO name {raw:?}"), e))
}

fn build_dkim(cfg: &tranquil_config::DkimConfig) -> Result<Option<DkimSigner>, SendError> {
    let selector = match cfg.selector.as_deref() {
        Some(s) => s,
        None => return Ok(None),
    };
    let domain = cfg
        .domain
        .as_deref()
        .ok_or_else(|| SendError::DkimSign("MAIL_DKIM_DOMAIN required when selector set".into()))?;
    let key_path = cfg.private_key_path.as_deref().ok_or_else(|| {
        SendError::DkimSign("MAIL_DKIM_KEY_PATH required when selector set".into())
    })?;
    let selector = DkimSelector::parse(selector)
        .map_err(|e| SendError::DkimSign(format!("invalid DKIM selector: {e}")))?;
    let domain = EmailDomain::parse(domain)
        .map_err(|e| SendError::DkimSign(format!("invalid DKIM domain: {e}")))?;
    let path = DkimKeyPath::parse(key_path)
        .map_err(|e| SendError::DkimSign(format!("DKIM key path invalid: {e}")))?;
    DkimSigner::load(selector, domain, path).map(Some)
}

#[async_trait]
impl CommsSender for EmailSender {
    fn channel(&self) -> CommsChannel {
        CommsChannel::Email
    }

    async fn send(&self, notification: &QueuedComms) -> Result<(), SendError> {
        let mut message = message::build(&self.from, notification)?;
        if let Some(signer) = &self.dkim {
            signer.sign(&mut message);
        }
        match transport::dispatch(&self.mode, message).await {
            Ok(()) => Ok(()),
            Err(e) => {
                warn!(comms_id = %notification.id, error = %e, "SMTP send failed");
                Err(e)
            }
        }
    }
}
