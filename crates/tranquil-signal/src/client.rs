use std::fmt;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use presage::libsignal_service::configuration::SignalServers;
use presage::manager::Registered;
use presage::proto::DataMessage;
use presage::store::Store;
use sqlx::PgPool;
use tokio::sync::{RwLock, mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::store::PgSignalStore;

#[derive(Debug, Clone)]
pub struct SignalUsername(String);

#[derive(Debug, Clone)]
pub struct InvalidSignalUsername(String);

impl fmt::Display for InvalidSignalUsername {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid signal username: {}", self.0)
    }
}

impl std::error::Error for InvalidSignalUsername {}

impl SignalUsername {
    pub fn parse(username: &str) -> Result<Self, InvalidSignalUsername> {
        let reject = || Err(InvalidSignalUsername(username.to_string()));

        let Some((base, discriminator)) = username.rsplit_once('.') else {
            return reject();
        };

        if !matches!(base.len(), 3..=32) {
            return reject();
        }

        if !base.chars().next().is_some_and(|c| c.is_ascii_alphabetic()) {
            return reject();
        }

        if !base.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return reject();
        }

        if !is_valid_discriminator(discriminator) {
            return reject();
        }

        Ok(Self(username.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn is_valid_discriminator(s: &str) -> bool {
    if !s.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    if !matches!(s.len(), 2..=20) {
        return false;
    }
    if s.len() > 2 && s.starts_with('0') {
        return false;
    }
    s.parse::<u64>().is_ok_and(|n| n != 0)
}

impl fmt::Display for SignalUsername {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone)]
pub struct DeviceName(String);

#[derive(Debug, Clone)]
pub struct InvalidDeviceName(String);

impl fmt::Display for InvalidDeviceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid device name: {}", self.0)
    }
}

impl std::error::Error for InvalidDeviceName {}

impl DeviceName {
    pub fn new(name: String) -> Result<Self, InvalidDeviceName> {
        if name.is_empty() || name.len() > 50 || !name.is_ascii() {
            return Err(InvalidDeviceName(name));
        }
        Ok(Self(name))
    }

    fn into_inner(self) -> String {
        self.0
    }
}

const LINK_TIMEOUT: Duration = Duration::from_secs(120);
const SEND_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_MESSAGE_BYTES: usize = 2000;

#[derive(Debug, Clone)]
pub struct MessageBody(String);

#[derive(Debug, Clone)]
pub struct MessageTooLong {
    pub len: usize,
    pub max: usize,
}

impl fmt::Display for MessageTooLong {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "message body is {} bytes, max {}",
            self.len, self.max
        )
    }
}

impl std::error::Error for MessageTooLong {}

impl MessageBody {
    pub fn new(body: String) -> Result<Self, MessageTooLong> {
        let len = body.len();
        if len > MAX_MESSAGE_BYTES {
            return Err(MessageTooLong {
                len,
                max: MAX_MESSAGE_BYTES,
            });
        }
        Ok(Self(body))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkGeneration(u64);

impl LinkGeneration {
    fn next(self) -> Self {
        Self(self.0.wrapping_add(1))
    }
}

fn log_panic(thread_name: &str, payload: Box<dyn std::any::Any + Send>) {
    let msg = payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(|s| s.as_str()))
        .unwrap_or("unknown panic");
    tracing::error!(thread = thread_name, panic = msg, "signal thread panicked");
}

fn spawn_signal_thread(
    name: &'static str,
    f: impl FnOnce() + Send + 'static,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            if let Err(e) = std::panic::catch_unwind(AssertUnwindSafe(f)) {
                log_panic(name, e);
            }
        })
}

fn signal_local_block_on(fut: impl std::future::Future<Output = ()>) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("signal runtime");
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, fut);
}

struct LinkingGuard(Arc<AtomicBool>);

impl Drop for LinkingGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SignalError {
    #[error("store: {0}")]
    Store(String),
    #[error("presage: {0}")]
    Presage(String),
    #[error("username lookup failed: {0}")]
    UsernameLookup(String),
    #[error("username not found: {0}")]
    UsernameNotFound(String),
    #[error("linking: {0}")]
    Linking(String),
    #[error("linking timed out")]
    LinkingTimeout,
    #[error("linking cancelled")]
    LinkingCancelled,
    #[error("not linked")]
    NotLinked,
    #[error("runtime: {0}")]
    Runtime(String),
}

impl From<crate::store::PgStoreError> for SignalError {
    fn from(e: crate::store::PgStoreError) -> Self {
        Self::Store(e.to_string())
    }
}

struct SendRequest {
    recipient: SignalUsername,
    message: MessageBody,
    reply: oneshot::Sender<Result<(), SignalError>>,
}

pub struct LinkResult {
    pub url: Url,
    pub completion: oneshot::Receiver<Result<SignalClient, SignalError>>,
}

pub struct SignalSlot {
    state: RwLock<SlotState>,
    linking_in_progress: Arc<AtomicBool>,
}

struct SlotState {
    client: Option<SignalClient>,
    generation: LinkGeneration,
    link_cancel: Option<CancellationToken>,
}

impl Default for SignalSlot {
    fn default() -> Self {
        Self {
            state: RwLock::new(SlotState {
                client: None,
                generation: LinkGeneration(0),
                link_cancel: None,
            }),
            linking_in_progress: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl SignalSlot {
    pub async fn client(&self) -> Option<SignalClient> {
        let client = self.state.read().await.client.clone()?;
        if client.is_alive() {
            Some(client)
        } else {
            tracing::warn!("signal worker exited unexpectedly, clearing client");
            self.state.write().await.client = None;
            None
        }
    }

    pub async fn is_linked(&self) -> bool {
        self.state
            .read()
            .await
            .client
            .as_ref()
            .is_some_and(SignalClient::is_alive)
    }

    pub async fn set_client(&self, client: SignalClient) {
        self.state.write().await.client = Some(client);
    }

    pub fn linking_flag(&self) -> Arc<AtomicBool> {
        self.linking_in_progress.clone()
    }

    pub async fn begin_link(&self) -> (LinkGeneration, CancellationToken) {
        let mut guard = self.state.write().await;
        if let Some(old) = guard.link_cancel.take() {
            old.cancel();
        }
        let token = CancellationToken::new();
        guard.link_cancel = Some(token.clone());
        (guard.generation, token)
    }

    pub async fn complete_link(&self, generation: LinkGeneration, client: SignalClient) -> bool {
        let mut guard = self.state.write().await;
        if guard.generation != generation || guard.client.is_some() {
            return false;
        }
        guard.client = Some(client);
        guard.link_cancel = None;
        true
    }

    pub async fn unlink(&self) {
        let mut guard = self.state.write().await;
        guard.client = None;
        guard.generation = guard.generation.next();
        if let Some(cancel) = guard.link_cancel.take() {
            cancel.cancel();
        }
    }
}

#[derive(Clone)]
pub struct SignalClient {
    tx: mpsc::Sender<SendRequest>,
}

impl SignalClient {
    fn from_manager<S: Store>(
        manager: presage::Manager<S, Registered>,
        shutdown: CancellationToken,
    ) -> Result<Self, SignalError> {
        let (tx, rx) = mpsc::channel::<SendRequest>(64);

        spawn_signal_thread("signal-worker", move || {
            signal_local_block_on(Self::worker_loop(manager, rx, shutdown));
        })
        .map_err(|e| SignalError::Runtime(format!("failed to spawn signal worker: {e}")))?;

        Ok(Self { tx })
    }

    pub async fn from_store<S: Store>(store: S, shutdown: CancellationToken) -> Option<Self> {
        let (init_tx, init_rx) = oneshot::channel();

        spawn_signal_thread("signal-init", move || {
            signal_local_block_on(async {
                let result = presage::Manager::load_registered(store).await;
                init_tx
                    .send(result.map_err(|e| SignalError::Presage(e.to_string())))
                    .ok();
            });
        })
        .map_err(|e| tracing::error!(error = %e, "failed to spawn signal init thread"))
        .ok()?;

        let manager = init_rx
            .await
            .ok()?
            .map_err(|e| tracing::error!(error = %e, "failed to load registered signal manager"))
            .ok()?;

        Self::from_manager(manager, shutdown)
            .map_err(|e| tracing::error!(error = %e, "failed to start signal worker"))
            .ok()
    }

    pub async fn from_pool(db: &PgPool, shutdown: CancellationToken) -> Option<Self> {
        Self::from_store(PgSignalStore::new(db.clone()), shutdown).await
    }

    async fn worker_loop<S: Store>(
        mut manager: presage::Manager<S, Registered>,
        mut rx: mpsc::Receiver<SendRequest>,
        shutdown: CancellationToken,
    ) {
        loop {
            let req = tokio::select! {
                biased;
                _ = shutdown.cancelled() => {
                    tracing::info!("signal worker cancelled, shutting down");
                    break;
                }
                msg = rx.recv() => match msg {
                    Some(r) => r,
                    None => {
                        tracing::info!("signal worker channel closed, shutting down");
                        break;
                    }
                },
            };
            let result = match tokio::time::timeout(
                SEND_TIMEOUT,
                Self::handle_send(&mut manager, &req.recipient, &req.message),
            )
            .await
            {
                Ok(r) => r,
                Err(_) => {
                    tracing::error!(
                        recipient = %req.recipient,
                        "signal send timed out after {}s",
                        SEND_TIMEOUT.as_secs()
                    );
                    Err(SignalError::Runtime(format!(
                        "send timed out after {}s",
                        SEND_TIMEOUT.as_secs()
                    )))
                }
            };
            req.reply.send(result).ok();
        }
    }

    async fn handle_send<S: Store>(
        manager: &mut presage::Manager<S, Registered>,
        recipient: &SignalUsername,
        message: &MessageBody,
    ) -> Result<(), SignalError> {
        let aci = manager
            .lookup_username(recipient.as_str())
            .await
            .map_err(|e| SignalError::UsernameLookup(e.to_string()))?
            .ok_or_else(|| SignalError::UsernameNotFound(recipient.to_string()))?;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .map_err(|_| SignalError::Runtime("system clock is before unix epoch".into()))?;

        let data_message = DataMessage {
            body: Some(message.as_str().to_string()),
            timestamp: Some(timestamp),
            ..Default::default()
        };

        manager
            .send_message(aci, data_message, timestamp)
            .await
            .map_err(|e| SignalError::Presage(e.to_string()))
    }

    pub fn is_alive(&self) -> bool {
        !self.tx.is_closed()
    }

    pub async fn send(
        &self,
        recipient: &SignalUsername,
        message: MessageBody,
    ) -> Result<(), SignalError> {
        let (reply_tx, reply_rx) = oneshot::channel();

        self.tx
            .send(SendRequest {
                recipient: recipient.clone(),
                message,
                reply: reply_tx,
            })
            .await
            .map_err(|_| SignalError::Runtime("signal worker thread exited".into()))?;

        reply_rx
            .await
            .map_err(|_| SignalError::Runtime("signal worker dropped request".into()))?
    }

    pub async fn link_device_with_store<S: Store>(
        store: S,
        device_name: DeviceName,
        shutdown: CancellationToken,
        link_cancel: CancellationToken,
        linking_flag: Arc<AtomicBool>,
    ) -> Result<LinkResult, SignalError> {
        if linking_flag.swap(true, Ordering::AcqRel) {
            return Err(SignalError::Linking(
                "device linking already in progress".into(),
            ));
        }

        let (url_tx, url_rx) = oneshot::channel::<Result<Url, SignalError>>();
        let (done_tx, done_rx) = oneshot::channel::<Result<SignalClient, SignalError>>();

        let guard_flag = linking_flag.clone();
        let spawn_result = spawn_signal_thread("signal-link", move || {
            let _guard = LinkingGuard(guard_flag);
            signal_local_block_on(async {
                let (prov_tx, prov_rx) = futures::channel::oneshot::channel();

                let link_future = presage::Manager::link_secondary_device(
                    store,
                    SignalServers::Production,
                    device_name.into_inner(),
                    prov_tx,
                );

                let url_forward = async {
                    match prov_rx.await {
                        Ok(url) => {
                            url_tx.send(Ok(url)).ok();
                        }
                        Err(e) => {
                            url_tx.send(Err(SignalError::Linking(e.to_string()))).ok();
                        }
                    }
                };

                let link_result = tokio::select! {
                    biased;
                    _ = link_cancel.cancelled() => {
                        tracing::info!("signal device linking cancelled");
                        done_tx.send(Err(SignalError::LinkingCancelled)).ok();
                        return;
                    }
                    r = tokio::time::timeout(LINK_TIMEOUT, async {
                        let (link_res, _) =
                            futures::future::join(link_future, url_forward).await;
                        link_res
                    }) => r,
                };

                match link_result {
                    Ok(Ok(manager)) => {
                        let client_result = SignalClient::from_manager(manager, shutdown);
                        done_tx.send(client_result).ok();
                    }
                    Ok(Err(e)) => {
                        tracing::error!(error = %e, "signal device linking failed");
                        done_tx.send(Err(SignalError::Linking(e.to_string()))).ok();
                    }
                    Err(_) => {
                        tracing::error!(
                            "signal device linking timed out after {}s",
                            LINK_TIMEOUT.as_secs()
                        );
                        done_tx.send(Err(SignalError::LinkingTimeout)).ok();
                    }
                }
            });
        });

        match spawn_result {
            Ok(_) => {}
            Err(e) => {
                linking_flag.store(false, Ordering::Release);
                return Err(SignalError::Runtime(format!(
                    "failed to spawn link thread: {e}"
                )));
            }
        }

        let url = url_rx
            .await
            .map_err(|_| SignalError::Runtime("signal link thread exited".into()))??;

        Ok(LinkResult {
            url,
            completion: done_rx,
        })
    }

    pub async fn link_device(
        db: &PgPool,
        device_name: DeviceName,
        shutdown: CancellationToken,
        link_cancel: CancellationToken,
        linking_flag: Arc<AtomicBool>,
    ) -> Result<LinkResult, SignalError> {
        Self::link_device_with_store(
            PgSignalStore::new(db.clone()),
            device_name,
            shutdown,
            link_cancel,
            linking_flag,
        )
        .await
    }
}
