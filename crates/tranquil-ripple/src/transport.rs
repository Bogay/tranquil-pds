use backon::{ExponentialBuilder, Retryable};
use hkdf::Hkdf;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{
    ClientConfig, Connection, Endpoint, IdleTimeout, RecvStream, ServerConfig, TransportConfig,
    VarInt,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::Sha256;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch};
use tokio_util::sync::CancellationToken;

pub(crate) const MAX_FRAME_SIZE: usize = 4 * 1024 * 1024;
const MAX_INBOUND_CONNECTIONS: usize = 512;
const MAX_OUTBOUND_CONNECTIONS: usize = 512;
const MAX_QUEUED_WRITES: usize = 1024;
const MAX_CONCURRENT_UNI_STREAMS: u32 = 64;
const INBOUND_BYTE_BUDGET: usize = 128 * 1024 * 1024;
const MAX_READS_PER_PEER: usize = 32;
const READ_CHUNK_BYTES: usize = 256 * 1024;
const INCOMING_CHANNEL_DEPTH: usize = 1024;
const STREAM_RECEIVE_WINDOW: u32 = MAX_FRAME_SIZE as u32;
const CONNECTION_RECEIVE_WINDOW: u32 = 16 * 1024 * 1024;
const KEEPALIVE: Duration = Duration::from_secs(20);
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_JOIN_TIMEOUT: Duration = Duration::from_secs(30);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const READ_TIMEOUT: Duration = Duration::from_secs(30);
const RIPPLE_ALPN: &[u8] = b"ripple/1";
const RIPPLE_SERVER_NAME: &str = "ripple";
const CLUSTER_HKDF_SALT: &[u8] = b"ripple-cluster-identity-v1";
const CLUSTER_HKDF_INFO: &[u8] = b"ripple-node-ed25519";
const ED25519_PKCS8_V1_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

#[derive(Clone)]
pub struct ClusterKey(Arc<str>);

impl ClusterKey {
    pub fn new(secret: impl Into<Arc<str>>) -> Self {
        Self(secret.into())
    }
}

struct NodeIdentity {
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ChannelTag {
    Gossip = 0x01,
    CrdtSync = 0x02,
}

impl ChannelTag {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Gossip),
            0x02 => Some(Self::CrdtSync),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct IncomingFrame {
    pub from: SocketAddr,
    pub tag: ChannelTag,
    pub data: Vec<u8>,
    _budget: OwnedSemaphorePermit,
}

struct PeerConn {
    conn: Connection,
    generation: u64,
}

type ConnectingMap = Arc<parking_lot::Mutex<HashMap<SocketAddr, watch::Receiver<bool>>>>;

struct ConnectingGuard {
    connecting: ConnectingMap,
    target: SocketAddr,
}

impl Drop for ConnectingGuard {
    fn drop(&mut self) {
        self.connecting.lock().remove(&self.target);
    }
}

pub struct Transport {
    endpoint: Endpoint,
    local_addr: SocketAddr,
    connections: Arc<parking_lot::Mutex<HashMap<SocketAddr, PeerConn>>>,
    connecting: ConnectingMap,
    conn_generation: Arc<AtomicU64>,
    outbound_permits: Arc<Semaphore>,
    queue_permits: Arc<Semaphore>,
    inbound_byte_budget: Arc<Semaphore>,
    peer_read_limiter: PeerReadLimiter,
    shutdown: CancellationToken,
    incoming_tx: mpsc::Sender<IncomingFrame>,
}

impl Transport {
    pub async fn bind(
        addr: SocketAddr,
        cluster_key: Option<ClusterKey>,
        shutdown: CancellationToken,
    ) -> Result<(Self, mpsc::Receiver<IncomingFrame>), std::io::Error> {
        let identity = match &cluster_key {
            Some(key) => Some(
                derive_identity(key)
                    .map_err(|e| std::io::Error::other(format!("ripple cluster identity: {e}")))?,
            ),
            None => {
                if !addr.ip().is_loopback() {
                    tracing::warn!(
                        addr = %addr,
                        "ripple peer authentication disabled, set RIPPLE_CLUSTER_KEY to authenticate the cluster"
                    );
                }
                None
            }
        };

        let server_config = build_server_config(identity.as_ref())
            .map_err(|e| std::io::Error::other(format!("ripple server config: {e}")))?;
        let client_config = build_client_config(identity.as_ref())
            .map_err(|e| std::io::Error::other(format!("ripple client config: {e}")))?;

        let mut endpoint = Endpoint::server(server_config, addr)?;
        endpoint.set_default_client_config(client_config);
        let local_addr = endpoint.local_addr()?;
        let (incoming_tx, incoming_rx) = mpsc::channel(INCOMING_CHANNEL_DEPTH);
        let inbound_byte_budget = Arc::new(Semaphore::new(INBOUND_BYTE_BUDGET));
        let peer_read_limiter = PeerReadLimiter::new(MAX_READS_PER_PEER);

        let transport = Self {
            endpoint: endpoint.clone(),
            local_addr,
            connections: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            connecting: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            conn_generation: Arc::new(AtomicU64::new(0)),
            outbound_permits: Arc::new(Semaphore::new(MAX_OUTBOUND_CONNECTIONS)),
            queue_permits: Arc::new(Semaphore::new(MAX_QUEUED_WRITES)),
            inbound_byte_budget: inbound_byte_budget.clone(),
            peer_read_limiter: peer_read_limiter.clone(),
            shutdown: shutdown.clone(),
            incoming_tx: incoming_tx.clone(),
        };

        let inbound_permits = Arc::new(Semaphore::new(MAX_INBOUND_CONNECTIONS));
        let cancel = shutdown.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    incoming = endpoint.accept() => {
                        let Some(incoming) = incoming else { break };
                        if !incoming.remote_address_validated() {
                            let _ = incoming.retry();
                            continue;
                        }
                        let Ok(permit) = inbound_permits.clone().try_acquire_owned() else {
                            tracing::warn!(
                                peer = %incoming.remote_address(),
                                max = MAX_INBOUND_CONNECTIONS,
                                "rejecting inbound connection: limit reached"
                            );
                            incoming.refuse();
                            continue;
                        };
                        let tx = incoming_tx.clone();
                        let byte_budget = inbound_byte_budget.clone();
                        let limiter = peer_read_limiter.clone();
                        let conn_cancel = cancel.child_token();
                        tokio::spawn(async move {
                            let _permit = permit;
                            match incoming.await {
                                Ok(conn) => {
                                    let from = conn.remote_address();
                                    tracing::debug!(peer = %from, "accepted inbound connection");
                                    run_conn_reader(conn, from, tx, byte_budget, limiter, conn_cancel)
                                        .await;
                                }
                                Err(e) => tracing::warn!(error = %e, "inbound handshake failed"),
                            }
                        });
                    }
                }
            }
            endpoint.close(0u32.into(), b"shutdown");
        });

        tracing::info!(
            addr = %local_addr,
            authenticated = identity.is_some(),
            "ripple quic transport bound"
        );
        Ok((transport, incoming_rx))
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn try_queue(&self, target: SocketAddr, tag: ChannelTag, data: &[u8]) -> bool {
        let conn = self.connections.lock().get(&target).map(|p| p.conn.clone());
        let Some(conn) = conn else { return false };
        let Ok(permit) = self.queue_permits.clone().try_acquire_owned() else {
            return false;
        };
        let data = data.to_vec();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = write_frame(&conn, tag, &data).await {
                tracing::debug!(error = %e, "queued write failed");
            }
        });
        true
    }

    pub async fn send(&self, target: SocketAddr, tag: ChannelTag, data: &[u8]) {
        let Ok(permit) = self.queue_permits.clone().acquire_owned().await else {
            return;
        };
        let existing = self
            .connections
            .lock()
            .get(&target)
            .map(|p| (p.conn.clone(), p.generation));
        if let Some((conn, generation)) = existing {
            match write_frame(&conn, tag, data).await {
                Ok(()) => return,
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                    tracing::debug!(peer = %target, "write timed out, keeping connection");
                    return;
                }
                Err(_) => {
                    let mut conns = self.connections.lock();
                    if conns
                        .get(&target)
                        .is_some_and(|p| p.generation == generation)
                    {
                        conns.remove(&target);
                    }
                }
            }
        }
        drop(permit);
        self.connect_and_send(target, tag, data).await;
    }

    async fn connect_and_send(&self, target: SocketAddr, tag: ChannelTag, data: &[u8]) {
        enum Role {
            Lead(watch::Sender<bool>),
            Join(watch::Receiver<bool>),
        }
        let role = {
            let mut connecting = self.connecting.lock();
            match connecting.get(&target) {
                Some(rx) => Role::Join(rx.clone()),
                None => {
                    let (tx, rx) = watch::channel(false);
                    connecting.insert(target, rx);
                    Role::Lead(tx)
                }
            }
        };
        match role {
            Role::Lead(done) => {
                let _guard = ConnectingGuard {
                    connecting: self.connecting.clone(),
                    target,
                };
                let existing = self.connections.lock().get(&target).map(|p| p.conn.clone());
                match existing {
                    Some(conn) => {
                        if let Err(e) = write_frame(&conn, tag, data).await {
                            tracing::debug!(peer = %target, error = %e, "write on freshly established connection failed");
                        }
                    }
                    None => self.connect_and_send_inner(target, tag, data).await,
                }
                let _ = done.send(true);
            }
            Role::Join(mut done) => {
                let _ =
                    tokio::time::timeout(CONNECT_JOIN_TIMEOUT, done.wait_for(|ready| *ready)).await;
                let conn = self.connections.lock().get(&target).map(|p| p.conn.clone());
                match conn {
                    Some(conn) => {
                        if let Err(e) = write_frame(&conn, tag, data).await {
                            tracing::debug!(peer = %target, error = %e, "write after joined connect failed");
                        }
                    }
                    None => {
                        crate::metrics::record_transport_write_failure();
                        tracing::debug!(peer = %target, "connection attempt failed, dropping frame");
                    }
                }
            }
        }
    }

    async fn connect_and_send_inner(&self, target: SocketAddr, tag: ChannelTag, data: &[u8]) {
        let Ok(permit) = self.outbound_permits.clone().try_acquire_owned() else {
            tracing::warn!(
                peer = %target,
                max = MAX_OUTBOUND_CONNECTIONS,
                "outbound connection limit reached, dropping"
            );
            crate::metrics::record_transport_write_failure();
            return;
        };
        let shutdown = self.shutdown.clone();
        let endpoint = self.endpoint.clone();
        let conn = (|| async {
            let connecting = endpoint
                .connect(target, RIPPLE_SERVER_NAME)
                .map_err(std::io::Error::other)?;
            tokio::time::timeout(CONNECT_TIMEOUT, connecting)
                .await
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timeout"))?
                .map_err(std::io::Error::other)
        })
        .retry(
            ExponentialBuilder::default()
                .with_min_delay(Duration::from_millis(50))
                .with_max_delay(Duration::from_secs(2))
                .with_max_times(3),
        )
        .when(|_| !shutdown.is_cancelled())
        .await;

        match conn {
            Ok(conn) => {
                let generation = self.conn_generation.fetch_add(1, Ordering::Relaxed);
                self.connections.lock().insert(
                    target,
                    PeerConn {
                        conn: conn.clone(),
                        generation,
                    },
                );
                if let Err(e) = write_frame(&conn, tag, data).await {
                    tracing::warn!(peer = %target, error = %e, "initial write failed");
                }

                let reader_cancel = self.shutdown.child_token();
                tokio::spawn(run_conn_reader(
                    conn.clone(),
                    target,
                    self.incoming_tx.clone(),
                    self.inbound_byte_budget.clone(),
                    self.peer_read_limiter.clone(),
                    reader_cancel.clone(),
                ));

                let connections = self.connections.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    conn.closed().await;
                    {
                        let mut conns = connections.lock();
                        if conns
                            .get(&target)
                            .is_some_and(|p| p.generation == generation)
                        {
                            conns.remove(&target);
                        }
                    }
                    reader_cancel.cancel();
                });
                tracing::debug!(peer = %target, "established outbound connection");
            }
            Err(e) => {
                crate::metrics::record_transport_write_failure();
                tracing::warn!(peer = %target, error = %e, "failed to connect after retries");
            }
        }
    }
}

async fn run_conn_reader(
    conn: Connection,
    from: SocketAddr,
    incoming_tx: mpsc::Sender<IncomingFrame>,
    byte_budget: Arc<Semaphore>,
    peer_limiter: PeerReadLimiter,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            accepted = conn.accept_uni() => match accepted {
                Ok(recv) => {
                    tokio::spawn(read_frame(
                        recv,
                        from,
                        incoming_tx.clone(),
                        byte_budget.clone(),
                        peer_limiter.clone(),
                    ));
                }
                Err(_) => break,
            }
        }
    }
}

enum FrameReadError {
    Oversize,
    BudgetExhausted,
    Stream(String),
}

async fn read_frame(
    recv: RecvStream,
    from: SocketAddr,
    incoming_tx: mpsc::Sender<IncomingFrame>,
    byte_budget: Arc<Semaphore>,
    peer_limiter: PeerReadLimiter,
) {
    let Some(_peer_guard) = peer_limiter.try_acquire(from.ip()) else {
        crate::metrics::record_transport_inbound_dropped();
        tracing::debug!(peer = %from, "per-peer inbound read limit reached, dropping frame");
        return;
    };

    let read = async {
        let mut recv = recv;
        let mut tag_byte = [0u8; 1];
        recv.read_exact(&mut tag_byte)
            .await
            .map_err(|e| FrameReadError::Stream(e.to_string()))?;
        let mut data = Vec::with_capacity(READ_CHUNK_BYTES);
        let mut budget = byte_budget
            .clone()
            .try_acquire_many_owned(0)
            .expect("acquiring zero permits always succeeds");
        loop {
            match recv.read_chunk(READ_CHUNK_BYTES, true).await {
                Ok(Some(chunk)) => {
                    let len = chunk.bytes.len();
                    if data.len() + len > MAX_FRAME_SIZE {
                        return Err(FrameReadError::Oversize);
                    }
                    let permit = byte_budget
                        .clone()
                        .try_acquire_many_owned(len as u32)
                        .map_err(|_| FrameReadError::BudgetExhausted)?;
                    budget.merge(permit);
                    data.extend_from_slice(&chunk.bytes);
                }
                Ok(None) => break,
                Err(e) => return Err(FrameReadError::Stream(e.to_string())),
            }
        }
        Ok::<(u8, Vec<u8>, OwnedSemaphorePermit), FrameReadError>((tag_byte[0], data, budget))
    };

    match tokio::time::timeout(READ_TIMEOUT, read).await {
        Ok(Ok((tag_byte, data, budget))) => match ChannelTag::from_u8(tag_byte) {
            Some(tag) => {
                let frame = IncomingFrame {
                    from,
                    tag,
                    data,
                    _budget: budget,
                };
                if let Err(e) = incoming_tx.try_send(frame) {
                    tracing::warn!(peer = %from, error = %e, "incoming frame channel full, dropping frame");
                }
            }
            None => tracing::debug!(tag = tag_byte, "unknown channel tag, dropping frame"),
        },
        Ok(Err(FrameReadError::Oversize)) => {
            crate::metrics::record_transport_inbound_dropped();
            tracing::debug!(peer = %from, max = MAX_FRAME_SIZE, "inbound frame exceeds max size, dropping");
        }
        Ok(Err(FrameReadError::BudgetExhausted)) => {
            crate::metrics::record_transport_inbound_dropped();
            tracing::debug!(peer = %from, "inbound byte budget saturated, dropping frame");
        }
        Ok(Err(FrameReadError::Stream(msg))) => {
            tracing::debug!(peer = %from, error = %msg, "failed reading uni stream");
        }
        Err(_) => {
            tracing::debug!(peer = %from, "inbound frame read timed out, dropping");
        }
    }
}

#[derive(Clone)]
struct PeerReadLimiter {
    counts: Arc<parking_lot::Mutex<HashMap<IpAddr, usize>>>,
    max_per_peer: usize,
}

impl PeerReadLimiter {
    fn new(max_per_peer: usize) -> Self {
        Self {
            counts: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            max_per_peer,
        }
    }

    fn try_acquire(&self, peer: IpAddr) -> Option<PeerReadGuard> {
        let mut counts = self.counts.lock();
        let count = counts.entry(peer).or_insert(0);
        match *count >= self.max_per_peer {
            true => None,
            false => {
                *count += 1;
                Some(PeerReadGuard {
                    counts: self.counts.clone(),
                    peer,
                })
            }
        }
    }
}

struct PeerReadGuard {
    counts: Arc<parking_lot::Mutex<HashMap<IpAddr, usize>>>,
    peer: IpAddr,
}

impl Drop for PeerReadGuard {
    fn drop(&mut self) {
        let mut counts = self.counts.lock();
        if let Some(count) = counts.get_mut(&self.peer) {
            *count -= 1;
            if *count == 0 {
                counts.remove(&self.peer);
            }
        }
    }
}

async fn write_frame(conn: &Connection, tag: ChannelTag, data: &[u8]) -> std::io::Result<()> {
    if data.len() > MAX_FRAME_SIZE {
        tracing::warn!(
            frame_len = data.len(),
            max = MAX_FRAME_SIZE,
            "refusing to send oversized frame"
        );
        crate::metrics::record_transport_write_failure();
        return Ok(());
    }
    let timed_out = || std::io::Error::new(std::io::ErrorKind::TimedOut, "write timeout");
    let deadline = tokio::time::Instant::now() + WRITE_TIMEOUT;
    let result = match tokio::time::timeout_at(deadline, conn.open_uni()).await {
        Ok(Ok(mut send)) => {
            let write = async {
                send.write_all(&[tag as u8])
                    .await
                    .map_err(std::io::Error::other)?;
                send.write_all(data).await.map_err(std::io::Error::other)?;
                send.finish().map_err(std::io::Error::other)
            };
            let outcome = tokio::time::timeout_at(deadline, write).await;
            match outcome {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => {
                    let _ = send.reset(0u32.into());
                    Err(e)
                }
                Err(_) => {
                    let _ = send.reset(0u32.into());
                    Err(timed_out())
                }
            }
        }
        Ok(Err(e)) => Err(std::io::Error::other(e)),
        Err(_) => Err(timed_out()),
    };
    if result.is_err() {
        crate::metrics::record_transport_write_failure();
    }
    result
}

fn transport_config() -> TransportConfig {
    let mut tc = TransportConfig::default();
    tc.max_concurrent_uni_streams(VarInt::from(MAX_CONCURRENT_UNI_STREAMS));
    tc.stream_receive_window(VarInt::from_u32(STREAM_RECEIVE_WINDOW));
    tc.receive_window(VarInt::from_u32(CONNECTION_RECEIVE_WINDOW));
    tc.keep_alive_interval(Some(KEEPALIVE));
    tc.max_idle_timeout(Some(
        IdleTimeout::try_from(IDLE_TIMEOUT).expect("idle timeout fits in varint"),
    ));
    tc
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

fn derive_identity(key: &ClusterKey) -> Result<NodeIdentity, BoxError> {
    let hk = Hkdf::<Sha256>::new(Some(CLUSTER_HKDF_SALT), key.0.as_bytes());
    let mut seed = [0u8; 32];
    hk.expand(CLUSTER_HKDF_INFO, &mut seed)
        .map_err(|_| "hkdf expand failed")?;

    let mut pkcs8 = Vec::with_capacity(ED25519_PKCS8_V1_PREFIX.len() + seed.len());
    pkcs8.extend_from_slice(&ED25519_PKCS8_V1_PREFIX);
    pkcs8.extend_from_slice(&seed);
    let pkcs8 = PrivatePkcs8KeyDer::from(pkcs8);

    let keypair = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8, &rcgen::PKCS_ED25519)?;
    let mut params = rcgen::CertificateParams::new(vec![RIPPLE_SERVER_NAME.to_string()])?;
    params.serial_number = Some(rcgen::SerialNumber::from(1u64));
    params.not_before = rcgen::date_time_ymd(2024, 1, 1);
    params.not_after = rcgen::date_time_ymd(2099, 1, 1);
    let cert = params.self_signed(&keypair)?;

    Ok(NodeIdentity {
        cert: cert.der().clone(),
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(keypair.serialize_der())),
    })
}

fn ephemeral_identity() -> Result<NodeIdentity, BoxError> {
    let cert = rcgen::generate_simple_self_signed(vec![RIPPLE_SERVER_NAME.to_string()])?;
    Ok(NodeIdentity {
        cert: cert.cert.der().clone(),
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())),
    })
}

fn build_server_config(identity: Option<&NodeIdentity>) -> Result<ServerConfig, BoxError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?;
    let mut crypto = match identity {
        Some(id) => {
            let verifier = Arc::new(PinnedPeer::new(provider, &id.cert)?);
            builder
                .with_client_cert_verifier(verifier)
                .with_single_cert(vec![id.cert.clone()], id.key.clone_key())?
        }
        None => {
            let ephemeral = ephemeral_identity()?;
            builder
                .with_no_client_auth()
                .with_single_cert(vec![ephemeral.cert], ephemeral.key)?
        }
    };
    crypto.alpn_protocols = vec![RIPPLE_ALPN.to_vec()];

    let mut config = ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(crypto)?));
    config.transport_config(Arc::new(transport_config()));
    Ok(config)
}

fn build_client_config(identity: Option<&NodeIdentity>) -> Result<ClientConfig, BoxError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> = match identity {
        Some(id) => Arc::new(PinnedPeer::new(provider.clone(), &id.cert)?),
        None => Arc::new(SkipServerVerification::new(provider.clone())),
    };
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    let mut crypto = match identity {
        Some(id) => builder.with_client_auth_cert(vec![id.cert.clone()], id.key.clone_key())?,
        None => builder.with_no_client_auth(),
    };
    crypto.alpn_protocols = vec![RIPPLE_ALPN.to_vec()];

    let mut config = ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto)?));
    config.transport_config(Arc::new(transport_config()));
    Ok(config)
}

#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new(provider: Arc<rustls::crypto::CryptoProvider>) -> Self {
        Self(provider)
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn spki_der(cert: &CertificateDer<'_>) -> Result<Vec<u8>, BoxError> {
    let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_ref())
        .map_err(|e| format!("parse certificate: {e}"))?;
    Ok(parsed.public_key().raw.to_vec())
}

#[derive(Debug)]
struct PinnedPeer {
    provider: Arc<rustls::crypto::CryptoProvider>,
    expected_spki: Vec<u8>,
    root_hint_subjects: Vec<rustls::DistinguishedName>,
}

impl PinnedPeer {
    fn new(
        provider: Arc<rustls::crypto::CryptoProvider>,
        expected: &CertificateDer<'_>,
    ) -> Result<Self, BoxError> {
        Ok(Self {
            provider,
            expected_spki: spki_der(expected)?,
            root_hint_subjects: Vec::new(),
        })
    }

    fn check(&self, presented: &CertificateDer<'_>) -> Result<(), rustls::Error> {
        let presented_spki = spki_der(presented).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;
        match presented_spki == self.expected_spki {
            true => Ok(()),
            false => Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            )),
        }
    }
}

impl rustls::client::danger::ServerCertVerifier for PinnedPeer {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        self.check(end_entity)?;
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

impl rustls::server::danger::ClientCertVerifier for PinnedPeer {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &self.root_hint_subjects
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        self.check(end_entity)?;
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn quic_frame_roundtrip() {
        let shutdown = CancellationToken::new();
        let (sender, _rx_sender) =
            Transport::bind("127.0.0.1:0".parse().unwrap(), None, shutdown.clone())
                .await
                .expect("bind sender");
        let (receiver, mut rx_receiver) =
            Transport::bind("127.0.0.1:0".parse().unwrap(), None, shutdown.clone())
                .await
                .expect("bind receiver");
        let target = receiver.local_addr();

        sender
            .send(target, ChannelTag::Gossip, b"hello ripple")
            .await;

        let frame = tokio::time::timeout(Duration::from_secs(5), rx_receiver.recv())
            .await
            .expect("frame arrives before timeout")
            .expect("channel open");
        assert_eq!(frame.tag, ChannelTag::Gossip);
        assert_eq!(frame.data, b"hello ripple");

        shutdown.cancel();
    }

    #[tokio::test]
    async fn distinct_channels_roundtrip() {
        let shutdown = CancellationToken::new();
        let (sender, _rx_sender) =
            Transport::bind("127.0.0.1:0".parse().unwrap(), None, shutdown.clone())
                .await
                .expect("bind sender");
        let (receiver, mut rx_receiver) =
            Transport::bind("127.0.0.1:0".parse().unwrap(), None, shutdown.clone())
                .await
                .expect("bind receiver");
        let target = receiver.local_addr();

        sender.send(target, ChannelTag::Gossip, b"first").await;
        sender.send(target, ChannelTag::CrdtSync, b"second").await;

        let mut seen = Vec::new();
        for _ in 0..2 {
            let frame = tokio::time::timeout(Duration::from_secs(5), rx_receiver.recv())
                .await
                .expect("frame arrives before timeout")
                .expect("channel open");
            seen.push((frame.tag, frame.data));
        }
        assert!(seen.contains(&(ChannelTag::Gossip, b"first".to_vec())));
        assert!(seen.contains(&(ChannelTag::CrdtSync, b"second".to_vec())));

        shutdown.cancel();
    }

    #[test]
    fn cluster_identity_is_deterministic() {
        let a = derive_identity(&ClusterKey::new("periwinkle")).expect("derive a");
        let b = derive_identity(&ClusterKey::new("periwinkle")).expect("derive b");
        assert_eq!(a.cert.as_ref(), b.cert.as_ref());
        let c = derive_identity(&ClusterKey::new("limpet")).expect("derive c");
        assert_ne!(a.cert.as_ref(), c.cert.as_ref());
    }

    #[test]
    fn spki_pin_accepts_same_key_rejects_others() {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let a = derive_identity(&ClusterKey::new("periwinkle")).expect("derive a");
        let a2 = derive_identity(&ClusterKey::new("periwinkle")).expect("derive a2");
        let c = derive_identity(&ClusterKey::new("limpet")).expect("derive c");
        let pin = PinnedPeer::new(provider, &a.cert).expect("build pin");
        assert!(pin.check(&a2.cert).is_ok());
        assert!(pin.check(&c.cert).is_err());
    }

    #[test]
    fn spki_pin_survives_cert_reencoding() {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let canonical = derive_identity(&ClusterKey::new("periwinkle")).expect("derive canonical");
        let pin = PinnedPeer::new(provider, &canonical.cert).expect("build pin");

        let hk = Hkdf::<Sha256>::new(Some(CLUSTER_HKDF_SALT), b"periwinkle");
        let mut seed = [0u8; 32];
        hk.expand(CLUSTER_HKDF_INFO, &mut seed).expect("expand");
        let mut pkcs8 = Vec::with_capacity(ED25519_PKCS8_V1_PREFIX.len() + seed.len());
        pkcs8.extend_from_slice(&ED25519_PKCS8_V1_PREFIX);
        pkcs8.extend_from_slice(&seed);
        let keypair = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
            &PrivatePkcs8KeyDer::from(pkcs8),
            &rcgen::PKCS_ED25519,
        )
        .expect("keypair");
        let mut params =
            rcgen::CertificateParams::new(vec![RIPPLE_SERVER_NAME.to_string()]).expect("params");
        params.serial_number = Some(rcgen::SerialNumber::from(99u64));
        params.not_before = rcgen::date_time_ymd(2030, 6, 1);
        params.not_after = rcgen::date_time_ymd(2040, 6, 1);
        let reencoded = params.self_signed(&keypair).expect("self signed");

        assert_ne!(
            canonical.cert.as_ref(),
            reencoded.der().as_ref(),
            "test must actually vary the cert encoding"
        );
        assert!(
            pin.check(reencoded.der()).is_ok(),
            "same cluster key must authenticate across a cert re-encoding"
        );
    }

    #[tokio::test]
    async fn matching_cluster_key_roundtrip() {
        let shutdown = CancellationToken::new();
        let key = || Some(ClusterKey::new("nautilus-shared-secret"));
        let (sender, _rx_sender) =
            Transport::bind("127.0.0.1:0".parse().unwrap(), key(), shutdown.clone())
                .await
                .expect("bind sender");
        let (receiver, mut rx_receiver) =
            Transport::bind("127.0.0.1:0".parse().unwrap(), key(), shutdown.clone())
                .await
                .expect("bind receiver");
        let target = receiver.local_addr();

        sender
            .send(target, ChannelTag::Gossip, b"authenticated")
            .await;

        let frame = tokio::time::timeout(Duration::from_secs(5), rx_receiver.recv())
            .await
            .expect("frame arrives before timeout")
            .expect("channel open");
        assert_eq!(frame.data, b"authenticated");

        shutdown.cancel();
    }

    #[tokio::test]
    async fn mismatched_cluster_key_rejects() {
        let shutdown = CancellationToken::new();
        let (sender, _rx_sender) = Transport::bind(
            "127.0.0.1:0".parse().unwrap(),
            Some(ClusterKey::new("squid-key")),
            shutdown.clone(),
        )
        .await
        .expect("bind sender");
        let (receiver, mut rx_receiver) = Transport::bind(
            "127.0.0.1:0".parse().unwrap(),
            Some(ClusterKey::new("whelk-key")),
            shutdown.clone(),
        )
        .await
        .expect("bind receiver");
        let target = receiver.local_addr();

        sender
            .send(target, ChannelTag::Gossip, b"should be rejected")
            .await;

        let result = tokio::time::timeout(Duration::from_secs(2), rx_receiver.recv()).await;
        assert!(
            result.is_err(),
            "frame must not cross a cluster-key boundary"
        );

        shutdown.cancel();
    }

    #[tokio::test]
    async fn keyless_client_cannot_inject_into_keyed_node() {
        let shutdown = CancellationToken::new();
        let (receiver, mut rx_receiver) = Transport::bind(
            "127.0.0.1:0".parse().unwrap(),
            Some(ClusterKey::new("conch-secret")),
            shutdown.clone(),
        )
        .await
        .expect("bind receiver");
        let target = receiver.local_addr();

        let client_config = build_client_config(None).expect("client config");
        let mut endpoint =
            Endpoint::client("127.0.0.1:0".parse().unwrap()).expect("client endpoint");
        endpoint.set_default_client_config(client_config);

        if let Ok(connecting) = endpoint.connect(target, RIPPLE_SERVER_NAME)
            && let Ok(Ok(conn)) = tokio::time::timeout(Duration::from_secs(3), connecting).await
            && let Ok(mut s) = conn.open_uni().await
        {
            let _ = s.write_all(&[ChannelTag::Gossip as u8]).await;
            let _ = s.write_all(b"attacker payload").await;
            let _ = s.finish();
            let _ = tokio::time::timeout(Duration::from_secs(2), conn.closed()).await;
        }

        let res = tokio::time::timeout(Duration::from_secs(2), rx_receiver.recv()).await;
        assert!(
            res.is_err(),
            "no frame may cross from an unauthenticated client into a keyed node"
        );

        shutdown.cancel();
    }

    #[tokio::test]
    async fn max_size_frame_roundtrips_and_oversize_is_refused() {
        let shutdown = CancellationToken::new();
        let (sender, _rx_sender) =
            Transport::bind("127.0.0.1:0".parse().unwrap(), None, shutdown.clone())
                .await
                .expect("bind sender");
        let (receiver, mut rx_receiver) =
            Transport::bind("127.0.0.1:0".parse().unwrap(), None, shutdown.clone())
                .await
                .expect("bind receiver");
        let target = receiver.local_addr();

        let big = vec![0xABu8; MAX_FRAME_SIZE];
        sender.send(target, ChannelTag::CrdtSync, &big).await;
        let frame = tokio::time::timeout(Duration::from_secs(20), rx_receiver.recv())
            .await
            .expect("max-size frame arrives before timeout")
            .expect("channel open");
        assert_eq!(frame.data.len(), MAX_FRAME_SIZE);

        let oversize = vec![0u8; MAX_FRAME_SIZE + 1];
        sender.send(target, ChannelTag::CrdtSync, &oversize).await;
        let res = tokio::time::timeout(Duration::from_secs(2), rx_receiver.recv()).await;
        assert!(res.is_err(), "oversize frame must be refused sender-side");

        shutdown.cancel();
    }

    #[tokio::test]
    async fn stalled_streams_capped_per_peer() {
        let shutdown = CancellationToken::new();
        let (receiver, _rx_receiver) =
            Transport::bind("127.0.0.1:0".parse().unwrap(), None, shutdown.clone())
                .await
                .expect("bind receiver");
        let target = receiver.local_addr();

        let client_config = build_client_config(None).expect("client config");
        let mut endpoint =
            Endpoint::client("127.0.0.1:0".parse().unwrap()).expect("client endpoint");
        endpoint.set_default_client_config(client_config);
        let conn = endpoint
            .connect(target, RIPPLE_SERVER_NAME)
            .expect("connect")
            .await
            .expect("handshake");

        let mut sends = Vec::new();
        for _ in 0..(MAX_READS_PER_PEER + 16) {
            let mut s = conn.open_uni().await.expect("open uni");
            s.write_all(&[ChannelTag::Gossip as u8])
                .await
                .expect("write tag byte");
            sends.push(s);
        }

        let peer_ip: IpAddr = "127.0.0.1".parse().unwrap();
        let held = || {
            receiver
                .peer_read_limiter
                .counts
                .lock()
                .get(&peer_ip)
                .copied()
                .unwrap_or(0)
        };
        let mut capped = false;
        for _ in 0..100 {
            if held() == MAX_READS_PER_PEER {
                capped = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            capped,
            "stalled streams from one peer must be capped at MAX_READS_PER_PEER; held={}",
            held()
        );

        drop(sends);
        endpoint.close(0u32.into(), b"done");
        shutdown.cancel();
    }

    #[tokio::test]
    async fn inbound_byte_budget_held_until_consumed() {
        let shutdown = CancellationToken::new();
        let (sender, _rx_sender) =
            Transport::bind("127.0.0.1:0".parse().unwrap(), None, shutdown.clone())
                .await
                .expect("bind sender");
        let (receiver, _rx_receiver) =
            Transport::bind("127.0.0.1:0".parse().unwrap(), None, shutdown.clone())
                .await
                .expect("bind receiver");
        let target = receiver.local_addr();

        assert_eq!(
            receiver.inbound_byte_budget.available_permits(),
            INBOUND_BYTE_BUDGET
        );

        let payload = vec![7u8; 1024 * 1024];
        sender.send(target, ChannelTag::CrdtSync, &payload).await;

        let mut held = false;
        for _ in 0..100 {
            if receiver.inbound_byte_budget.available_permits()
                <= INBOUND_BYTE_BUDGET - payload.len()
            {
                held = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            held,
            "an undrained inbound frame must hold its byte budget; available={}",
            receiver.inbound_byte_budget.available_permits()
        );

        shutdown.cancel();
    }

    #[tokio::test]
    async fn incoming_frame_from_matches_peer_listen_addr() {
        let shutdown = CancellationToken::new();
        let (sender, _rx_sender) =
            Transport::bind("127.0.0.1:0".parse().unwrap(), None, shutdown.clone())
                .await
                .expect("bind sender");
        let (receiver, mut rx_receiver) =
            Transport::bind("127.0.0.1:0".parse().unwrap(), None, shutdown.clone())
                .await
                .expect("bind receiver");

        sender
            .send(receiver.local_addr(), ChannelTag::Gossip, b"addr check")
            .await;

        let frame = tokio::time::timeout(Duration::from_secs(5), rx_receiver.recv())
            .await
            .expect("frame arrives before timeout")
            .expect("channel open");
        assert_eq!(
            frame.from,
            sender.local_addr(),
            "inbound frames must report the peer's canonical listen address"
        );

        shutdown.cancel();
    }

    #[tokio::test]
    async fn inbound_budget_exhaustion_drops_excess_frames() {
        use futures::StreamExt;

        let shutdown = CancellationToken::new();
        let (sender, _rx_sender) =
            Transport::bind("127.0.0.1:0".parse().unwrap(), None, shutdown.clone())
                .await
                .expect("bind sender");
        let (receiver, rx_receiver) =
            Transport::bind("127.0.0.1:0".parse().unwrap(), None, shutdown.clone())
                .await
                .expect("bind receiver");
        let target = receiver.local_addr();

        let frame_count = INBOUND_BYTE_BUDGET / MAX_FRAME_SIZE + 1;
        let payload = vec![0x5Au8; MAX_FRAME_SIZE];
        futures::stream::iter(0..frame_count)
            .for_each(|_| sender.send(target, ChannelTag::CrdtSync, &payload))
            .await;

        let received: Vec<IncomingFrame> = futures::stream::unfold(rx_receiver, |mut rx| async {
            tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .ok()
                .flatten()
                .map(|frame| (frame, rx))
        })
        .collect()
        .await;

        assert!(
            !received.is_empty(),
            "frames within the budget must be delivered"
        );
        assert!(
            received.len() < frame_count,
            "frames beyond the inbound byte budget must be dropped while earlier frames sit unconsumed; sent={frame_count} received={}",
            received.len()
        );

        shutdown.cancel();
    }

    #[tokio::test]
    async fn concurrent_sends_to_fresh_peer_all_delivered() {
        let shutdown = CancellationToken::new();
        let (sender, _rx_sender) =
            Transport::bind("127.0.0.1:0".parse().unwrap(), None, shutdown.clone())
                .await
                .expect("bind sender");
        let (receiver, rx_receiver) =
            Transport::bind("127.0.0.1:0".parse().unwrap(), None, shutdown.clone())
                .await
                .expect("bind receiver");
        let target = receiver.local_addr();

        let payloads: Vec<Vec<u8>> = (0..8u8).map(|i| vec![i; 16]).collect();
        futures::future::join_all(
            payloads
                .iter()
                .map(|p| sender.send(target, ChannelTag::CrdtSync, p)),
        )
        .await;

        use futures::StreamExt;
        let received: Vec<IncomingFrame> = futures::stream::unfold(rx_receiver, |mut rx| async {
            tokio::time::timeout(Duration::from_secs(2), rx.recv())
                .await
                .ok()
                .flatten()
                .map(|frame| (frame, rx))
        })
        .collect()
        .await;

        let mut seen: Vec<Vec<u8>> = received.into_iter().map(|f| f.data).collect();
        seen.sort();
        assert_eq!(
            seen, payloads,
            "sends racing a fresh connection must join it and deliver every frame"
        );

        shutdown.cancel();
    }

    #[tokio::test]
    async fn timed_out_write_resets_stream_instead_of_truncating() {
        let shutdown = CancellationToken::new();
        let (sender, _rx_sender) =
            Transport::bind("127.0.0.1:0".parse().unwrap(), None, shutdown.clone())
                .await
                .expect("bind sender");

        let server_config = build_server_config(None).expect("server config");
        let stalled_server = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap())
            .expect("bind stalled server");
        let target = stalled_server.local_addr().expect("local addr");

        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let reader = tokio::spawn(async move {
            let incoming = stalled_server.accept().await.expect("incoming");
            let conn = incoming.await.expect("handshake");
            let mut recv = conn.accept_uni().await.expect("accept uni");
            release_rx.await.expect("release signal");
            recv.read_to_end(MAX_FRAME_SIZE * 2).await
        });

        let payload = vec![0xEEu8; MAX_FRAME_SIZE];
        let started = tokio::time::Instant::now();
        sender.send(target, ChannelTag::CrdtSync, &payload).await;
        assert!(
            started.elapsed() >= WRITE_TIMEOUT,
            "a frame one byte over the stream receive window must stall until the write timeout"
        );

        release_tx.send(()).expect("server task alive");
        let read = reader.await.expect("server task");
        assert!(
            read.is_err(),
            "a timed-out partial write must reset the stream, not surface a truncated frame; read {} bytes",
            read.map(|d| d.len()).unwrap_or(0)
        );

        shutdown.cancel();
    }

    #[tokio::test]
    async fn write_timeout_keeps_connection() {
        use futures::StreamExt;

        let shutdown = CancellationToken::new();
        let (sender, _rx_sender) =
            Transport::bind("127.0.0.1:0".parse().unwrap(), None, shutdown.clone())
                .await
                .expect("bind sender");

        let server_config = build_server_config(None).expect("server config");
        let mute_server = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap())
            .expect("bind mute server");
        let target = mute_server.local_addr().expect("local addr");
        let mute = tokio::spawn(async move {
            let incoming = mute_server.accept().await.expect("incoming");
            let conn = incoming.await.expect("handshake");
            std::future::pending::<()>().await;
            drop(conn);
        });

        futures::stream::iter(0..u64::from(MAX_CONCURRENT_UNI_STREAMS))
            .for_each(|_| sender.send(target, ChannelTag::Gossip, b"fill stream credit"))
            .await;
        assert!(
            sender.connections.lock().contains_key(&target),
            "connection must be established before exhausting stream credit"
        );

        let started = tokio::time::Instant::now();
        sender
            .send(target, ChannelTag::Gossip, b"blocked frame")
            .await;
        assert!(
            started.elapsed() >= WRITE_TIMEOUT,
            "send with exhausted stream credit must block until the write timeout"
        );
        assert!(
            sender.connections.lock().contains_key(&target),
            "a timed-out write must keep the connection registered"
        );

        mute.abort();
        shutdown.cancel();
    }
}
