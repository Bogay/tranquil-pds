use backon::{ExponentialBuilder, Retryable};
use bytes::{Buf, BufMut, BytesMut};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

pub(crate) const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;
const MAX_INBOUND_CONNECTIONS: usize = 512;
const MAX_OUTBOUND_CONNECTIONS: usize = 512;
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ChannelTag {
    Gossip = 0x01,
    CrdtSync = 0x02,
    Raft = 0x03,
    Direct = 0x04,
}

impl ChannelTag {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Gossip),
            0x02 => Some(Self::CrdtSync),
            0x03 => Some(Self::Raft),
            0x04 => Some(Self::Direct),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct IncomingFrame {
    pub from: SocketAddr,
    pub tag: ChannelTag,
    pub data: Vec<u8>,
}

struct ConnectionWriter {
    tx: mpsc::Sender<Vec<u8>>,
    generation: u64,
}

pub struct Transport {
    local_addr: SocketAddr,
    _machine_id: u64,
    connections: Arc<parking_lot::Mutex<HashMap<SocketAddr, ConnectionWriter>>>,
    connecting: Arc<parking_lot::Mutex<std::collections::HashSet<SocketAddr>>>,
    conn_generation: Arc<AtomicU64>,
    #[allow(dead_code)]
    inbound_count: Arc<AtomicUsize>,
    outbound_count: Arc<AtomicUsize>,
    shutdown: CancellationToken,
    incoming_tx: mpsc::Sender<IncomingFrame>,
}

impl Transport {
    pub async fn bind(
        addr: SocketAddr,
        machine_id: u64,
        shutdown: CancellationToken,
    ) -> Result<(Self, mpsc::Receiver<IncomingFrame>), std::io::Error> {
        let listener = TcpListener::bind(addr).await?;
        let local_addr = listener.local_addr()?;
        let (incoming_tx, incoming_rx) = mpsc::channel(4096);
        let inbound_count = Arc::new(AtomicUsize::new(0));

        let transport = Self {
            local_addr,
            _machine_id: machine_id,
            connections: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            connecting: Arc::new(parking_lot::Mutex::new(std::collections::HashSet::new())),
            conn_generation: Arc::new(AtomicU64::new(0)),
            inbound_count: inbound_count.clone(),
            outbound_count: Arc::new(AtomicUsize::new(0)),
            shutdown: shutdown.clone(),
            incoming_tx: incoming_tx.clone(),
        };

        let cancel = shutdown.clone();
        let inbound_counter = inbound_count.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    result = listener.accept() => {
                        match result {
                            Ok((stream, peer_addr)) => {
                                let current = inbound_counter.load(Ordering::Relaxed);
                                if current >= MAX_INBOUND_CONNECTIONS {
                                    tracing::warn!(
                                        peer = %peer_addr,
                                        count = current,
                                        max = MAX_INBOUND_CONNECTIONS,
                                        "rejecting inbound connection: limit reached"
                                    );
                                    drop(stream);
                                    continue;
                                }
                                inbound_counter.fetch_add(1, Ordering::Relaxed);
                                configure_socket(&stream);
                                Self::spawn_reader(
                                    stream,
                                    peer_addr,
                                    incoming_tx.clone(),
                                    cancel.clone(),
                                    inbound_counter.clone(),
                                );
                                tracing::debug!(peer = %peer_addr, "accepted inbound connection");
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "accept failed");
                            }
                        }
                    }
                }
            }
        });

        tracing::info!(addr = %local_addr, "ripple transport bound");
        Ok((transport, incoming_rx))
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn try_queue(&self, target: SocketAddr, tag: ChannelTag, data: &[u8]) -> bool {
        let frame = match encode_frame(tag, data) {
            Some(f) => f,
            None => return false,
        };
        let conns = self.connections.lock();
        match conns.get(&target) {
            Some(writer) => writer.tx.try_send(frame).is_ok(),
            None => false,
        }
    }

    pub async fn send(&self, target: SocketAddr, tag: ChannelTag, data: &[u8]) {
        let frame = match encode_frame(tag, data) {
            Some(f) => f,
            None => return,
        };
        let writer = {
            let conns = self.connections.lock();
            conns.get(&target).map(|w| (w.tx.clone(), w.generation))
        };
        match writer {
            Some((tx, acquired_gen)) => {
                if tx.send(frame).await.is_err() {
                    {
                        let mut conns = self.connections.lock();
                        let stale = conns
                            .get(&target)
                            .is_some_and(|w| w.generation == acquired_gen);
                        if stale {
                            conns.remove(&target);
                        }
                    }
                    self.connect_and_send(target, tag, data).await;
                }
            }
            None => {
                self.connect_and_send(target, tag, data).await;
            }
        }
    }

    async fn connect_and_send(&self, target: SocketAddr, tag: ChannelTag, data: &[u8]) {
        {
            let mut connecting = self.connecting.lock();
            if connecting.contains(&target) {
                tracing::warn!(peer = %target, "connection already in-flight, dropping frame");
                return;
            }
            connecting.insert(target);
        }

        let result = self.connect_and_send_inner(target, tag, data).await;
        self.connecting.lock().remove(&target);
        result
    }

    async fn connect_and_send_inner(&self, target: SocketAddr, tag: ChannelTag, data: &[u8]) {
        let shutdown = self.shutdown.clone();
        let stream = (|| async {
            tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(target))
                .await
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timeout"))?
        })
        .retry(
            ExponentialBuilder::default()
                .with_min_delay(Duration::from_millis(50))
                .with_max_delay(Duration::from_secs(2))
                .with_max_times(3),
        )
        .when(|_| !shutdown.is_cancelled())
        .await;
        match stream {
            Ok(stream) => {
                if self.outbound_count.load(Ordering::Relaxed) >= MAX_OUTBOUND_CONNECTIONS {
                    tracing::warn!(
                        peer = %target,
                        max = MAX_OUTBOUND_CONNECTIONS,
                        "outbound connection limit reached, dropping"
                    );
                    return;
                }
                self.outbound_count.fetch_add(1, Ordering::Relaxed);
                configure_socket(&stream);
                let (read_half, write_half) = stream.into_split();
                let (write_tx, mut write_rx) = mpsc::channel::<Vec<u8>>(1024);

                let conn_gen = self.conn_generation.fetch_add(1, Ordering::Relaxed);
                self.connections.lock().insert(
                    target,
                    ConnectionWriter {
                        tx: write_tx.clone(),
                        generation: conn_gen,
                    },
                );
                if let Some(frame) = encode_frame(tag, data) {
                    let _ = write_tx.try_send(frame);
                }

                let conn_cancel = self.shutdown.child_token();
                let reader_cancel = conn_cancel.clone();
                let connections = self.connections.clone();
                let outbound_counter = self.outbound_count.clone();
                let peer = target;

                tokio::spawn(async move {
                    let mut writer = write_half;
                    loop {
                        tokio::select! {
                            _ = conn_cancel.cancelled() => break,
                            msg = write_rx.recv() => {
                                match msg {
                                    Some(buf) => {
                                        let write_result = tokio::time::timeout(
                                            WRITE_TIMEOUT,
                                            writer.write_all(&buf),
                                        ).await;
                                        match write_result {
                                            Ok(Ok(())) => {}
                                            Ok(Err(e)) => {
                                                tracing::warn!(peer = %peer, error = %e, "write failed, closing connection");
                                                break;
                                            }
                                            Err(_) => {
                                                tracing::warn!(peer = %peer, "write timed out, closing connection");
                                                break;
                                            }
                                        }
                                    }
                                    None => break,
                                }
                            }
                        }
                    }
                    connections.lock().remove(&peer);
                    outbound_counter.fetch_sub(1, Ordering::Relaxed);
                    conn_cancel.cancel();
                });

                Self::spawn_reader_half(read_half, target, self.incoming_tx.clone(), reader_cancel);
                tracing::debug!(peer = %target, "established outbound connection");
            }
            Err(e) => {
                tracing::warn!(peer = %target, error = %e, "failed to connect after retries");
            }
        }
    }

    fn spawn_reader(
        stream: TcpStream,
        peer_addr: SocketAddr,
        incoming_tx: mpsc::Sender<IncomingFrame>,
        cancel: CancellationToken,
        inbound_counter: Arc<AtomicUsize>,
    ) {
        tokio::spawn(async move {
            let mut buf = BytesMut::with_capacity(8192);
            let mut stream = stream;
            loop {
                if buf.len() > MAX_FRAME_SIZE * 2 {
                    tracing::warn!(peer = %peer_addr, buf_len = buf.len(), "read buffer exceeded limit, closing connection");
                    break;
                }
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    n = stream.read_buf(&mut buf) => {
                        match n {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {
                                if !Self::process_frames(&mut buf, peer_addr, &incoming_tx) {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            inbound_counter.fetch_sub(1, Ordering::Relaxed);
        });
    }

    fn spawn_reader_half(
        read_half: tokio::net::tcp::OwnedReadHalf,
        peer_addr: SocketAddr,
        incoming_tx: mpsc::Sender<IncomingFrame>,
        cancel: CancellationToken,
    ) {
        tokio::spawn(async move {
            let mut buf = BytesMut::with_capacity(8192);
            let mut reader = read_half;
            loop {
                if buf.len() > MAX_FRAME_SIZE * 2 {
                    tracing::warn!(peer = %peer_addr, buf_len = buf.len(), "read buffer exceeded limit, closing connection");
                    break;
                }
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    n = reader.read_buf(&mut buf) => {
                        match n {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {
                                if !Self::process_frames(&mut buf, peer_addr, &incoming_tx) {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            cancel.cancel();
        });
    }

    fn process_frames(
        buf: &mut BytesMut,
        peer_addr: SocketAddr,
        incoming_tx: &mpsc::Sender<IncomingFrame>,
    ) -> bool {
        loop {
            match decode_frame(buf) {
                DecodeResult::Frame(tag, data) => {
                    if let Err(e) = incoming_tx.try_send(IncomingFrame {
                        from: peer_addr,
                        tag,
                        data,
                    }) {
                        tracing::warn!(peer = %peer_addr, error = %e, "incoming frame channel full, dropping frame");
                    }
                }
                DecodeResult::NeedMoreData => return true,
                DecodeResult::Corrupt => return false,
            }
        }
    }
}

fn configure_socket(stream: &TcpStream) {
    let sock_ref = socket2::SockRef::from(stream);
    if let Err(e) = sock_ref.set_tcp_nodelay(true) {
        tracing::warn!(error = %e, "failed to set TCP_NODELAY");
    }
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(30));
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    let keepalive = keepalive.with_interval(Duration::from_secs(10));
    let params = keepalive;
    if let Err(e) = sock_ref.set_tcp_keepalive(&params) {
        tracing::warn!(error = %e, "failed to set TCP keepalive");
    }
}

fn encode_frame(tag: ChannelTag, data: &[u8]) -> Option<Vec<u8>> {
    match data.len() > MAX_FRAME_SIZE {
        true => {
            tracing::warn!(
                frame_len = data.len(),
                max = MAX_FRAME_SIZE,
                "refusing to encode oversized frame"
            );
            None
        }
        false => {
            let len = u32::try_from(data.len()).ok()?;
            let mut buf = Vec::with_capacity(5 + data.len());
            buf.put_u32(len);
            buf.put_u8(tag as u8);
            buf.extend_from_slice(data);
            Some(buf)
        }
    }
}

enum DecodeResult {
    Frame(ChannelTag, Vec<u8>),
    NeedMoreData,
    Corrupt,
}

fn decode_frame(buf: &mut BytesMut) -> DecodeResult {
    loop {
        if buf.len() < 5 {
            return DecodeResult::NeedMoreData;
        }
        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        if len > MAX_FRAME_SIZE {
            tracing::warn!(
                frame_len = len,
                max = MAX_FRAME_SIZE,
                "oversized frame, closing connection"
            );
            buf.clear();
            return DecodeResult::Corrupt;
        }
        if buf.len() < 5 + len {
            return DecodeResult::NeedMoreData;
        }
        buf.advance(4);
        let tag_byte = buf[0];
        buf.advance(1);
        let data = buf.split_to(len).to_vec();
        match ChannelTag::from_u8(tag_byte) {
            Some(tag) => return DecodeResult::Frame(tag, data),
            None => {
                tracing::debug!(tag = tag_byte, "skipping frame with unknown channel tag");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let original = b"hello world";
        let encoded = encode_frame(ChannelTag::Gossip, original).expect("should encode");
        let mut buf = BytesMut::from(&encoded[..]);
        match decode_frame(&mut buf) {
            DecodeResult::Frame(tag, data) => {
                assert_eq!(tag, ChannelTag::Gossip);
                assert_eq!(data, original);
            }
            _ => panic!("expected frame"),
        }
        assert!(buf.is_empty());
    }

    #[test]
    fn partial_frame_returns_need_more() {
        let encoded = encode_frame(ChannelTag::CrdtSync, b"test data").expect("should encode");
        let mut buf = BytesMut::from(&encoded[..3]);
        assert!(matches!(decode_frame(&mut buf), DecodeResult::NeedMoreData));
    }

    #[test]
    fn multiple_frames() {
        let f1 = encode_frame(ChannelTag::Gossip, b"first").expect("should encode");
        let f2 = encode_frame(ChannelTag::Direct, b"second").expect("should encode");
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&f1);
        buf.extend_from_slice(&f2);

        match decode_frame(&mut buf) {
            DecodeResult::Frame(tag1, data1) => {
                assert_eq!(tag1, ChannelTag::Gossip);
                assert_eq!(data1, b"first");
            }
            _ => panic!("expected frame"),
        }

        match decode_frame(&mut buf) {
            DecodeResult::Frame(tag2, data2) => {
                assert_eq!(tag2, ChannelTag::Direct);
                assert_eq!(data2, b"second");
            }
            _ => panic!("expected frame"),
        }
    }
}
