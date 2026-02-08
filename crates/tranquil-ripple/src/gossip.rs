use crate::crdt::delta::CrdtDelta;
use crate::crdt::lww_map::LwwDelta;
use crate::crdt::ShardedCrdtStore;
use crate::metrics;
use crate::transport::{ChannelTag, IncomingFrame, Transport};
use foca::{Config, Foca, Notification, Runtime, Timer};
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::collections::HashSet;
use std::fmt;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

const MAX_GCOUNTER_NODES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PeerId {
    pub addr: SocketAddr,
    pub machine_id: u64,
    pub generation: u32,
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}(g{})", self.machine_id, self.addr, self.generation)
    }
}

impl foca::Identity for PeerId {
    type Addr = SocketAddr;

    fn addr(&self) -> SocketAddr {
        self.addr
    }

    fn renew(&self) -> Option<Self> {
        Some(Self {
            addr: self.addr,
            machine_id: self.machine_id,
            generation: self.generation.saturating_add(1),
        })
    }

    fn win_addr_conflict(&self, adversary: &Self) -> bool {
        self.generation > adversary.generation
    }
}

impl serde::Serialize for PeerId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeTuple;
        let mut tup = serializer.serialize_tuple(3)?;
        tup.serialize_element(&self.addr.to_string())?;
        tup.serialize_element(&self.machine_id)?;
        tup.serialize_element(&self.generation)?;
        tup.end()
    }
}

impl<'de> serde::Deserialize<'de> for PeerId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let (addr_str, machine_id, generation): (String, u64, u32) =
            serde::Deserialize::deserialize(deserializer)?;
        let addr: SocketAddr = addr_str.parse().map_err(serde::de::Error::custom)?;
        Ok(Self {
            addr,
            machine_id,
            generation,
        })
    }
}

enum RuntimeAction {
    SendTo(PeerId, Vec<u8>),
    ScheduleTimer(Timer<PeerId>, Duration),
    MemberUp(SocketAddr),
    MemberDown(SocketAddr),
}

struct BufferedRuntime {
    actions: Vec<RuntimeAction>,
}

impl BufferedRuntime {
    fn new() -> Self {
        Self {
            actions: Vec::new(),
        }
    }
}

struct MemberTracker {
    active_addrs: HashSet<SocketAddr>,
}

impl MemberTracker {
    fn new() -> Self {
        Self {
            active_addrs: HashSet::new(),
        }
    }

    fn member_up(&mut self, addr: SocketAddr) {
        self.active_addrs.insert(addr);
    }

    fn member_down(&mut self, addr: SocketAddr) {
        self.active_addrs.remove(&addr);
    }

    fn active_peers(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.active_addrs.iter().copied()
    }

    fn peer_count(&self) -> usize {
        self.active_addrs.len()
    }
}

impl Runtime<PeerId> for &mut BufferedRuntime {
    fn notify(&mut self, notification: Notification<'_, PeerId>) {
        match notification {
            Notification::MemberUp(peer) => {
                self.actions.push(RuntimeAction::MemberUp(peer.addr));
            }
            Notification::MemberDown(peer) => {
                self.actions.push(RuntimeAction::MemberDown(peer.addr));
            }
            _ => {}
        }
    }

    fn send_to(&mut self, to: PeerId, data: &[u8]) {
        self.actions
            .push(RuntimeAction::SendTo(to, data.to_vec()));
    }

    fn submit_after(&mut self, event: Timer<PeerId>, after: Duration) {
        self.actions.push(RuntimeAction::ScheduleTimer(event, after));
    }
}

pub struct GossipEngine {
    transport: Arc<Transport>,
    store: Arc<ShardedCrdtStore>,
    local_id: PeerId,
}

impl GossipEngine {
    pub fn new(
        transport: Arc<Transport>,
        store: Arc<ShardedCrdtStore>,
        local_id: PeerId,
    ) -> Self {
        Self {
            transport,
            store,
            local_id,
        }
    }

    pub fn spawn(
        self,
        seed_peers: Vec<SocketAddr>,
        gossip_interval_ms: u64,
        mut incoming_rx: mpsc::Receiver<IncomingFrame>,
        shutdown: CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        let mut config = Config::simple();
        config.max_packet_size = NonZeroUsize::new(2 * 1024 * 1024).expect("nonzero");
        config.periodic_gossip = Some(foca::PeriodicParams {
            frequency: Duration::from_millis(gossip_interval_ms),
            num_members: NonZeroUsize::new(3).expect("nonzero"),
        });
        config.periodic_announce = Some(foca::PeriodicParams {
            frequency: Duration::from_secs(30),
            num_members: NonZeroUsize::new(3).expect("nonzero"),
        });

        let rng = StdRng::from_os_rng();
        let codec = foca::BincodeCodec(bincode::config::standard());
        let mut foca: Foca<PeerId, _, _, _> = Foca::new(self.local_id.clone(), config, rng, codec);

        let transport = self.transport.clone();
        let store = self.store.clone();

        let (timer_tx, mut timer_rx) = mpsc::channel::<(Timer<PeerId>, Duration)>(256);

        const WATERMARK_STALE_SECS: u64 = 30;

        tokio::spawn(async move {
            let mut runtime = BufferedRuntime::new();
            let mut members = MemberTracker::new();
            let mut last_commit = tokio::time::Instant::now();

            seed_peers.iter().for_each(|&addr| {
                let seed_id = PeerId {
                    addr,
                    machine_id: 0,
                    generation: 0,
                };
                if let Err(e) = foca.announce(seed_id, &mut runtime) {
                    tracing::warn!(error = %e, "failed to announce to seed peer");
                }
            });

            drain_runtime_actions(&mut runtime, &transport, &timer_tx, &mut members, &store, &shutdown);

            let mut gossip_tick =
                tokio::time::interval(Duration::from_millis(gossip_interval_ms));
            gossip_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => {
                        tracing::info!("gossip engine shutting down, flushing final delta");
                        flush_final_delta(&store, &transport, &members);
                        break;
                    }
                    Some(frame) = incoming_rx.recv() => {
                        match frame.tag {
                            ChannelTag::Gossip => {
                                if let Err(e) = foca.handle_data(&frame.data, &mut runtime) {
                                    tracing::warn!(error = %e, "foca handle_data error");
                                }
                                drain_runtime_actions(&mut runtime, &transport, &timer_tx, &mut members, &store, &shutdown);
                            }
                            ChannelTag::CrdtSync => {
                                const MAX_DELTA_ENTRIES: usize = 10_000;
                                const MAX_DELTA_RATE_LIMITS: usize = 10_000;
                                metrics::record_gossip_delta_received();
                                metrics::record_gossip_delta_bytes(frame.data.len());
                                match bincode::serde::decode_from_slice::<CrdtDelta, _>(&frame.data, bincode::config::standard()) {
                                    Ok((delta, _)) => {
                                        let cache_len = delta.cache_delta.as_ref().map_or(0, |d| d.entries.len());
                                        let rl_len = delta.rate_limit_deltas.len();
                                        let gcounter_oversize = delta.rate_limit_deltas.iter().any(|rd| rd.counter.increments.len() > MAX_GCOUNTER_NODES);
                                        let window_mismatch = delta.rate_limit_deltas.iter().any(|rd| rd.counter.window_duration_ms == 0);
                                        match cache_len > MAX_DELTA_ENTRIES || rl_len > MAX_DELTA_RATE_LIMITS || gcounter_oversize || window_mismatch {
                                            true => {
                                                metrics::record_gossip_drop();
                                                tracing::warn!(
                                                    cache_entries = cache_len,
                                                    rate_limit_entries = rl_len,
                                                    gcounter_oversize = gcounter_oversize,
                                                    "dropping invalid CRDT delta"
                                                );
                                            }
                                            false => {
                                                if store.merge_delta(&delta) {
                                                    metrics::record_gossip_merge();
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        metrics::record_gossip_drop();
                                        tracing::warn!(error = %e, "failed to decode crdt sync delta");
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    _ = gossip_tick.tick() => {
                        let delta = store.peek_broadcast_delta();
                        match delta.is_empty() {
                            true => {
                                last_commit = tokio::time::Instant::now();
                            }
                            false => {
                                let chunks = chunk_and_serialize(&delta);
                                match chunks.is_empty() {
                                    true => {
                                        tracing::warn!("all delta chunks failed to serialize, force-committing watermark");
                                        store.commit_broadcast(&delta);
                                        last_commit = tokio::time::Instant::now();
                                    }
                                    false => {
                                        let peers: Vec<SocketAddr> = members.active_peers().collect();
                                        let mut all_queued = true;
                                        let cancel = shutdown.clone();
                                        chunks.iter().for_each(|chunk| {
                                            metrics::record_gossip_delta_bytes(chunk.len());
                                            peers.iter().for_each(|&addr| {
                                                metrics::record_gossip_delta_sent();
                                                match transport.try_queue(addr, ChannelTag::CrdtSync, chunk) {
                                                    true => {}
                                                    false => {
                                                        all_queued = false;
                                                        let t = transport.clone();
                                                        let d = chunk.clone();
                                                        let c = cancel.clone();
                                                        tokio::spawn(async move {
                                                            tokio::select! {
                                                                _ = c.cancelled() => {}
                                                                _ = t.send(addr, ChannelTag::CrdtSync, &d) => {}
                                                            }
                                                        });
                                                    }
                                                }
                                            });
                                        });
                                        let stale = last_commit.elapsed() > Duration::from_secs(WATERMARK_STALE_SECS);
                                        if all_queued || peers.is_empty() || stale {
                                            if stale && !all_queued {
                                                tracing::warn!(
                                                    elapsed_secs = last_commit.elapsed().as_secs(),
                                                    "force-advancing broadcast watermark (staleness cap)"
                                                );
                                            }
                                            store.commit_broadcast(&delta);
                                            last_commit = tokio::time::Instant::now();
                                        }
                                    }
                                }
                            }
                        };
                        if let Err(e) = foca.gossip(&mut runtime) {
                            tracing::warn!(error = %e, "foca gossip error");
                        }
                        drain_runtime_actions(&mut runtime, &transport, &timer_tx, &mut members, &store, &shutdown);
                    }
                    Some((timer, _)) = timer_rx.recv() => {
                        if let Err(e) = foca.handle_timer(timer, &mut runtime) {
                            tracing::warn!(error = %e, "foca handle_timer error");
                        }
                        drain_runtime_actions(&mut runtime, &transport, &timer_tx, &mut members, &store, &shutdown);
                    }
                    _ = tokio::time::sleep(Duration::from_secs(10)) => {
                        tracing::trace!(
                            members = foca.num_members(),
                            cache_bytes = store.cache_estimated_bytes(),
                            rate_limit_bytes = store.rate_limit_estimated_bytes(),
                            "gossip health check"
                        );
                    }
                }
            }
        })
    }
}

fn flush_final_delta(
    store: &Arc<ShardedCrdtStore>,
    transport: &Arc<Transport>,
    members: &MemberTracker,
) {
    let delta = store.peek_broadcast_delta();
    if delta.is_empty() {
        return;
    }
    let chunks = chunk_and_serialize(&delta);
    chunks.iter().for_each(|chunk| {
        members.active_peers().for_each(|addr| {
            let _ = transport.try_queue(addr, ChannelTag::CrdtSync, chunk);
        });
    });
    store.commit_broadcast(&delta);
}

fn drain_runtime_actions(
    runtime: &mut BufferedRuntime,
    transport: &Arc<Transport>,
    timer_tx: &mpsc::Sender<(Timer<PeerId>, Duration)>,
    members: &mut MemberTracker,
    store: &Arc<ShardedCrdtStore>,
    shutdown: &CancellationToken,
) {
    let actions: Vec<RuntimeAction> = runtime.actions.drain(..).collect();
    actions.into_iter().for_each(|action| match action {
        RuntimeAction::SendTo(peer, data) => {
            let t = transport.clone();
            let c = shutdown.clone();
            tokio::spawn(async move {
                tokio::select! {
                    _ = c.cancelled() => {}
                    _ = t.send(peer.addr, ChannelTag::Gossip, &data) => {}
                }
            });
        }
        RuntimeAction::ScheduleTimer(timer, duration) => {
            let tx = timer_tx.clone();
            let c = shutdown.clone();
            tokio::spawn(async move {
                tokio::select! {
                    _ = c.cancelled() => {}
                    _ = tokio::time::sleep(duration) => {
                        let _ = tx.send((timer, duration)).await;
                    }
                }
            });
        }
        RuntimeAction::MemberUp(addr) => {
            tracing::info!(peer = %addr, "member up");
            members.member_up(addr);
            metrics::set_gossip_peers(members.peer_count());
            let snapshot = store.peek_full_state();
            if !snapshot.is_empty() {
                chunk_and_serialize(&snapshot).into_iter().for_each(|chunk| {
                    let t = transport.clone();
                    let c = shutdown.clone();
                    tokio::spawn(async move {
                        tokio::select! {
                            _ = c.cancelled() => {}
                            _ = t.send(addr, ChannelTag::CrdtSync, &chunk) => {}
                        }
                    });
                });
            }
        }
        RuntimeAction::MemberDown(addr) => {
            tracing::info!(peer = %addr, "member down");
            members.member_down(addr);
            metrics::set_gossip_peers(members.peer_count());
        }
    });
}

fn chunk_and_serialize(delta: &CrdtDelta) -> Vec<Vec<u8>> {
    let config = bincode::config::standard();
    match bincode::serde::encode_to_vec(delta, config) {
        Ok(bytes) if bytes.len() <= crate::transport::MAX_FRAME_SIZE => vec![bytes],
        Ok(_) => split_and_serialize(delta.clone()),
        Err(e) => {
            tracing::warn!(error = %e, "failed to serialize delta");
            vec![]
        }
    }
}

fn split_and_serialize(delta: CrdtDelta) -> Vec<Vec<u8>> {
    let version = delta.version;
    let source_node = delta.source_node;
    let cache_entries = delta.cache_delta.map_or(Vec::new(), |d| d.entries);
    let rl_deltas = delta.rate_limit_deltas;

    if cache_entries.is_empty() && rl_deltas.is_empty() {
        return vec![];
    }

    if cache_entries.len() <= 1 && rl_deltas.len() <= 1 {
        let mini = CrdtDelta {
            version,
            source_node,
            cache_delta: match cache_entries.is_empty() {
                true => None,
                false => Some(LwwDelta { entries: cache_entries }),
            },
            rate_limit_deltas: rl_deltas,
        };
        match bincode::serde::encode_to_vec(&mini, bincode::config::standard()) {
            Ok(bytes) if bytes.len() <= crate::transport::MAX_FRAME_SIZE => return vec![bytes],
            _ => {
                tracing::error!("irreducible delta entry exceeds max frame size, dropping");
                return vec![];
            }
        }
    }

    let mid_cache = cache_entries.len() / 2;
    let mid_rl = rl_deltas.len() / 2;

    let mut left_cache = cache_entries;
    let right_cache = left_cache.split_off(mid_cache);
    let mut left_rl = rl_deltas;
    let right_rl = left_rl.split_off(mid_rl);

    let make_sub = |entries: Vec<_>, rls| CrdtDelta {
        version,
        source_node,
        cache_delta: match entries.is_empty() {
            true => None,
            false => Some(LwwDelta { entries }),
        },
        rate_limit_deltas: rls,
    };

    let left = make_sub(left_cache, left_rl);
    let right = make_sub(right_cache, right_rl);

    let mut result = chunk_and_serialize(&left);
    result.extend(chunk_and_serialize(&right));
    result
}
