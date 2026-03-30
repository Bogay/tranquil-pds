use std::collections::BTreeMap;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::{Condvar, Mutex};
use tokio::sync::broadcast;
use tracing::warn;

use super::reader::{EventLogReader, RawEvent};
use super::segment_file::ValidEvent;
use super::types::{EventSequence, SegmentId, SegmentOffset};
use super::valid_event_to_raw;
use super::writer::{EventLogWriter, SyncResult};
use crate::io::StorageIO;

const MAX_BATCH_SIZE: usize = 1024;
const MAX_REORDER_PENDING: usize = 65536;
const SYNC_TIMEOUT: Duration = Duration::from_secs(30);
const REORDER_TIMEOUT: Duration = Duration::from_millis(100);
const GAP_ABANDON_TIMEOUT: Duration = Duration::from_secs(5);

pub struct FreezeResponse {
    pub synced_through: EventSequence,
    pub segment_id: SegmentId,
    pub position: SegmentOffset,
}

pub enum WriterRequest {
    Append(ValidEvent),
    SyncBarrier {
        response: flume::Sender<io::Result<SyncResult>>,
    },
    Freeze {
        response: flume::Sender<io::Result<FreezeResponse>>,
        resume: flume::Receiver<()>,
    },
    Shutdown,
}

pub struct WriterNotify {
    synced_seq: AtomicU64,
    poisoned: AtomicBool,
    mutex: Mutex<()>,
    cond: Condvar,
}

pub struct PendingBytesBudget {
    budget: u64,
    state: Mutex<BudgetState>,
    cond: Condvar,
}

struct BudgetState {
    in_flight: u64,
    closed: bool,
}

impl PendingBytesBudget {
    pub fn new(budget: u64) -> Self {
        let effective = match budget {
            0 => u64::MAX,
            n => n,
        };
        Self {
            budget: effective,
            state: Mutex::new(BudgetState {
                in_flight: 0,
                closed: false,
            }),
            cond: Condvar::new(),
        }
    }

    pub fn budget(&self) -> u64 {
        self.budget
    }

    pub fn in_flight(&self) -> u64 {
        self.state.lock().in_flight
    }

    pub fn acquire(&self, bytes: u64) -> io::Result<()> {
        let oversized = bytes > self.budget;
        let mut guard = self.state.lock();
        loop {
            if guard.closed {
                return Err(io::Error::other("eventlog writer pending budget closed"));
            }
            let admit = match oversized {
                true => guard.in_flight == 0,
                false => guard.in_flight.saturating_add(bytes) <= self.budget,
            };
            if admit {
                guard.in_flight = guard.in_flight.saturating_add(bytes);
                if oversized {
                    warn!(
                        bytes,
                        budget = self.budget,
                        "eventlog admitting oversized event past pending budget"
                    );
                }
                return Ok(());
            }
            self.cond.wait(&mut guard);
        }
    }

    pub fn release(&self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        let mut guard = self.state.lock();
        guard.in_flight = guard.in_flight.saturating_sub(bytes);
        self.cond.notify_all();
    }

    pub fn close(&self) {
        let mut guard = self.state.lock();
        guard.closed = true;
        self.cond.notify_all();
    }
}

impl WriterNotify {
    pub fn new(initial_synced: u64) -> Self {
        Self {
            synced_seq: AtomicU64::new(initial_synced),
            poisoned: AtomicBool::new(false),
            mutex: Mutex::new(()),
            cond: Condvar::new(),
        }
    }

    pub fn wait_for_sync(&self, target: EventSequence) -> io::Result<()> {
        let target_raw = target.raw();

        if self.synced_seq.load(Ordering::Acquire) >= target_raw {
            return Ok(());
        }

        if self.poisoned.load(Ordering::Acquire) {
            return Err(io::Error::other("eventlog writer poisoned"));
        }

        let deadline = Instant::now() + SYNC_TIMEOUT;
        let mut guard = self.mutex.lock();

        loop {
            if self.synced_seq.load(Ordering::Acquire) >= target_raw {
                return Ok(());
            }
            if self.poisoned.load(Ordering::Acquire) {
                return Err(io::Error::other("eventlog writer poisoned"));
            }

            let now = Instant::now();
            if now >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "eventlog sync timed out",
                ));
            }

            self.cond.wait_for(&mut guard, deadline - now);
        }
    }

    fn update_synced(&self, synced_through: u64) {
        self.synced_seq.store(synced_through, Ordering::Release);
        let _guard = self.mutex.lock();
        self.cond.notify_all();
    }

    fn poison(&self) {
        self.poisoned.store(true, Ordering::Release);
        let _guard = self.mutex.lock();
        self.cond.notify_all();
    }
}

struct ReorderBuffer {
    pending: BTreeMap<u64, ValidEvent>,
    next_write_seq: u64,
    gap_since: Option<Instant>,
}

impl ReorderBuffer {
    fn new(next_write_seq: u64) -> Self {
        Self {
            pending: BTreeMap::new(),
            next_write_seq,
            gap_since: None,
        }
    }

    fn insert(&mut self, event: ValidEvent) {
        if event.seq.raw() < self.next_write_seq {
            warn!(
                event_seq = event.seq.raw(),
                next_write_seq = self.next_write_seq,
                "dropping late-arriving event after gap skip"
            );
            return;
        }
        self.pending.insert(event.seq.raw(), event);
    }

    fn is_full(&self) -> bool {
        self.pending.len() >= MAX_REORDER_PENDING
    }

    fn pending_count(&self) -> usize {
        self.pending.len()
    }

    fn drain_contiguous(&mut self) -> Vec<ValidEvent> {
        let mut batch = Vec::new();
        while let Some(event) = self.pending.remove(&self.next_write_seq) {
            self.next_write_seq = event.seq.next().raw();
            batch.push(event);
        }
        if batch.is_empty() && !self.pending.is_empty() {
            if self.gap_since.is_none() {
                self.gap_since = Some(Instant::now());
            }
        } else {
            self.gap_since = None;
        }
        batch
    }

    fn should_skip_gap(&self) -> bool {
        self.gap_since
            .is_some_and(|since| since.elapsed() >= GAP_ABANDON_TIMEOUT)
    }

    fn skip_to_first_available(&mut self) -> Vec<ValidEvent> {
        let first_available = match self.pending.keys().next() {
            Some(&seq) => seq,
            None => return Vec::new(),
        };
        warn!(
            expected = self.next_write_seq,
            skipping_to = first_available,
            "eventlog writer skipping gap after timeout"
        );
        self.next_write_seq = first_available;
        self.gap_since = None;
        self.drain_contiguous()
    }

    fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }
}

struct WriterCtx<'a, S: StorageIO> {
    reader: &'a EventLogReader<S>,
    broadcast_tx: &'a broadcast::Sender<RawEvent>,
    notify: &'a WriterNotify,
    synced_seq: &'a AtomicU64,
    pending_bytes: &'a PendingBytesBudget,
}

fn post_sync<S: StorageIO>(result: &mut SyncResult, ctx: &WriterCtx<'_, S>) {
    let synced = result.synced_through.raw();
    let flushed = std::mem::take(&mut result.flushed_events);

    if let (Some(first), Some(last)) = (flushed.first(), flushed.last()) {
        ctx.reader.extend_active_range(first.seq, last.seq);
    }

    ctx.synced_seq.store(synced, Ordering::Release);
    ctx.notify.update_synced(synced);

    let released = flushed
        .iter()
        .map(|e| e.payload.len() as u64)
        .fold(0u64, u64::saturating_add);

    flushed.into_iter().for_each(|e| {
        let _ = ctx.broadcast_tx.send(valid_event_to_raw(e));
    });

    ctx.pending_bytes.release(released);
}

fn flush_and_notify<S: StorageIO>(writer: &mut EventLogWriter<S>, ctx: &WriterCtx<'_, S>) -> bool {
    match writer.sync() {
        Ok(mut result) => {
            post_sync(&mut result, ctx);

            match writer.rotate_if_needed() {
                Ok(Some(sealed_id)) => {
                    let new_id = writer.active_segment_id();
                    if let Err(e) = ctx.reader.on_segment_rotated(sealed_id, new_id) {
                        warn!(error = %e, "eventlog rotation notification failed");
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    warn!(error = %e, "eventlog rotation deferred");
                }
            }
            true
        }
        Err(e) => {
            warn!(error = %e, "eventlog sync failed, poisoning writer");
            ctx.notify.poison();
            false
        }
    }
}

fn append_batch<S: StorageIO>(
    writer: &mut EventLogWriter<S>,
    events: Vec<ValidEvent>,
    notify: &WriterNotify,
) -> bool {
    let ok = events
        .into_iter()
        .try_for_each(|event| writer.append_valid_event(event));
    if let Err(e) = ok {
        warn!(error = %e, "eventlog append failed, poisoning writer");
        notify.poison();
        return false;
    }
    true
}

fn handle_sync_barrier<S: StorageIO>(
    writer: &mut EventLogWriter<S>,
    response: flume::Sender<io::Result<SyncResult>>,
    ctx: &WriterCtx<'_, S>,
) {
    let mut result = writer.sync();

    if let Ok(ref mut sync_result) = result {
        post_sync(sync_result, ctx);
    }

    let _ = response.send(result);
}

fn handle_freeze<S: StorageIO>(
    writer: &mut EventLogWriter<S>,
    response: flume::Sender<io::Result<FreezeResponse>>,
    resume: flume::Receiver<()>,
    ctx: &WriterCtx<'_, S>,
) {
    let result = writer.sync().map(|mut sync_result| {
        post_sync(&mut sync_result, ctx);

        FreezeResponse {
            synced_through: sync_result.synced_through,
            segment_id: sync_result.segment_id,
            position: sync_result.position,
        }
    });

    let _ = response.send(result);
    let _ = resume.recv();
}

struct CloseOnDrop<'a>(&'a PendingBytesBudget);

impl<'a> Drop for CloseOnDrop<'a> {
    fn drop(&mut self) {
        self.0.close();
    }
}

fn writer_loop<S: StorageIO>(
    receiver: &flume::Receiver<WriterRequest>,
    writer: &mut EventLogWriter<S>,
    ctx: &WriterCtx<'_, S>,
) {
    let _close = CloseOnDrop(ctx.pending_bytes);
    let mut reorder = ReorderBuffer::new(writer.current_seq().next().raw());

    loop {
        if ctx.notify.poisoned.load(Ordering::Acquire) {
            let _ = writer.shutdown();
            break;
        }

        let recv_result = match reorder.has_pending() {
            true => receiver.recv_timeout(REORDER_TIMEOUT),
            false => receiver
                .recv()
                .map_err(|_| flume::RecvTimeoutError::Disconnected),
        };

        match recv_result {
            Err(flume::RecvTimeoutError::Disconnected) => {
                if reorder.has_pending() {
                    let batch = reorder.skip_to_first_available();
                    if !batch.is_empty() && append_batch(writer, batch, ctx.notify) {
                        flush_and_notify(writer, ctx);
                    }
                }
                let _ = writer.shutdown();
                break;
            }
            Err(flume::RecvTimeoutError::Timeout) => {
                if reorder.should_skip_gap() {
                    let batch = reorder.skip_to_first_available();
                    if !batch.is_empty() && append_batch(writer, batch, ctx.notify) {
                        flush_and_notify(writer, ctx);
                    }
                }
                continue;
            }
            Ok(WriterRequest::Shutdown) => {
                if reorder.has_pending() {
                    let batch = reorder.skip_to_first_available();
                    if !batch.is_empty() {
                        append_batch(writer, batch, ctx.notify);
                    }
                }
                let _ = writer.shutdown();
                break;
            }
            Ok(WriterRequest::SyncBarrier { response }) => {
                let batch = reorder.drain_contiguous();
                if !batch.is_empty() {
                    append_batch(writer, batch, ctx.notify);
                }
                handle_sync_barrier(writer, response, ctx);
            }
            Ok(WriterRequest::Freeze { response, resume }) => {
                if reorder.has_pending() {
                    let batch = reorder.skip_to_first_available();
                    if !batch.is_empty() {
                        append_batch(writer, batch, ctx.notify);
                    }
                }
                handle_freeze(writer, response, resume, ctx);
                reorder = ReorderBuffer::new(writer.current_seq().next().raw());
            }
            Ok(WriterRequest::Append(event)) => {
                reorder.insert(event);

                while reorder.pending_count() < MAX_BATCH_SIZE {
                    match receiver.try_recv() {
                        Ok(WriterRequest::Append(e)) => reorder.insert(e),
                        Ok(WriterRequest::Shutdown) => {
                            let batch = reorder.skip_to_first_available();
                            if !batch.is_empty() {
                                append_batch(writer, batch, ctx.notify);
                            }
                            let _ = writer.shutdown();
                            return;
                        }
                        Ok(WriterRequest::SyncBarrier { response }) => {
                            let batch = reorder.drain_contiguous();
                            if !batch.is_empty() && append_batch(writer, batch, ctx.notify) {
                                flush_and_notify(writer, ctx);
                            }
                            handle_sync_barrier(writer, response, ctx);
                            break;
                        }
                        Ok(WriterRequest::Freeze { response, resume }) => {
                            let batch = reorder.drain_contiguous();
                            if !batch.is_empty() && append_batch(writer, batch, ctx.notify) {
                                flush_and_notify(writer, ctx);
                            }
                            handle_freeze(writer, response, resume, ctx);
                            reorder = ReorderBuffer::new(writer.current_seq().next().raw());
                            break;
                        }
                        Err(_) => break,
                    }
                }

                let batch = reorder.drain_contiguous();
                if !batch.is_empty() && append_batch(writer, batch, ctx.notify) {
                    flush_and_notify(writer, ctx);
                }

                if reorder.is_full() {
                    warn!(
                        pending = reorder.pending_count(),
                        "reorder buffer at capacity, force-skipping gap"
                    );
                    let batch = reorder.skip_to_first_available();
                    if !batch.is_empty() && append_batch(writer, batch, ctx.notify) {
                        flush_and_notify(writer, ctx);
                    }
                }
            }
        }
    }
}

fn log_thread_panic(payload: Box<dyn std::any::Any + Send>) {
    let msg = payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(|s| s.as_str()))
        .unwrap_or("unknown panic");
    tracing::error!(panic = msg, "eventlog commit thread panicked");
}

pub struct CommitThread {
    sender: flume::Sender<WriterRequest>,
    handle: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl CommitThread {
    pub fn spawn<S: StorageIO + 'static>(
        mut writer: EventLogWriter<S>,
        reader: Arc<EventLogReader<S>>,
        broadcast_tx: broadcast::Sender<RawEvent>,
        notify: Arc<WriterNotify>,
        synced_seq: Arc<AtomicU64>,
        pending_bytes: Arc<PendingBytesBudget>,
    ) -> io::Result<Self> {
        let (sender, receiver) = flume::unbounded();

        let handle = std::thread::Builder::new()
            .name("eventlog-commit".into())
            .spawn(move || {
                let ctx = WriterCtx {
                    reader: &reader,
                    broadcast_tx: &broadcast_tx,
                    notify: &notify,
                    synced_seq: &synced_seq,
                    pending_bytes: &pending_bytes,
                };
                writer_loop(&receiver, &mut writer, &ctx);
            })
            .map_err(io::Error::other)?;

        Ok(Self {
            sender,
            handle: Mutex::new(Some(handle)),
        })
    }

    pub fn sender(&self) -> &flume::Sender<WriterRequest> {
        &self.sender
    }

    pub fn shutdown(&self) {
        let _ = self.sender.send(WriterRequest::Shutdown);
        if let Some(handle) = self.handle.lock().take()
            && let Err(payload) = handle.join()
        {
            log_thread_panic(payload);
        }
    }
}

impl Drop for CommitThread {
    fn drop(&mut self) {
        let _ = self.sender.try_send(WriterRequest::Shutdown);
        if let Some(handle) = self.handle.lock().take()
            && let Err(payload) = handle.join()
        {
            log_thread_panic(payload);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn close_unblocks_waiter() {
        let budget = Arc::new(PendingBytesBudget::new(1024));
        budget.acquire(1024).unwrap();
        assert_eq!(budget.in_flight(), 1024);

        let budget_blocked = Arc::clone(&budget);
        let blocked = std::thread::spawn(move || budget_blocked.acquire(256));

        std::thread::sleep(Duration::from_millis(100));
        assert!(
            !blocked.is_finished(),
            "acquire must block when budget exhausted"
        );

        budget.close();

        let result = blocked.join().expect("blocked thread must not panic");
        assert!(
            result.is_err(),
            "acquire must error after close, got {result:?}"
        );
    }

    #[test]
    fn close_makes_subsequent_acquire_fail_immediately() {
        let budget = PendingBytesBudget::new(1024);
        budget.close();
        assert!(budget.acquire(1).is_err());
    }

    #[test]
    fn release_after_full_unblocks_waiter() {
        let budget = Arc::new(PendingBytesBudget::new(1024));
        budget.acquire(1024).unwrap();

        let budget_blocked = Arc::clone(&budget);
        let blocked = std::thread::spawn(move || budget_blocked.acquire(256));

        std::thread::sleep(Duration::from_millis(100));
        assert!(!blocked.is_finished());

        budget.release(1024);

        blocked
            .join()
            .expect("thread panic")
            .expect("acquire after release must succeed");
        assert_eq!(budget.in_flight(), 256);
    }

    #[test]
    fn zero_budget_means_unbounded() {
        let budget = PendingBytesBudget::new(0);
        budget.acquire(u64::MAX / 2).unwrap();
        budget.acquire(u64::MAX / 4).unwrap();
        assert!(budget.in_flight() >= u64::MAX / 2);
    }
}
