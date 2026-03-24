use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use chrono::Utc;
use tranquil_db_traits::{RepoEventType, SequenceNumber, SequencedEvent};
use tranquil_types::Did;

use tranquil_store::RealIO;
use tranquil_store::eventlog::{EventLog, EventLogConfig, EventSequence};

fn make_did(index: usize) -> Did {
    let suffix: String = format!("{index:024x}");
    Did::new(format!("did:plc:{suffix}")).unwrap()
}

fn make_event(index: usize) -> SequencedEvent {
    let ops_size = match index % 4 {
        0 => 64,
        1 => 256,
        2 => 1024,
        _ => 4096,
    };

    let ops_payload: String = (0..ops_size)
        .map(|i| ((index.wrapping_mul(31).wrapping_add(i)) % 26 + 97) as u8 as char)
        .collect();

    SequencedEvent {
        seq: SequenceNumber::from_raw(i64::try_from(index + 1).expect("event index overflow")),
        did: make_did(index % 10_000),
        created_at: Utc::now(),
        event_type: match index % 4 {
            0 => RepoEventType::Commit,
            1 => RepoEventType::Identity,
            2 => RepoEventType::Account,
            _ => RepoEventType::Sync,
        },
        commit_cid: None,
        prev_cid: None,
        prev_data_cid: None,
        ops: Some(serde_json::json!({ "data": ops_payload })),
        blobs: None,
        blocks_cids: None,
        handle: None,
        active: None,
        status: None,
        rev: None,
    }
}

fn estimated_payload_size(event: &SequencedEvent) -> usize {
    tranquil_store::eventlog::encode_payload(event).len()
}

struct LatencyStats {
    p50: Duration,
    p95: Duration,
    p99: Duration,
    max: Duration,
    mean: Duration,
}

fn compute_stats(durations: &mut [Duration]) -> Option<LatencyStats> {
    if durations.is_empty() {
        return None;
    }
    durations.sort();
    let len = durations.len();
    let sum: Duration = durations.iter().sum();
    let divisor = u32::try_from(len).unwrap_or(u32::MAX);
    let last = len - 1;
    Some(LatencyStats {
        p50: durations[last * 50 / 100],
        p95: durations[last * 95 / 100],
        p99: durations[last * 99 / 100],
        max: durations[last],
        mean: sum / divisor,
    })
}

fn format_latency(stats: Option<&LatencyStats>) -> String {
    match stats {
        Some(s) => format!(
            " | p50={:?} p95={:?} p99={:?} max={:?} mean={:?}",
            s.p50, s.p95, s.p99, s.max, s.mean
        ),
        None => String::new(),
    }
}

fn open_eventlog(dir: &Path) -> EventLog<RealIO> {
    let segments_dir = dir.join("segments");
    std::fs::create_dir_all(&segments_dir).unwrap();
    EventLog::open(
        EventLogConfig {
            segments_dir,
            ..EventLogConfig::default()
        },
        RealIO::new(),
    )
    .unwrap()
}

fn bench_sequential_append(event_count: usize) {
    println!("-- sequential append: {event_count} events --");
    let dir = tempfile::TempDir::new().unwrap();
    let log = open_eventlog(dir.path());

    let events: Vec<SequencedEvent> = (0..event_count).map(make_event).collect();
    let total_bytes: usize = events.iter().map(estimated_payload_size).sum();
    let mut latencies = Vec::with_capacity(event_count);

    let start = Instant::now();
    events.iter().enumerate().for_each(|(i, event)| {
        let t = Instant::now();
        log.append_event(&make_did(i % 10_000), RepoEventType::Commit, event)
            .unwrap();
        if (i + 1) % 256 == 0 {
            log.sync().unwrap();
        }
        latencies.push(t.elapsed());
    });
    log.sync().unwrap();
    let elapsed = start.elapsed();

    let lat = format_latency(compute_stats(&mut latencies).as_ref());
    println!(
        "{:.0} events/sec, {:.1} MB/sec, {:.1}ms{lat}",
        event_count as f64 / elapsed.as_secs_f64(),
        total_bytes as f64 / elapsed.as_secs_f64() / (1024.0 * 1024.0),
        elapsed.as_secs_f64() * 1000.0,
    );
    let _ = log.shutdown();
}

fn bench_concurrent_producers(event_count: usize, producers: usize) {
    println!("-- {producers} concurrent producers, {event_count} total events --");
    let dir = tempfile::TempDir::new().unwrap();
    let log = Arc::new(open_eventlog(dir.path()));

    let events_per_producer = event_count / producers;
    let actual_count = events_per_producer * producers;
    let avg_payload: usize = (0..4)
        .map(|i| estimated_payload_size(&make_event(i)))
        .sum::<usize>()
        / 4;

    let start = Instant::now();

    let handles: Vec<_> = (0..producers)
        .map(|pid| {
            let log = Arc::clone(&log);
            std::thread::spawn(move || {
                let mut latencies = Vec::with_capacity(events_per_producer);
                (0..events_per_producer).for_each(|i| {
                    let global = pid * events_per_producer + i;
                    let event = make_event(global);
                    let t = Instant::now();
                    log.append_and_sync(&make_did(global % 10_000), RepoEventType::Commit, &event)
                        .unwrap();
                    latencies.push(t.elapsed());
                });
                latencies
            })
        })
        .collect();

    let mut all_latencies: Vec<Duration> = handles
        .into_iter()
        .flat_map(|h| h.join().unwrap())
        .collect();
    let elapsed = start.elapsed();

    let total_bytes = actual_count * avg_payload;
    let lat = format_latency(compute_stats(&mut all_latencies).as_ref());
    println!(
        "{:.0} events/sec, {:.1} MB/sec, {:.1}ms{lat}",
        actual_count as f64 / elapsed.as_secs_f64(),
        total_bytes as f64 / elapsed.as_secs_f64() / (1024.0 * 1024.0),
        elapsed.as_secs_f64() * 1000.0,
    );
    let _ = log.shutdown();
}

fn bench_batch_append(event_count: usize, batch_size: usize) {
    println!("-- batch append: {event_count} events, batch_size={batch_size} --");
    let dir = tempfile::TempDir::new().unwrap();
    let log = open_eventlog(dir.path());

    let events: Vec<SequencedEvent> = (0..event_count).map(make_event).collect();
    let dids: Vec<Did> = (0..event_count).map(|i| make_did(i % 10_000)).collect();
    let total_bytes: usize = events.iter().map(estimated_payload_size).sum();
    let mut batch_latencies = Vec::with_capacity(event_count / batch_size + 1);

    let start = Instant::now();
    events
        .chunks(batch_size)
        .enumerate()
        .for_each(|(chunk_idx, chunk)| {
            let base = chunk_idx * batch_size;
            let batch: Vec<(&Did, RepoEventType, &SequencedEvent)> = chunk
                .iter()
                .enumerate()
                .map(|(j, event)| (&dids[base + j], RepoEventType::Commit, event))
                .collect();
            let t = Instant::now();
            log.append_batch(batch).unwrap();
            log.sync().unwrap();
            batch_latencies.push(t.elapsed());
        });
    let elapsed = start.elapsed();

    let lat = format_latency(compute_stats(&mut batch_latencies).as_ref());
    println!(
        "{:.0} events/sec, {:.1} MB/sec, {:.1}ms{lat}",
        event_count as f64 / elapsed.as_secs_f64(),
        total_bytes as f64 / elapsed.as_secs_f64() / (1024.0 * 1024.0),
        elapsed.as_secs_f64() * 1000.0,
    );
    let _ = log.shutdown();
}

fn bench_rotation_under_load(event_count: usize) {
    println!("-- rotation: {event_count} events, 256KB segments --");
    let dir = tempfile::TempDir::new().unwrap();
    let segments_dir = dir.path().join("segments");
    std::fs::create_dir_all(&segments_dir).unwrap();
    let log = EventLog::open(
        EventLogConfig {
            segments_dir,
            max_segment_size: 256 * 1024,
            ..EventLogConfig::default()
        },
        RealIO::new(),
    )
    .unwrap();

    let events: Vec<SequencedEvent> = (0..event_count).map(make_event).collect();
    let append_latencies = Vec::with_capacity(event_count);
    let rotation_latencies = Vec::new();

    let start = Instant::now();
    let (mut append_latencies, mut rotation_latencies, _) = events.iter().enumerate().fold(
        (append_latencies, rotation_latencies, false),
        |(mut appends, mut rotations, fd_limited), (i, event)| {
            let t = Instant::now();
            log.append_and_sync(&make_did(i % 10_000), RepoEventType::Commit, event)
                .unwrap();
            appends.push(t.elapsed());

            match fd_limited {
                true => (appends, rotations, true),
                false => {
                    let rt = Instant::now();
                    match log.maybe_rotate() {
                        Ok(true) => {
                            rotations.push(rt.elapsed());
                            (appends, rotations, false)
                        }
                        Ok(false) => (appends, rotations, false),
                        Err(e) => {
                            println!("fd limit hit at {} segments: {e}", log.segment_count());
                            (appends, rotations, true)
                        }
                    }
                }
            }
        },
    );
    let elapsed = start.elapsed();

    let append_lat = format_latency(compute_stats(&mut append_latencies).as_ref());
    let rotation_lat = format_latency(compute_stats(&mut rotation_latencies).as_ref());
    println!(
        "{:.0} events/sec, {} segments, {} rotations, {:.1}ms",
        event_count as f64 / elapsed.as_secs_f64(),
        log.segment_count(),
        rotation_latencies.len(),
        elapsed.as_secs_f64() * 1000.0,
    );
    println!("append{append_lat}");
    println!("rotation{rotation_lat}");
    let _ = log.shutdown();
}

fn scan_all_events(log: &EventLog<RealIO>, batch_size: usize) -> usize {
    scan_all_events_from(log, EventSequence::BEFORE_ALL, batch_size, 0)
}

fn scan_all_events_from(
    log: &EventLog<RealIO>,
    cursor: EventSequence,
    batch_size: usize,
    accumulated: usize,
) -> usize {
    let batch = log.get_events_since(cursor, batch_size).unwrap();
    match batch.last() {
        None => accumulated,
        Some(last) => {
            let next_cursor = EventSequence::new(u64::try_from(last.seq.as_i64()).unwrap());
            scan_all_events_from(log, next_cursor, batch_size, accumulated + batch.len())
        }
    }
}

fn bench_sequential_scan(event_count: usize) {
    println!("-- sequential scan: {event_count} events --");
    let dir = tempfile::TempDir::new().unwrap();
    let log = open_eventlog(dir.path());

    let events: Vec<SequencedEvent> = (0..event_count).map(make_event).collect();
    let total_bytes: usize = events.iter().map(estimated_payload_size).sum();

    events.iter().enumerate().for_each(|(i, event)| {
        log.append_event(&make_did(i % 10_000), RepoEventType::Commit, event)
            .unwrap();
    });
    log.sync().unwrap();

    let start = Instant::now();
    let read_count = scan_all_events(&log, 4096);
    let elapsed = start.elapsed();

    println!(
        "{:.0} events/sec, {:.1} MB/sec, {read_count} events, {:.1}ms",
        read_count as f64 / elapsed.as_secs_f64(),
        total_bytes as f64 / elapsed.as_secs_f64() / (1024.0 * 1024.0),
        elapsed.as_secs_f64() * 1000.0,
    );
    let _ = log.shutdown();
}

fn bench_parallel_readers(event_count: usize, readers: usize) {
    println!("-- parallel readers: {event_count} events, {readers} readers --");
    let dir = tempfile::TempDir::new().unwrap();
    let log = Arc::new(open_eventlog(dir.path()));

    let events: Vec<SequencedEvent> = (0..event_count).map(make_event).collect();

    events.iter().enumerate().for_each(|(i, event)| {
        log.append_event(&make_did(i % 10_000), RepoEventType::Commit, event)
            .unwrap();
    });
    log.sync().unwrap();

    let total_read = Arc::new(AtomicU64::new(0));
    let batch_size = 4096;

    let start = Instant::now();

    let handles: Vec<_> = (0..readers)
        .map(|_| {
            let log = Arc::clone(&log);
            let total_read = Arc::clone(&total_read);
            std::thread::spawn(move || {
                let count = scan_all_events(&log, batch_size) as u64;
                total_read.fetch_add(count, Ordering::Relaxed);
            })
        })
        .collect();

    handles.into_iter().for_each(|h| h.join().unwrap());
    let elapsed = start.elapsed();

    let total = total_read.load(Ordering::Relaxed);
    let avg_payload: usize = (0..4)
        .map(|i| estimated_payload_size(&make_event(i)))
        .sum::<usize>()
        / 4;
    println!(
        "{:.0} total events/sec across {readers} readers ({:.0} per reader)",
        total as f64 / elapsed.as_secs_f64(),
        (total as f64 / readers as f64) / elapsed.as_secs_f64(),
    );
    println!(
        "aggregate {:.1} MB/sec, {:.1}ms",
        (total as f64 * avg_payload as f64) / elapsed.as_secs_f64() / (1024.0 * 1024.0),
        elapsed.as_secs_f64() * 1000.0,
    );
    let _ = log.shutdown();
}

fn bench_stampede(event_count: usize, producers: usize, readers: usize, subscribers: usize) {
    println!(
        "-- stampede: {event_count} events, {producers} producers, {readers} readers, {subscribers} subscribers --"
    );
    let dir = tempfile::TempDir::new().unwrap();
    let log = Arc::new(open_eventlog(dir.path()));

    let events_per_producer = event_count / producers;
    let actual_events = events_per_producer * producers;

    let writes_done = Arc::new(AtomicBool::new(false));
    let total_written = Arc::new(AtomicU64::new(0));
    let total_read = Arc::new(AtomicU64::new(0));
    let total_subscribed = Arc::new(AtomicU64::new(0));

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();

    let start = Instant::now();

    let subscriber_handles: Vec<_> = (0..subscribers)
        .map(|_| {
            let log = Arc::clone(&log);
            let writes_done = Arc::clone(&writes_done);
            let total_subscribed = Arc::clone(&total_subscribed);
            let total_written = Arc::clone(&total_written);
            rt.spawn(async move {
                let mut sub = log.subscriber(EventSequence::BEFORE_ALL);
                let mut count = 0u64;
                loop {
                    match tokio::time::timeout(Duration::from_millis(100), sub.next()).await {
                        Ok(Some(_)) => {
                            count += 1;
                        }
                        Ok(None) => break,
                        Err(_) => {
                            if writes_done.load(Ordering::Acquire) {
                                let written = total_written.load(Ordering::Acquire);
                                if count >= written {
                                    break;
                                }
                                match tokio::time::timeout(Duration::from_secs(2), sub.next()).await
                                {
                                    Ok(Some(_)) => count += 1,
                                    _ => break,
                                }
                            }
                        }
                    }
                }
                total_subscribed.fetch_add(count, Ordering::Relaxed);
            })
        })
        .collect();

    let writer_handles: Vec<_> = (0..producers)
        .map(|pid| {
            let log = Arc::clone(&log);
            let total_written = Arc::clone(&total_written);
            std::thread::spawn(move || {
                let mut latencies = Vec::with_capacity(events_per_producer);
                (0..events_per_producer).for_each(|i| {
                    let global = pid * events_per_producer + i;
                    let event = make_event(global);
                    let t = Instant::now();
                    log.append_and_sync(&make_did(global % 10_000), RepoEventType::Commit, &event)
                        .unwrap();
                    latencies.push(t.elapsed());
                    total_written.fetch_add(1, Ordering::Release);
                });
                latencies
            })
        })
        .collect();

    let reader_handles: Vec<_> = (0..readers)
        .map(|_| {
            let log = Arc::clone(&log);
            let writes_done = Arc::clone(&writes_done);
            let total_read = Arc::clone(&total_read);
            std::thread::spawn(move || {
                let mut cursor = EventSequence::BEFORE_ALL;
                let mut count = 0u64;
                loop {
                    let batch = log.get_events_since(cursor, 1024).unwrap();
                    match batch.last() {
                        Some(last) => {
                            count += batch.len() as u64;
                            cursor = EventSequence::new(u64::try_from(last.seq.as_i64()).unwrap());
                        }
                        None if writes_done.load(Ordering::Acquire) => {
                            let final_batch = log.get_events_since(cursor, 1024).unwrap();
                            match final_batch.last() {
                                Some(last) => {
                                    count += final_batch.len() as u64;
                                    cursor = EventSequence::new(
                                        u64::try_from(last.seq.as_i64()).unwrap(),
                                    );
                                }
                                None => break,
                            }
                        }
                        None => {
                            std::thread::yield_now();
                        }
                    }
                }
                total_read.fetch_add(count, Ordering::Relaxed);
            })
        })
        .collect();

    let mut write_latencies: Vec<Duration> = writer_handles
        .into_iter()
        .flat_map(|h| h.join().unwrap())
        .collect();
    let write_elapsed = start.elapsed();

    writes_done.store(true, Ordering::Release);

    reader_handles.into_iter().for_each(|h| h.join().unwrap());
    let read_elapsed = start.elapsed();

    rt.block_on(async {
        let _ = tokio::time::timeout(
            Duration::from_secs(10),
            futures::future::join_all(subscriber_handles),
        )
        .await;
    });
    let total_elapsed = start.elapsed();

    let reads = total_read.load(Ordering::Relaxed);
    let subscribed = total_subscribed.load(Ordering::Relaxed);

    let write_lat = format_latency(compute_stats(&mut write_latencies).as_ref());
    println!(
        "writes: {:.0} events/sec, {actual_events} events, {:.1}ms{write_lat}",
        actual_events as f64 / write_elapsed.as_secs_f64(),
        write_elapsed.as_secs_f64() * 1000.0,
    );
    println!(
        "reads: {:.0} events/sec, {readers} readers, {reads} events, {:.1}ms",
        reads as f64 / read_elapsed.as_secs_f64(),
        read_elapsed.as_secs_f64() * 1000.0,
    );
    println!(
        "subscribers: {subscribed} events across {subscribers} subscribers, {:.1}ms",
        total_elapsed.as_secs_f64() * 1000.0,
    );
    println!("segments: {}", log.segment_count());
    let _ = log.shutdown();
}

fn bench_broadcast_fanout(subscriber_count: usize) {
    println!("-- broadcast fanout: 10000 events, {subscriber_count} subscribers --");
    let dir = tempfile::TempDir::new().unwrap();
    let log = Arc::new(open_eventlog(dir.path()));

    let event_count = 10_000usize;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(8),
        )
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let received_counts: Arc<Vec<AtomicU64>> =
            Arc::new((0..subscriber_count).map(|_| AtomicU64::new(0)).collect());

        let sub_handles: Vec<_> = (0..subscriber_count)
            .map(|sub_id| {
                let mut subscriber = log.subscriber(EventSequence::BEFORE_ALL);
                let received_counts = Arc::clone(&received_counts);
                tokio::spawn(async move {
                    let mut count = 0u64;
                    while count < event_count as u64 {
                        match tokio::time::timeout(Duration::from_secs(10), subscriber.next()).await
                        {
                            Ok(Some(_)) => count += 1,
                            _ => break,
                        }
                    }
                    received_counts[sub_id].store(count, Ordering::Relaxed);
                })
            })
            .collect();

        let log_writer = Arc::clone(&log);
        let write_handle = tokio::task::spawn_blocking(move || {
            let mut latencies = Vec::with_capacity(event_count);
            (0..event_count).for_each(|i| {
                let event = make_event(i);
                let t = Instant::now();
                log_writer
                    .append_and_sync(&make_did(i % 10_000), RepoEventType::Commit, &event)
                    .unwrap();
                latencies.push(t.elapsed());
            });
            latencies
        });

        let mut write_latencies = write_handle.await.unwrap();

        let _ = tokio::time::timeout(
            Duration::from_secs(30),
            futures::future::join_all(sub_handles),
        )
        .await;

        let total_received: u64 = received_counts
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .sum();
        let min_received = received_counts
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .min()
            .unwrap_or(0);

        let write_lat = format_latency(compute_stats(&mut write_latencies).as_ref());
        println!("write{write_lat}");
        println!(
            "total received: {total_received}/{}, min per sub: {min_received}/{event_count}",
            event_count as u64 * subscriber_count as u64,
        );
    });

    let _ = log.shutdown();
}

async fn bench_pg_write_throughput(event_count: usize, concurrency: usize) {
    let database_url = match std::env::var("DATABASE_URL") {
        Ok(url) => url,
        Err(_) => {
            println!("skipped, set DATABASE_URL to enable");
            return;
        }
    };

    let max_conns = u32::try_from(concurrency)
        .unwrap_or(u32::MAX)
        .saturating_add(10);
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(max_conns)
        .acquire_timeout(Duration::from_secs(30))
        .connect(&database_url)
        .await
        .unwrap();

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS bench_repo_seq (
            seq BIGSERIAL PRIMARY KEY,
            did TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            event_type TEXT NOT NULL,
            ops JSONB
        )",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("TRUNCATE bench_repo_seq")
        .execute(&pool)
        .await
        .unwrap();

    let events_per_task = event_count / concurrency;
    let actual_count = events_per_task * concurrency;

    let start = Instant::now();

    let handles: Vec<_> = (0..concurrency)
        .map(|task_id| {
            let pool = pool.clone();
            tokio::spawn(async move {
                futures::stream::iter(0..events_per_task)
                    .then(|i| {
                        let pool = pool.clone();
                        async move {
                            let global = task_id * events_per_task + i;
                            let did = format!("did:plc:{global:024x}");
                            let ops_size = match global % 4 {
                                0 => 64,
                                1 => 256,
                                2 => 1024,
                                _ => 4096,
                            };
                            let payload: String = (0..ops_size)
                                .map(|j| {
                                    ((global.wrapping_mul(31).wrapping_add(j)) % 26 + 97) as u8
                                        as char
                                })
                                .collect();
                            let ops = serde_json::json!({ "data": payload });
                            let t = Instant::now();
                            sqlx::query(
                                "INSERT INTO bench_repo_seq (did, event_type, ops) VALUES ($1, $2, $3)",
                            )
                            .bind(&did)
                            .bind("commit")
                            .bind(&ops)
                            .execute(&pool)
                            .await
                            .unwrap();
                            t.elapsed()
                        }
                    })
                    .collect::<Vec<Duration>>()
                    .await
            })
        })
        .collect();

    let mut all_latencies: Vec<Duration> = futures::future::join_all(handles)
        .await
        .into_iter()
        .flat_map(Result::unwrap)
        .collect();
    let elapsed = start.elapsed();

    let lat = format_latency(compute_stats(&mut all_latencies).as_ref());
    println!(
        "{:.0} events/sec, {:.1}ms{lat}",
        actual_count as f64 / elapsed.as_secs_f64(),
        elapsed.as_secs_f64() * 1000.0,
    );

    sqlx::query("TRUNCATE bench_repo_seq")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}

async fn bench_pg_read_throughput(event_count: usize, concurrency: usize) {
    let database_url = match std::env::var("DATABASE_URL") {
        Ok(url) => url,
        Err(_) => {
            println!("skipped, set DATABASE_URL to enable");
            return;
        }
    };

    let max_conns = u32::try_from(concurrency)
        .unwrap_or(u32::MAX)
        .saturating_add(5);
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(max_conns)
        .connect(&database_url)
        .await
        .unwrap();

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS bench_repo_seq (
            seq BIGSERIAL PRIMARY KEY,
            did TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            event_type TEXT NOT NULL,
            ops JSONB
        )",
    )
    .execute(&pool)
    .await
    .unwrap();

    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM bench_repo_seq")
        .fetch_one(&pool)
        .await
        .unwrap();
    if (row.0 as usize) < event_count {
        sqlx::query("TRUNCATE bench_repo_seq")
            .execute(&pool)
            .await
            .unwrap();
        println!("populating {event_count} events");
        futures::stream::iter(0..event_count)
            .map(|i| {
                let pool = pool.clone();
                async move {
                    let did = format!("did:plc:{i:024x}");
                    let ops = serde_json::json!({ "data": "x".repeat(256) });
                    sqlx::query(
                        "INSERT INTO bench_repo_seq (did, event_type, ops) VALUES ($1, $2, $3)",
                    )
                    .bind(&did)
                    .bind("commit")
                    .bind(&ops)
                    .execute(&pool)
                    .await
                    .unwrap();
                }
            })
            .buffer_unordered(50)
            .collect::<Vec<()>>()
            .await;
    }

    let total_events = Arc::new(AtomicU64::new(0));

    let start = Instant::now();

    let handles: Vec<_> = (0..concurrency)
        .map(|_| {
            let pool = pool.clone();
            let total_events = Arc::clone(&total_events);
            tokio::spawn(async move {
                let mut cursor = 0i64;
                let mut count = 0u64;
                loop {
                    let rows: Vec<(i64,)> = sqlx::query_as(
                        "SELECT seq FROM bench_repo_seq WHERE seq > $1 ORDER BY seq LIMIT $2",
                    )
                    .bind(cursor)
                    .bind(1000i64)
                    .fetch_all(&pool)
                    .await
                    .unwrap();
                    if rows.is_empty() {
                        break;
                    }
                    count += rows.len() as u64;
                    cursor = rows.last().unwrap().0;
                }
                total_events.fetch_add(count, Ordering::Relaxed);
            })
        })
        .collect();

    futures::future::join_all(handles).await;
    let elapsed = start.elapsed();

    let total = total_events.load(Ordering::Relaxed);
    println!(
        "{:.0} total events/sec across {concurrency} readers, {total} events, {:.1}ms",
        total as f64 / elapsed.as_secs_f64(),
        elapsed.as_secs_f64() * 1000.0,
    );

    pool.close().await;
}

fn main() {
    println!("-- eventlog benchmarks --");
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(8);
    println!("available parallelism: {cpus}");

    let parse_env_list = |var: &str, defaults: Vec<usize>| -> Vec<usize> {
        std::env::var(var).map_or(defaults, |s| {
            s.split(',')
                .map(|n| {
                    n.trim()
                        .replace('_', "")
                        .parse::<usize>()
                        .unwrap_or_else(|e| panic!("{var}: {e}"))
                })
                .collect()
        })
    };

    let event_counts = parse_env_list("BENCH_EVENT_COUNTS", vec![10_000, 100_000]);
    let large_event_counts = parse_env_list("BENCH_LARGE_EVENT_COUNTS", vec![1_000_000]);
    let producer_counts = parse_env_list("BENCH_PRODUCERS", vec![1, 10, 50, 100, 500]);

    let all_write_counts: Vec<usize> = event_counts
        .iter()
        .chain(large_event_counts.iter())
        .copied()
        .collect();

    println!("event counts: {event_counts:?}, large: {large_event_counts:?}");
    println!("producer counts: {producer_counts:?}");

    println!("-- write throughput --");

    all_write_counts.iter().for_each(|&n| {
        bench_sequential_append(n);
    });

    all_write_counts.iter().for_each(|&n| {
        producer_counts.iter().for_each(|&p| {
            if n >= p {
                bench_concurrent_producers(n, p);
            }
        });
    });

    all_write_counts.iter().for_each(|&n| {
        [256usize, 1024, 4096].iter().for_each(|&batch| {
            bench_batch_append(n, batch);
        });
    });

    println!("-- rotation --");

    event_counts.iter().for_each(|&n| {
        bench_rotation_under_load(n);
    });

    println!("-- read throughput --");

    event_counts.iter().for_each(|&n| {
        bench_sequential_scan(n);
    });

    event_counts.iter().for_each(|&n| {
        [2usize, 4, 8, 16, 32].iter().for_each(|&r| {
            bench_parallel_readers(n, r);
        });
    });

    println!("-- broadcast fanout --");

    [1usize, 10, 100, 500, 1000].iter().for_each(|&s| {
        bench_broadcast_fanout(s);
    });

    println!("-- stampede --");

    bench_stampede(100_000, 50, 8, 10);
    bench_stampede(100_000, 100, 16, 50);
    bench_stampede(500_000, 100, 16, 50);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(cpus)
        .enable_all()
        .build()
        .unwrap();

    if std::env::var("DATABASE_URL").is_ok() {
        println!("-- postgres comparison --");

        event_counts.iter().for_each(|&n| {
            producer_counts.iter().for_each(|&p| {
                if n >= p {
                    println!("-- postgres write: {n} events, {p} writers --",);
                    rt.block_on(bench_pg_write_throughput(n, p));
                }
            });
        });

        event_counts.iter().for_each(|&n| {
            [1usize, 4, 16, 32].iter().for_each(|&r| {
                println!("-- postgres read: {n} events, {r} readers --",);
                rt.block_on(bench_pg_read_throughput(n, r));
            });
        });

        rt.block_on(async {
            let url = std::env::var("DATABASE_URL").unwrap();
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(5)
                .connect(&url)
                .await
                .unwrap();
            sqlx::query("DROP TABLE IF EXISTS bench_repo_seq")
                .execute(&pool)
                .await
                .unwrap();
            pool.close().await;
        });
    } else {
        println!("set DATABASE_URL for postgres comparison");
    }
}
