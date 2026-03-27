use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::StreamExt;
use tokio::sync::oneshot;
use tranquil_db_traits::{
    ApplyCommitInput, CommitEventData, RecordUpsert, RepoEventType, RepoRepository,
};
use tranquil_types::{CidLink, Did, Handle, Nsid, Rkey};
use uuid::Uuid;

use tranquil_store::RealIO;
use tranquil_store::eventlog::{EventLog, EventLogConfig};
use tranquil_store::metastore::handler::{
    CommitRequest, HandlerPool, MetastoreRequest, RecordRequest, RepoRequest,
};
use tranquil_store::metastore::{Metastore, MetastoreConfig};

struct LatencyStats {
    p50: Duration,
    p95: Duration,
    p99: Duration,
    max: Duration,
    mean: Duration,
}

fn compute_stats(durations: &mut [Duration]) -> Option<LatencyStats> {
    match durations.is_empty() {
        true => None,
        false => {
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
    }
}

fn print_result(label: &str, ops: usize, elapsed: Duration, stats: Option<&LatencyStats>) {
    let throughput = ops as f64 / elapsed.as_secs_f64();
    match stats {
        Some(s) => println!(
            "{label}: {throughput:.0} ops/sec, {:.1}ms | p50={:?} p95={:?} p99={:?} max={:?} mean={:?}",
            elapsed.as_secs_f64() * 1000.0,
            s.p50,
            s.p95,
            s.p99,
            s.max,
            s.mean
        ),
        None => println!(
            "{label}: {throughput:.0} ops/sec, {:.1}ms",
            elapsed.as_secs_f64() * 1000.0,
        ),
    }
}

async fn collect_latencies(handles: Vec<tokio::task::JoinHandle<Vec<Duration>>>) -> Vec<Duration> {
    futures::stream::iter(handles)
        .fold(Vec::new(), |mut acc, h| async move {
            acc.extend(h.await.unwrap());
            acc
        })
        .await
}

fn test_cid(seed: u8) -> CidLink {
    let digest: [u8; 32] = std::array::from_fn(|i| seed.wrapping_add(i as u8));
    let mh = multihash::Multihash::<64>::wrap(0x12, &digest).unwrap();
    let c = cid::Cid::new_v1(0x71, mh);
    CidLink::from_cid(&c)
}

fn test_cid_bytes(seed: u8) -> Vec<u8> {
    let digest: [u8; 32] = std::array::from_fn(|i| seed.wrapping_add(i as u8));
    let mh = multihash::Multihash::<64>::wrap(0x12, &digest).unwrap();
    cid::Cid::new_v1(0x71, mh).to_bytes()
}

fn make_rev(n: u64) -> String {
    format!("rev{n:010}")
}

struct BenchHarness {
    pool: Arc<HandlerPool>,
    metastore: Metastore,
    _metastore_dir: tempfile::TempDir,
    _eventlog_dir: tempfile::TempDir,
}

fn cache_size_for_users(user_count: usize) -> u64 {
    let estimated_dataset_bytes = user_count as u64 * 10 * 300;
    let cache_bytes = estimated_dataset_bytes
        .saturating_mul(2)
        .max(512 * 1024 * 1024);
    let cap = 8u64 * 1024 * 1024 * 1024;
    cache_bytes.min(cap)
}

fn setup(thread_count: usize, user_count: usize) -> BenchHarness {
    let cache_bytes = cache_size_for_users(user_count);
    println!(
        "cache size: {} MB (for {user_count} users)",
        cache_bytes / (1024 * 1024)
    );

    let metastore_dir = tempfile::TempDir::new().unwrap();
    let eventlog_dir = tempfile::TempDir::new().unwrap();
    let segments_dir = eventlog_dir.path().join("segments");
    std::fs::create_dir_all(&segments_dir).unwrap();

    let metastore = Metastore::open(
        metastore_dir.path(),
        MetastoreConfig {
            cache_size_bytes: cache_bytes,
        },
    )
    .unwrap();

    let event_log = EventLog::open(
        EventLogConfig {
            segments_dir,
            ..EventLogConfig::default()
        },
        RealIO::new(),
    )
    .unwrap();

    let bridge = Arc::new(tranquil_store::eventlog::EventLogBridge::new(Arc::new(
        event_log,
    )));

    let pool = Arc::new(HandlerPool::spawn::<RealIO>(
        metastore.clone(),
        bridge,
        None,
        Some(thread_count),
    ));

    BenchHarness {
        pool,
        metastore,
        _metastore_dir: metastore_dir,
        _eventlog_dir: eventlog_dir,
    }
}

fn compact_and_report(metastore: &Metastore) {
    println!("running major compaction...");
    let start = Instant::now();
    metastore.major_compact().unwrap();
    println!(
        "major compaction complete in {:.1}s",
        start.elapsed().as_secs_f64()
    );
}

struct UserInfo {
    user_id: Uuid,
    did: Did,
}

async fn seed_users(pool: &HandlerPool, count: usize) -> Vec<UserInfo> {
    let users: Vec<UserInfo> = (0..count)
        .map(|i| {
            let user_id = Uuid::new_v4();
            UserInfo {
                did: Did::from(format!("did:plc:scale{i:06x}{}", user_id.as_simple())),
                user_id,
            }
        })
        .collect();

    let batch_size = 500;
    let batches: Vec<&[UserInfo]> = users.chunks(batch_size).collect();
    let total_batches = batches.len();

    let start = Instant::now();
    futures::stream::iter(batches.into_iter().enumerate())
        .fold((), |(), (batch_idx, batch)| async move {
            futures::stream::iter(batch.iter())
                .fold((), |(), user| async {
                    let (tx, rx) = oneshot::channel();
                    pool.send(MetastoreRequest::Repo(RepoRequest::CreateRepoFull {
                        user_id: user.user_id,
                        did: user.did.clone(),
                        handle: Handle::from(format!(
                            "u{}.scale.invalid",
                            user.user_id.as_simple()
                        )),
                        repo_root_cid: test_cid(1),
                        repo_rev: "rev0000000000".to_string(),
                        tx,
                    }))
                    .unwrap();
                    rx.await.unwrap().unwrap();
                })
                .await;
            if (batch_idx + 1) % 20 == 0 || batch_idx + 1 == total_batches {
                println!(
                    "seeded {}/{} users, {:.1}s",
                    (batch_idx + 1) * batch_size,
                    count,
                    start.elapsed().as_secs_f64()
                );
            }
        })
        .await;
    println!(
        "seeded {} users in {:.1}s, {:.0} users/sec",
        count,
        start.elapsed().as_secs_f64(),
        count as f64 / start.elapsed().as_secs_f64()
    );

    users
}

async fn seed_records_for_user(pool: &HandlerPool, user: &UserInfo, record_count: usize) {
    let collection = Nsid::from("app.bsky.feed.post".to_string());
    let record_upserts: Vec<RecordUpsert> = (0..record_count)
        .map(|i| RecordUpsert {
            collection: collection.clone(),
            rkey: Rkey::from(format!("rec{i:08}")),
            cid: test_cid(((i * 7 + 3) & 0xFF) as u8),
        })
        .collect();

    let new_block_cids: Vec<Vec<u8>> = (0..record_count)
        .map(|i| test_cid_bytes(((i * 11 + 5) & 0xFF) as u8))
        .collect();

    let input = ApplyCommitInput {
        user_id: user.user_id,
        did: user.did.clone(),
        expected_root_cid: None,
        new_root_cid: test_cid(2),
        new_rev: make_rev(1),
        new_block_cids,
        obsolete_block_cids: vec![],
        record_upserts,
        record_deletes: vec![],
        backlinks_to_add: vec![],
        backlinks_to_remove: vec![],
        commit_event: CommitEventData {
            did: user.did.clone(),
            event_type: RepoEventType::Commit,
            commit_cid: Some(test_cid(2)),
            prev_cid: None,
            ops: None,
            blobs: None,
            blocks_cids: None,
            prev_data_cid: None,
            rev: Some(make_rev(1)),
        },
    };

    let (tx, rx) = oneshot::channel();
    pool.send(MetastoreRequest::Commit(Box::new(
        CommitRequest::ApplyCommit {
            input: Box::new(input),
            tx,
        },
    )))
    .unwrap();
    rx.await.unwrap().unwrap();
}

async fn seed_all_records(pool: &Arc<HandlerPool>, users: &[UserInfo], records_per_user: usize) {
    let start = Instant::now();
    let total = users.len();
    let chunk_size = 500;
    let chunks: Vec<&[UserInfo]> = users.chunks(chunk_size).collect();
    let total_chunks = chunks.len();

    futures::stream::iter(chunks.into_iter().enumerate())
        .fold((), |(), (chunk_idx, chunk)| {
            let pool = Arc::clone(pool);
            async move {
                futures::stream::iter(chunk.iter())
                    .fold((), |(), user| {
                        let pool = &pool;
                        async move {
                            seed_records_for_user(pool, user, records_per_user).await;
                        }
                    })
                    .await;
                if (chunk_idx + 1) % 20 == 0 || chunk_idx + 1 == total_chunks {
                    println!(
                        "seeded records for {}/{} users, {:.1}s",
                        (chunk_idx + 1) * chunk_size,
                        total,
                        start.elapsed().as_secs_f64()
                    );
                }
            }
        })
        .await;
    println!(
        "seeded {} records across {} users in {:.1}s",
        total * records_per_user,
        total,
        start.elapsed().as_secs_f64()
    );
}

async fn bench_single_user_commit(pool: &Arc<HandlerPool>, user: &UserInfo, ops: usize) {
    let collection = Nsid::from("app.bsky.feed.post".to_string());
    let start = Instant::now();
    let mut latencies: Vec<Duration> = Vec::with_capacity(ops);

    futures::stream::iter(0..ops)
        .fold(&mut latencies, |latencies, i| {
            let pool = &pool;
            let user = &user;
            let collection = &collection;
            async move {
                let rev_n = (i + 100) as u64;
                let cid_seed = ((i * 7 + 42) & 0xFF) as u8;
                let input = ApplyCommitInput {
                    user_id: user.user_id,
                    did: user.did.clone(),
                    expected_root_cid: None,
                    new_root_cid: test_cid(cid_seed),
                    new_rev: make_rev(rev_n),
                    new_block_cids: vec![test_cid_bytes(cid_seed)],
                    obsolete_block_cids: vec![],
                    record_upserts: vec![RecordUpsert {
                        collection: collection.clone(),
                        rkey: Rkey::from(format!("new{rev_n:010}")),
                        cid: test_cid(cid_seed),
                    }],
                    record_deletes: vec![],
                    backlinks_to_add: vec![],
                    backlinks_to_remove: vec![],
                    commit_event: CommitEventData {
                        did: user.did.clone(),
                        event_type: RepoEventType::Commit,
                        commit_cid: Some(test_cid(cid_seed)),
                        prev_cid: None,
                        ops: None,
                        blobs: None,
                        blocks_cids: None,
                        prev_data_cid: None,
                        rev: Some(make_rev(rev_n)),
                    },
                };
                let t = Instant::now();
                let (tx, rx) = oneshot::channel();
                pool.send(MetastoreRequest::Commit(Box::new(
                    CommitRequest::ApplyCommit {
                        input: Box::new(input),
                        tx,
                    },
                )))
                .unwrap();
                rx.await.unwrap().unwrap();
                latencies.push(t.elapsed());
                latencies
            }
        })
        .await;

    let elapsed = start.elapsed();
    let stats = compute_stats(&mut latencies);
    print_result("single-user commit", ops, elapsed, stats.as_ref());
}

async fn bench_multi_user_commit(
    pool: &Arc<HandlerPool>,
    users: &[UserInfo],
    concurrency: usize,
    ops_per_task: usize,
) {
    let collection = Nsid::from("app.bsky.feed.post".to_string());
    let active_users: Vec<&UserInfo> = users.iter().take(concurrency).collect();

    let start = Instant::now();
    let handles: Vec<_> = active_users
        .iter()
        .enumerate()
        .map(|(task_id, user)| {
            let pool = Arc::clone(pool);
            let user_id = user.user_id;
            let did = user.did.clone();
            let collection = collection.clone();
            tokio::spawn(async move {
                futures::stream::iter(0..ops_per_task)
                    .fold(Vec::with_capacity(ops_per_task), |mut latencies, i| {
                        let pool = &pool;
                        let did = &did;
                        let collection = &collection;
                        async move {
                            let rev_n = (task_id * ops_per_task + i + 200) as u64;
                            let cid_seed = ((task_id * 31 + i * 7) & 0xFF) as u8;
                            let input = ApplyCommitInput {
                                user_id,
                                did: did.clone(),
                                expected_root_cid: None,
                                new_root_cid: test_cid(cid_seed),
                                new_rev: make_rev(rev_n),
                                new_block_cids: vec![test_cid_bytes(cid_seed)],
                                obsolete_block_cids: vec![],
                                record_upserts: vec![RecordUpsert {
                                    collection: collection.clone(),
                                    rkey: Rkey::from(format!("mu{rev_n:010}")),
                                    cid: test_cid(cid_seed),
                                }],
                                record_deletes: vec![],
                                backlinks_to_add: vec![],
                                backlinks_to_remove: vec![],
                                commit_event: CommitEventData {
                                    did: did.clone(),
                                    event_type: RepoEventType::Commit,
                                    commit_cid: Some(test_cid(cid_seed)),
                                    prev_cid: None,
                                    ops: None,
                                    blobs: None,
                                    blocks_cids: None,
                                    prev_data_cid: None,
                                    rev: Some(make_rev(rev_n)),
                                },
                            };
                            let t = Instant::now();
                            let (tx, rx) = oneshot::channel();
                            pool.send(MetastoreRequest::Commit(Box::new(
                                CommitRequest::ApplyCommit {
                                    input: Box::new(input),
                                    tx,
                                },
                            )))
                            .unwrap();
                            rx.await.unwrap().unwrap();
                            latencies.push(t.elapsed());
                            latencies
                        }
                    })
                    .await
            })
        })
        .collect();

    let mut all_latencies = collect_latencies(handles).await;
    let elapsed = start.elapsed();
    let total_ops = concurrency * ops_per_task;
    let stats = compute_stats(&mut all_latencies);
    print_result(
        &format!("multi-user commit ({concurrency} writers)"),
        total_ops,
        elapsed,
        stats.as_ref(),
    );
}

async fn bench_list_records_at_scale(
    pool: &Arc<HandlerPool>,
    users: &[UserInfo],
    concurrency: usize,
    ops_per_task: usize,
) {
    let collection = Nsid::from("app.bsky.feed.post".to_string());
    let user_count = users.len();

    let start = Instant::now();
    let handles: Vec<_> = (0..concurrency)
        .map(|task_id| {
            let pool = Arc::clone(pool);
            let collection = collection.clone();
            let users: Vec<(Uuid, Did)> =
                users.iter().map(|u| (u.user_id, u.did.clone())).collect();
            tokio::spawn(async move {
                futures::stream::iter(0..ops_per_task)
                    .fold(Vec::with_capacity(ops_per_task), |mut latencies, i| {
                        let pool = &pool;
                        let collection = &collection;
                        let users = &users;
                        async move {
                            let idx = (task_id * 997 + i * 31) % user_count;
                            let (user_id, _) = &users[idx];
                            let t = Instant::now();
                            let (tx, rx) = oneshot::channel();
                            pool.send(MetastoreRequest::Record(RecordRequest::ListRecords {
                                repo_id: *user_id,
                                collection: collection.clone(),
                                cursor: None,
                                limit: 50,
                                reverse: false,
                                rkey_start: None,
                                rkey_end: None,
                                tx,
                            }))
                            .unwrap();
                            let _result = rx.await.unwrap().unwrap();
                            latencies.push(t.elapsed());
                            latencies
                        }
                    })
                    .await
            })
        })
        .collect();

    let mut all_latencies = collect_latencies(handles).await;
    let elapsed = start.elapsed();
    let total_ops = concurrency * ops_per_task;
    let stats = compute_stats(&mut all_latencies);
    print_result(
        &format!("listRecords ({concurrency} readers)"),
        total_ops,
        elapsed,
        stats.as_ref(),
    );
}

async fn bench_get_record_at_scale(
    pool: &Arc<HandlerPool>,
    users: &[UserInfo],
    concurrency: usize,
    ops_per_task: usize,
) {
    let collection = Nsid::from("app.bsky.feed.post".to_string());
    let user_count = users.len();
    let records_per_user = 10usize;

    let start = Instant::now();
    let handles: Vec<_> = (0..concurrency)
        .map(|task_id| {
            let pool = Arc::clone(pool);
            let collection = collection.clone();
            let users: Vec<Uuid> = users.iter().map(|u| u.user_id).collect();
            tokio::spawn(async move {
                futures::stream::iter(0..ops_per_task)
                    .fold(Vec::with_capacity(ops_per_task), |mut latencies, i| {
                        let pool = &pool;
                        let collection = &collection;
                        let users = &users;
                        async move {
                            let user_idx = (task_id * 997 + i * 31) % user_count;
                            let rec_idx = (task_id * 13 + i * 7) % records_per_user;
                            let rkey = Rkey::from(format!("rec{rec_idx:08}"));
                            let t = Instant::now();
                            let (tx, rx) = oneshot::channel();
                            pool.send(MetastoreRequest::Record(RecordRequest::GetRecordCid {
                                repo_id: users[user_idx],
                                collection: collection.clone(),
                                rkey,
                                tx,
                            }))
                            .unwrap();
                            let _result = rx.await.unwrap().unwrap();
                            latencies.push(t.elapsed());
                            latencies
                        }
                    })
                    .await
            })
        })
        .collect();

    let mut all_latencies = collect_latencies(handles).await;
    let elapsed = start.elapsed();
    let total_ops = concurrency * ops_per_task;
    let stats = compute_stats(&mut all_latencies);
    print_result(
        &format!("getRecordCid ({concurrency} readers)"),
        total_ops,
        elapsed,
        stats.as_ref(),
    );
}

async fn pg_seed_users(pg: &sqlx::PgPool, count: usize) -> Vec<UserInfo> {
    let users: Vec<UserInfo> = (0..count)
        .map(|i| {
            let user_id = Uuid::new_v4();
            UserInfo {
                did: Did::from(format!("did:plc:pgscale{i:06x}{}", user_id.as_simple())),
                user_id,
            }
        })
        .collect();

    let start = Instant::now();
    let batch_size = 500;
    let batches: Vec<&[UserInfo]> = users.chunks(batch_size).collect();
    let total_batches = batches.len();

    futures::stream::iter(batches.into_iter().enumerate())
        .fold((), |(), (batch_idx, batch)| async move {
            futures::stream::iter(batch.iter())
                .fold((), |(), user| async {
                    sqlx::query(
                        "INSERT INTO users (id, handle, did) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
                    )
                    .bind(user.user_id)
                    .bind(format!("u{}.pgscale.invalid", user.user_id.as_simple()))
                    .bind(user.did.as_str())
                    .execute(pg)
                    .await
                    .unwrap();

                    let repo = tranquil_db::postgres::PostgresRepoRepository::new(pg.clone());
                    let handle = Handle::from(format!(
                        "u{}.pgscale.invalid",
                        user.user_id.as_simple()
                    ));
                    repo.create_repo(user.user_id, &user.did, &handle, &test_cid(1), "rev0000000000")
                        .await
                        .unwrap();
                })
                .await;
            if (batch_idx + 1) % 20 == 0 || batch_idx + 1 == total_batches {
                println!(
                    "seeded {}/{} postgres users, {:.1}s",
                    (batch_idx + 1) * batch_size,
                    count,
                    start.elapsed().as_secs_f64()
                );
            }
        })
        .await;
    println!(
        "seeded {} postgres users in {:.1}s, {:.0} users/sec",
        count,
        start.elapsed().as_secs_f64(),
        count as f64 / start.elapsed().as_secs_f64()
    );

    users
}

async fn pg_seed_all_records(pg: &sqlx::PgPool, users: &[UserInfo], records_per_user: usize) {
    let start = Instant::now();
    let total = users.len();
    let collection = Nsid::from("app.bsky.feed.post".to_string());
    let chunk_size = 500;
    let chunks: Vec<&[UserInfo]> = users.chunks(chunk_size).collect();
    let total_chunks = chunks.len();

    futures::stream::iter(chunks.into_iter().enumerate())
        .fold((), |(), (chunk_idx, chunk)| {
            let collection = collection.clone();
            let pg = pg.clone();
            async move {
                let repo = tranquil_db::postgres::PostgresRepoRepository::new(pg);
                futures::stream::iter(chunk.iter())
                    .fold((), |(), user| {
                        let repo = &repo;
                        let collection = &collection;
                        async move {
                            let collections: Vec<Nsid> =
                                (0..records_per_user).map(|_| collection.clone()).collect();
                            let rkeys: Vec<Rkey> = (0..records_per_user)
                                .map(|i| Rkey::from(format!("rec{i:08}")))
                                .collect();
                            let cids: Vec<CidLink> = (0..records_per_user)
                                .map(|i| test_cid(((i * 7 + 3) & 0xFF) as u8))
                                .collect();
                            repo.upsert_records(
                                user.user_id,
                                &collections,
                                &rkeys,
                                &cids,
                                "rev0000000001",
                            )
                            .await
                            .unwrap();
                        }
                    })
                    .await;
                if (chunk_idx + 1) % 20 == 0 || chunk_idx + 1 == total_chunks {
                    println!(
                        "seeded records for {}/{} postgres users, {:.1}s",
                        (chunk_idx + 1) * chunk_size,
                        total,
                        start.elapsed().as_secs_f64()
                    );
                }
            }
        })
        .await;
    println!(
        "seeded {} postgres records in {:.1}s",
        total * records_per_user,
        start.elapsed().as_secs_f64()
    );
}

async fn bench_pg_single_user_commit(pg: &sqlx::PgPool, user: &UserInfo, ops: usize) {
    let repo = tranquil_db::postgres::PostgresRepoRepository::new(pg.clone());
    let collection = Nsid::from("app.bsky.feed.post".to_string());
    let start = Instant::now();
    let mut latencies: Vec<Duration> = Vec::with_capacity(ops);

    futures::stream::iter(0..ops)
        .fold(&mut latencies, |latencies, i| {
            let repo = &repo;
            let user = &user;
            let collection = &collection;
            async move {
                let rev_n = (i + 100) as u64;
                let cid_seed = ((i * 7 + 42) & 0xFF) as u8;
                let rkey = Rkey::from(format!("new{rev_n:010}"));
                let t = Instant::now();
                repo.upsert_records(
                    user.user_id,
                    std::slice::from_ref(collection),
                    &[rkey],
                    &[test_cid(cid_seed)],
                    &make_rev(rev_n),
                )
                .await
                .unwrap();
                latencies.push(t.elapsed());
                latencies
            }
        })
        .await;

    let elapsed = start.elapsed();
    let stats = compute_stats(&mut latencies);
    print_result("single-user commit", ops, elapsed, stats.as_ref());
}

async fn bench_pg_multi_user_commit(
    pg: &sqlx::PgPool,
    users: &[UserInfo],
    concurrency: usize,
    ops_per_task: usize,
) {
    let collection = Nsid::from("app.bsky.feed.post".to_string());
    let active_users: Vec<&UserInfo> = users.iter().take(concurrency).collect();

    let start = Instant::now();
    let handles: Vec<_> = active_users
        .iter()
        .enumerate()
        .map(|(task_id, user)| {
            let pg = pg.clone();
            let user_id = user.user_id;
            let collection = collection.clone();
            tokio::spawn(async move {
                let repo = tranquil_db::postgres::PostgresRepoRepository::new(pg);
                futures::stream::iter(0..ops_per_task)
                    .fold(Vec::with_capacity(ops_per_task), |mut latencies, i| {
                        let repo = &repo;
                        let collection = &collection;
                        async move {
                            let rev_n = (task_id * ops_per_task + i + 200) as u64;
                            let cid_seed = ((task_id * 31 + i * 7) & 0xFF) as u8;
                            let rkey = Rkey::from(format!("mu{rev_n:010}"));
                            let t = Instant::now();
                            repo.upsert_records(
                                user_id,
                                std::slice::from_ref(collection),
                                &[rkey],
                                &[test_cid(cid_seed)],
                                &make_rev(rev_n),
                            )
                            .await
                            .unwrap();
                            latencies.push(t.elapsed());
                            latencies
                        }
                    })
                    .await
            })
        })
        .collect();

    let mut all_latencies = collect_latencies(handles).await;
    let elapsed = start.elapsed();
    let total_ops = concurrency * ops_per_task;
    let stats = compute_stats(&mut all_latencies);
    print_result(
        &format!("multi-user commit ({concurrency} writers)"),
        total_ops,
        elapsed,
        stats.as_ref(),
    );
}

async fn bench_pg_list_records(
    pg: &sqlx::PgPool,
    users: &[UserInfo],
    concurrency: usize,
    ops_per_task: usize,
) {
    let collection = Nsid::from("app.bsky.feed.post".to_string());
    let user_count = users.len();

    let start = Instant::now();
    let handles: Vec<_> = (0..concurrency)
        .map(|task_id| {
            let pg = pg.clone();
            let collection = collection.clone();
            let user_ids: Vec<Uuid> = users.iter().map(|u| u.user_id).collect();
            tokio::spawn(async move {
                let repo = tranquil_db::postgres::PostgresRepoRepository::new(pg);
                futures::stream::iter(0..ops_per_task)
                    .fold(Vec::with_capacity(ops_per_task), |mut latencies, i| {
                        let repo = &repo;
                        let collection = &collection;
                        let user_ids = &user_ids;
                        async move {
                            let idx = (task_id * 997 + i * 31) % user_count;
                            let t = Instant::now();
                            let _result = repo
                                .list_records(
                                    user_ids[idx],
                                    collection,
                                    None,
                                    50,
                                    false,
                                    None,
                                    None,
                                )
                                .await
                                .unwrap();
                            latencies.push(t.elapsed());
                            latencies
                        }
                    })
                    .await
            })
        })
        .collect();

    let mut all_latencies = collect_latencies(handles).await;
    let elapsed = start.elapsed();
    let total_ops = concurrency * ops_per_task;
    let stats = compute_stats(&mut all_latencies);
    print_result(
        &format!("listRecords ({concurrency} readers)"),
        total_ops,
        elapsed,
        stats.as_ref(),
    );
}

async fn bench_pg_get_record(
    pg: &sqlx::PgPool,
    users: &[UserInfo],
    concurrency: usize,
    ops_per_task: usize,
) {
    let collection = Nsid::from("app.bsky.feed.post".to_string());
    let user_count = users.len();
    let records_per_user = 10usize;

    let start = Instant::now();
    let handles: Vec<_> = (0..concurrency)
        .map(|task_id| {
            let pg = pg.clone();
            let collection = collection.clone();
            let user_ids: Vec<Uuid> = users.iter().map(|u| u.user_id).collect();
            tokio::spawn(async move {
                let repo = tranquil_db::postgres::PostgresRepoRepository::new(pg);
                futures::stream::iter(0..ops_per_task)
                    .fold(Vec::with_capacity(ops_per_task), |mut latencies, i| {
                        let repo = &repo;
                        let collection = &collection;
                        let user_ids = &user_ids;
                        async move {
                            let user_idx = (task_id * 997 + i * 31) % user_count;
                            let rec_idx = (task_id * 13 + i * 7) % records_per_user;
                            let rkey = Rkey::from(format!("rec{rec_idx:08}"));
                            let t = Instant::now();
                            let _result = repo
                                .get_record_cid(user_ids[user_idx], collection, &rkey)
                                .await
                                .unwrap();
                            latencies.push(t.elapsed());
                            latencies
                        }
                    })
                    .await
            })
        })
        .collect();

    let mut all_latencies = collect_latencies(handles).await;
    let elapsed = start.elapsed();
    let total_ops = concurrency * ops_per_task;
    let stats = compute_stats(&mut all_latencies);
    print_result(
        &format!("getRecordCid ({concurrency} readers)"),
        total_ops,
        elapsed,
        stats.as_ref(),
    );
}

async fn setup_pg_bench_schema(pool: &sqlx::PgPool) {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            handle TEXT NOT NULL UNIQUE,
            email TEXT,
            did TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL DEFAULT '',
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            deactivated_at TIMESTAMPTZ,
            invites_disabled BOOLEAN DEFAULT FALSE,
            takedown_ref TEXT,
            preferred_comms_channel TEXT NOT NULL DEFAULT 'email',
            password_reset_code TEXT,
            password_reset_code_expires_at TIMESTAMPTZ,
            email_verified BOOLEAN NOT NULL DEFAULT FALSE,
            two_factor_enabled BOOLEAN NOT NULL DEFAULT FALSE,
            discord_id TEXT,
            discord_verified BOOLEAN NOT NULL DEFAULT FALSE,
            telegram_username TEXT,
            telegram_verified BOOLEAN NOT NULL DEFAULT FALSE,
            signal_number TEXT,
            signal_verified BOOLEAN NOT NULL DEFAULT FALSE,
            is_admin BOOLEAN NOT NULL DEFAULT FALSE,
            migrated_to_pds TEXT,
            migrated_at TIMESTAMPTZ,
            preferred_locale TEXT,
            signal_uuid TEXT
        )",
    )
    .execute(pool)
    .await
    .unwrap();

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS repos (
            user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            repo_root_cid TEXT NOT NULL,
            repo_rev TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )",
    )
    .execute(pool)
    .await
    .unwrap();

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS records (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            repo_id UUID NOT NULL REFERENCES repos(user_id) ON DELETE CASCADE,
            collection TEXT NOT NULL,
            rkey TEXT NOT NULL,
            record_cid TEXT NOT NULL,
            takedown_ref TEXT,
            repo_rev TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE(repo_id, collection, rkey)
        )",
    )
    .execute(pool)
    .await
    .unwrap();

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS user_blocks (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            block_cid BYTEA NOT NULL,
            repo_rev TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE(user_id, block_cid)
        )",
    )
    .execute(pool)
    .await
    .unwrap();
}

#[tokio::main]
async fn main() {
    let handler_threads = std::thread::available_parallelism()
        .map(|n| n.get().max(2) / 2)
        .unwrap_or(2);
    println!("-- metastore scale --");
    println!("handler threads: {handler_threads}");

    let scale_levels: &[usize] = &[1_000, 10_000, 100_000, 300_000];
    let records_per_user = 10;
    let bench_ops = 2000;
    let concurrency = 100;
    let ops_per_writer = 20;

    futures::stream::iter(scale_levels.iter())
        .fold((), |(), &user_count| async move {
            println!("-- tranquil-store, {user_count} users, {records_per_user} records each --");

            let h = setup(handler_threads, user_count);
            let users = seed_users(&h.pool, user_count).await;
            seed_all_records(&h.pool, &users, records_per_user).await;

            compact_and_report(&h.metastore);

            bench_single_user_commit(&h.pool, &users[0], bench_ops).await;

            let writers = concurrency.min(user_count);
            bench_multi_user_commit(&h.pool, &users, writers, ops_per_writer).await;

            let warmup_ops = 50;
            println!("warming read cache, {} ops per task...", warmup_ops);
            bench_list_records_at_scale(&h.pool, &users, concurrency, warmup_ops).await;
            bench_get_record_at_scale(&h.pool, &users, concurrency, warmup_ops).await;

            let read_ops = 500;
            println!("measuring reads, {} ops per task...", read_ops);
            bench_list_records_at_scale(&h.pool, &users, concurrency, read_ops).await;
            bench_get_record_at_scale(&h.pool, &users, concurrency, read_ops).await;
        })
        .await;

    let pg_url = match std::env::var("DATABASE_URL") {
        Ok(url) => url,
        Err(_) => {
            println!("set DATABASE_URL for postgres comparison");
            return;
        }
    };

    let pg_scale_levels: &[usize] = &[1_000, 10_000, 100_000];

    let setup_pg = |max_conns: u32| {
        let url = pg_url.clone();
        async move {
            sqlx::postgres::PgPoolOptions::new()
                .max_connections(max_conns)
                .acquire_timeout(Duration::from_secs(30))
                .connect(&url)
                .await
                .unwrap()
        }
    };

    let pg = setup_pg(60).await;
    setup_pg_bench_schema(&pg).await;
    pg.close().await;

    futures::stream::iter(pg_scale_levels.iter())
        .fold((), |(), &user_count| {
            let setup_pg = &setup_pg;
            async move {
                println!("-- postgres, {user_count} users, {records_per_user} records each --");

                let pg = setup_pg(120).await;

                let users = pg_seed_users(&pg, user_count).await;
                pg_seed_all_records(&pg, &users, records_per_user).await;

                bench_pg_single_user_commit(&pg, &users[0], bench_ops).await;

                let writers = concurrency.min(user_count);
                bench_pg_multi_user_commit(&pg, &users, writers, ops_per_writer).await;

                bench_pg_list_records(&pg, &users, concurrency, ops_per_writer).await;
                bench_pg_get_record(&pg, &users, concurrency, ops_per_writer).await;

                sqlx::query("TRUNCATE user_blocks, records, repos, users CASCADE")
                    .execute(&pg)
                    .await
                    .unwrap();
                pg.close().await;
            }
        })
        .await;

    let pg = setup_pg(5).await;
    sqlx::query("DROP TABLE IF EXISTS user_blocks, records, repos, users CASCADE")
        .execute(&pg)
        .await
        .unwrap();
    pg.close().await;
}
