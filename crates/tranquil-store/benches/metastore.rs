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

fn print_result(ops: usize, elapsed: Duration, stats: Option<&LatencyStats>) {
    let throughput = ops as f64 / elapsed.as_secs_f64();
    match stats {
        Some(s) => println!(
            "{throughput:.0} ops/sec, {:.1}ms | p50={:?} p95={:?} p99={:?} max={:?} mean={:?}",
            elapsed.as_secs_f64() * 1000.0,
            s.p50,
            s.p95,
            s.p99,
            s.max,
            s.mean
        ),
        None => println!(
            "{throughput:.0} ops/sec, {:.1}ms",
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
    _metastore_dir: tempfile::TempDir,
    _eventlog_dir: tempfile::TempDir,
}

fn setup(thread_count: usize) -> BenchHarness {
    let metastore_dir = tempfile::TempDir::new().unwrap();
    let eventlog_dir = tempfile::TempDir::new().unwrap();
    let segments_dir = eventlog_dir.path().join("segments");
    std::fs::create_dir_all(&segments_dir).unwrap();

    let metastore = Metastore::open(
        metastore_dir.path(),
        MetastoreConfig {
            cache_size_bytes: 256 * 1024 * 1024,
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
        metastore,
        bridge,
        None,
        Some(thread_count),
    ));

    BenchHarness {
        pool,
        _metastore_dir: metastore_dir,
        _eventlog_dir: eventlog_dir,
    }
}

async fn create_user(pool: &HandlerPool, user_id: Uuid, did: &Did, cid: &CidLink) {
    let (tx, rx) = oneshot::channel();
    pool.send(MetastoreRequest::Repo(RepoRequest::CreateRepoFull {
        user_id,
        did: did.clone(),
        handle: Handle::from(format!("bench.{}.invalid", user_id.as_simple())),
        repo_root_cid: cid.clone(),
        repo_rev: "rev0000000000".to_string(),
        tx,
    }))
    .unwrap();
    rx.await.unwrap().unwrap();
}

fn make_commit_input(
    user_id: Uuid,
    did: &Did,
    collection: &Nsid,
    rev_n: u64,
    cid_seed: u8,
) -> ApplyCommitInput {
    ApplyCommitInput {
        user_id,
        did: did.clone(),
        expected_root_cid: None,
        new_root_cid: test_cid(cid_seed),
        new_rev: make_rev(rev_n),
        new_block_cids: vec![test_cid_bytes(cid_seed)],
        obsolete_block_cids: vec![],
        record_upserts: vec![RecordUpsert {
            collection: collection.clone(),
            rkey: Rkey::from(format!("r{rev_n:010}")),
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
    }
}

async fn seed_records(
    pool: &HandlerPool,
    user_id: Uuid,
    did: &Did,
    collection: &Nsid,
    count: usize,
) {
    let batches: Vec<(usize, usize, u64, u8)> = (0..)
        .map(|i| {
            let start = i * 50;
            let end = (start + 50).min(count);
            let rev_n = (i as u64) + 1;
            let cid_seed = ((i + 10) & 0xFF) as u8;
            (start, end, rev_n, cid_seed)
        })
        .take_while(|(start, _, _, _)| *start < count)
        .collect();

    futures::stream::iter(batches)
        .fold((), |(), (batch_start, batch_end, rev_n, cid_seed)| {
            let did = did.clone();
            let collection = collection.clone();
            async move {
                let record_upserts: Vec<RecordUpsert> = (batch_start..batch_end)
                    .map(|i| RecordUpsert {
                        collection: collection.clone(),
                        rkey: Rkey::from(format!("rec{i:08}")),
                        cid: test_cid(((i * 7 + 3) & 0xFF) as u8),
                    })
                    .collect();

                let new_block_cids: Vec<Vec<u8>> = (batch_start..batch_end)
                    .map(|i| test_cid_bytes(((i * 11 + 5) & 0xFF) as u8))
                    .collect();

                let input = ApplyCommitInput {
                    user_id,
                    did: did.clone(),
                    expected_root_cid: None,
                    new_root_cid: test_cid(cid_seed),
                    new_rev: make_rev(rev_n),
                    new_block_cids,
                    obsolete_block_cids: vec![],
                    record_upserts,
                    record_deletes: vec![],
                    backlinks_to_add: vec![],
                    backlinks_to_remove: vec![],
                    commit_event: CommitEventData {
                        did,
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
        })
        .await;
}

async fn bench_apply_commit(pool: &Arc<HandlerPool>, concurrency: usize, ops_per_task: usize) {
    let user_ids: Vec<Uuid> = (0..concurrency).map(|_| Uuid::new_v4()).collect();
    let dids: Vec<Did> = user_ids
        .iter()
        .map(|u| Did::from(format!("did:plc:bench{}", u.as_simple())))
        .collect();

    futures::stream::iter(user_ids.iter().zip(dids.iter()))
        .fold((), |(), (uid, did)| async {
            create_user(pool, *uid, did, &test_cid(1)).await;
        })
        .await;

    let collection = Nsid::from("app.bsky.feed.post".to_string());
    let start = Instant::now();
    let handles: Vec<_> = (0..concurrency)
        .map(|task_id| {
            let pool = Arc::clone(pool);
            let user_id = user_ids[task_id];
            let did = dids[task_id].clone();
            let collection = collection.clone();
            tokio::spawn(async move {
                futures::stream::iter(0..ops_per_task)
                    .fold(Vec::with_capacity(ops_per_task), |mut latencies, i| {
                        let pool = &pool;
                        let did = &did;
                        let collection = &collection;
                        async move {
                            let rev_n = (task_id * ops_per_task + i + 1) as u64;
                            let cid_seed = ((task_id * 31 + i * 7) & 0xFF) as u8;
                            let input =
                                make_commit_input(user_id, did, collection, rev_n, cid_seed);
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
    print_result(total_ops, elapsed, stats.as_ref());
}

async fn bench_get_record_cid(pool: &Arc<HandlerPool>, concurrency: usize, ops_per_task: usize) {
    let user_id = Uuid::new_v4();
    let did = Did::from(format!("did:plc:getrecord{}", user_id.as_simple()));
    let collection = Nsid::from("app.bsky.feed.post".to_string());
    create_user(pool, user_id, &did, &test_cid(1)).await;
    seed_records(pool, user_id, &did, &collection, 1000).await;

    let total_records = 1000usize;
    let start = Instant::now();
    let handles: Vec<_> = (0..concurrency)
        .map(|task_id| {
            let pool = Arc::clone(pool);
            let collection = collection.clone();
            tokio::spawn(async move {
                futures::stream::iter(0..ops_per_task)
                    .fold(Vec::with_capacity(ops_per_task), |mut latencies, i| {
                        let pool = &pool;
                        let collection = &collection;
                        async move {
                            let rec_idx = (task_id * 7 + i * 13) % total_records;
                            let rkey = Rkey::from(format!("rec{rec_idx:08}"));
                            let t = Instant::now();
                            let (tx, rx) = oneshot::channel();
                            pool.send(MetastoreRequest::Record(RecordRequest::GetRecordCid {
                                repo_id: user_id,
                                collection: collection.clone(),
                                rkey,
                                tx,
                            }))
                            .unwrap();
                            let result = rx.await.unwrap().unwrap();
                            assert!(result.is_some());
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
    print_result(total_ops, elapsed, stats.as_ref());
}

async fn bench_list_records(pool: &Arc<HandlerPool>, concurrency: usize, ops_per_task: usize) {
    let user_id = Uuid::new_v4();
    let did = Did::from(format!("did:plc:listrecords{}", user_id.as_simple()));
    let collection = Nsid::from("app.bsky.feed.post".to_string());
    create_user(pool, user_id, &did, &test_cid(1)).await;
    seed_records(pool, user_id, &did, &collection, 1000).await;

    let start = Instant::now();
    let handles: Vec<_> = (0..concurrency)
        .map(|_| {
            let pool = Arc::clone(pool);
            let collection = collection.clone();
            tokio::spawn(async move {
                futures::stream::iter(0..ops_per_task)
                    .fold(Vec::with_capacity(ops_per_task), |mut latencies, _| {
                        let pool = &pool;
                        let collection = &collection;
                        async move {
                            let t = Instant::now();
                            let (tx, rx) = oneshot::channel();
                            pool.send(MetastoreRequest::Record(RecordRequest::ListRecords {
                                repo_id: user_id,
                                collection: collection.clone(),
                                cursor: None,
                                limit: 50,
                                reverse: false,
                                rkey_start: None,
                                rkey_end: None,
                                tx,
                            }))
                            .unwrap();
                            let result = rx.await.unwrap().unwrap();
                            assert!(!result.is_empty());
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
    print_result(total_ops, elapsed, stats.as_ref());
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
}

async fn pg_create_user(pg: &sqlx::PgPool, user_id: Uuid, did: &str) {
    sqlx::query("INSERT INTO users (id, handle, did) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING")
        .bind(user_id)
        .bind(format!("bench.{}.invalid", Uuid::new_v4().as_simple()))
        .bind(did)
        .execute(pg)
        .await
        .unwrap();
}

async fn bench_pg_upsert_records(
    repo: &dyn RepoRepository,
    pg: &sqlx::PgPool,
    concurrency: usize,
    ops_per_task: usize,
) {
    let user_ids: Vec<Uuid> = (0..concurrency).map(|_| Uuid::new_v4()).collect();
    let dids: Vec<String> = user_ids
        .iter()
        .map(|u| format!("did:plc:pgbench{}", u.as_simple()))
        .collect();

    futures::stream::iter(user_ids.iter().zip(dids.iter()))
        .fold((), |(), (uid, did)| async {
            pg_create_user(pg, *uid, did).await;
            let did_typed = Did::from(did.clone());
            let handle = Handle::from(format!("bench.{}.invalid", uid.as_simple()));
            repo.create_repo(*uid, &did_typed, &handle, &test_cid(1), "rev0000000000")
                .await
                .unwrap();
        })
        .await;

    let collection = Nsid::from("app.bsky.feed.post".to_string());
    let start = Instant::now();
    let handles: Vec<_> = (0..concurrency)
        .map(|task_id| {
            let user_id = user_ids[task_id];
            let collection = collection.clone();
            let pg = pg.clone();
            tokio::spawn(async move {
                let repo = tranquil_db::postgres::PostgresRepoRepository::new(pg);
                futures::stream::iter(0..ops_per_task)
                    .fold(Vec::with_capacity(ops_per_task), |mut latencies, i| {
                        let repo = &repo;
                        let collection = &collection;
                        async move {
                            let rev_n = (task_id * ops_per_task + i + 1) as u64;
                            let cid_seed = ((task_id * 31 + i * 7) & 0xFF) as u8;
                            let rkey = Rkey::from(format!("r{rev_n:010}"));
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
    print_result(total_ops, elapsed, stats.as_ref());
}

async fn pg_seed_records(
    repo: &dyn RepoRepository,
    user_id: Uuid,
    collection: &Nsid,
    count: usize,
) {
    let batches: Vec<(usize, usize)> = (0..)
        .map(|i| {
            let start = i * 50;
            let end = (start + 50).min(count);
            (start, end)
        })
        .take_while(|(start, _)| *start < count)
        .collect();

    futures::stream::iter(batches)
        .fold((), |(), (batch_start, batch_end)| {
            let collection = collection.clone();
            async move {
                let collections: Vec<Nsid> = (batch_start..batch_end)
                    .map(|_| collection.clone())
                    .collect();
                let rkeys: Vec<Rkey> = (batch_start..batch_end)
                    .map(|i| Rkey::from(format!("rec{i:08}")))
                    .collect();
                let cids: Vec<CidLink> = (batch_start..batch_end)
                    .map(|i| test_cid(((i * 7 + 3) & 0xFF) as u8))
                    .collect();
                repo.upsert_records(
                    user_id,
                    &collections,
                    &rkeys,
                    &cids,
                    &make_rev(batch_start as u64),
                )
                .await
                .unwrap();
            }
        })
        .await;
}

async fn bench_pg_get_record_cid(pg: &sqlx::PgPool, concurrency: usize, ops_per_task: usize) {
    let user_id = Uuid::new_v4();
    let did = format!("did:plc:pgget{}", user_id.as_simple());
    let collection = Nsid::from("app.bsky.feed.post".to_string());
    pg_create_user(pg, user_id, &did).await;
    let repo = tranquil_db::postgres::PostgresRepoRepository::new(pg.clone());
    let did_typed = Did::from(did.clone());
    let handle = Handle::from(format!("bench.{}.invalid", user_id.as_simple()));
    repo.create_repo(user_id, &did_typed, &handle, &test_cid(1), "rev0000000000")
        .await
        .unwrap();
    pg_seed_records(&repo, user_id, &collection, 1000).await;

    let total_records = 1000usize;
    let start = Instant::now();
    let handles: Vec<_> = (0..concurrency)
        .map(|task_id| {
            let pg = pg.clone();
            let collection = collection.clone();
            tokio::spawn(async move {
                let repo = tranquil_db::postgres::PostgresRepoRepository::new(pg);
                futures::stream::iter(0..ops_per_task)
                    .fold(Vec::with_capacity(ops_per_task), |mut latencies, i| {
                        let repo = &repo;
                        let collection = &collection;
                        async move {
                            let rec_idx = (task_id * 7 + i * 13) % total_records;
                            let rkey = Rkey::from(format!("rec{rec_idx:08}"));
                            let t = Instant::now();
                            let result = repo
                                .get_record_cid(user_id, collection, &rkey)
                                .await
                                .unwrap();
                            assert!(result.is_some());
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
    print_result(total_ops, elapsed, stats.as_ref());
}

async fn bench_pg_list_records(pg: &sqlx::PgPool, concurrency: usize, ops_per_task: usize) {
    let user_id = Uuid::new_v4();
    let did = format!("did:plc:pglist{}", user_id.as_simple());
    let collection = Nsid::from("app.bsky.feed.post".to_string());
    pg_create_user(pg, user_id, &did).await;
    let repo = tranquil_db::postgres::PostgresRepoRepository::new(pg.clone());
    let did_typed = Did::from(did.clone());
    let handle = Handle::from(format!("bench.{}.invalid", user_id.as_simple()));
    repo.create_repo(user_id, &did_typed, &handle, &test_cid(1), "rev0000000000")
        .await
        .unwrap();
    pg_seed_records(&repo, user_id, &collection, 1000).await;

    let start = Instant::now();
    let handles: Vec<_> = (0..concurrency)
        .map(|_| {
            let pg = pg.clone();
            let collection = collection.clone();
            tokio::spawn(async move {
                let repo = tranquil_db::postgres::PostgresRepoRepository::new(pg);
                futures::stream::iter(0..ops_per_task)
                    .fold(Vec::with_capacity(ops_per_task), |mut latencies, _| {
                        let repo = &repo;
                        let collection = &collection;
                        async move {
                            let t = Instant::now();
                            let result = repo
                                .list_records(user_id, collection, None, 50, false, None, None)
                                .await
                                .unwrap();
                            assert!(!result.is_empty());
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
    print_result(total_ops, elapsed, stats.as_ref());
}

#[tokio::main]
async fn main() {
    let handler_threads = std::thread::available_parallelism()
        .map(|n| n.get().max(2) / 2)
        .unwrap_or(2);
    println!("handler threads: {handler_threads}");

    let concurrency_levels = [1, 10, 100, 1000];
    let ops_per_concurrency = |c: usize| match c {
        1 => 5000,
        10 => 1000,
        100 => 200,
        1000 => 50,
        _ => 100,
    };

    futures::stream::iter(concurrency_levels.iter())
        .fold((), |(), &c| async move {
            let ops = ops_per_concurrency(c);

            println!("-- apply_commit: {} ops, {} callers --", ops * c, c);
            let h = setup(handler_threads);
            bench_apply_commit(&h.pool, c, ops).await;

            println!("-- get_record_cid: {} ops, {} callers --", ops * c, c);
            let h = setup(handler_threads);
            bench_get_record_cid(&h.pool, c, ops).await;

            println!("-- list_records: {} ops, {} callers --", ops * c, c);
            let h = setup(handler_threads);
            bench_list_records(&h.pool, c, ops).await;
        })
        .await;

    let pg_url = match std::env::var("DATABASE_URL") {
        Ok(url) => url,
        Err(_) => {
            println!("set DATABASE_URL for postgres comparison");
            return;
        }
    };

    let pg_concurrency_levels: &[usize] = &[1, 10, 50];

    let setup_pg = |max_conns: u32| {
        let url = pg_url.clone();
        async move {
            sqlx::postgres::PgPoolOptions::new()
                .max_connections(max_conns)
                .connect(&url)
                .await
                .unwrap()
        }
    };

    let pg = setup_pg(60).await;
    setup_pg_bench_schema(&pg).await;
    pg.close().await;

    futures::stream::iter(pg_concurrency_levels.iter())
        .fold((), |(), &c| {
            let setup_pg = &setup_pg;
            async move {
                let ops = ops_per_concurrency(c);
                let max_conns = u32::try_from(c).unwrap_or(50) + 10;
                let pg = setup_pg(max_conns).await;
                let repo = tranquil_db::postgres::PostgresRepoRepository::new(pg.clone());

                println!(
                    "-- postgres upsert_records: {} ops, {} callers --",
                    ops * c,
                    c
                );
                bench_pg_upsert_records(&repo, &pg, c, ops).await;

                println!(
                    "-- postgres get_record_cid: {} ops, {} callers --",
                    ops * c,
                    c
                );
                bench_pg_get_record_cid(&pg, c, ops).await;

                println!(
                    "-- postgres list_records: {} ops, {} callers --",
                    ops * c,
                    c
                );
                bench_pg_list_records(&pg, c, ops).await;

                sqlx::query("TRUNCATE records, repos, users CASCADE")
                    .execute(&pg)
                    .await
                    .unwrap();
                pg.close().await;
            }
        })
        .await;

    let pg = setup_pg(5).await;
    sqlx::query("DROP TABLE IF EXISTS records CASCADE")
        .execute(&pg)
        .await
        .unwrap();
    sqlx::query("DROP TABLE IF EXISTS repos CASCADE")
        .execute(&pg)
        .await
        .unwrap();
    sqlx::query("DROP TABLE IF EXISTS users CASCADE")
        .execute(&pg)
        .await
        .unwrap();
    pg.close().await;
}
