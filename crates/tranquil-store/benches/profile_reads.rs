use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::StreamExt;
use tokio::sync::oneshot;
use tranquil_db_traits::{ApplyCommitInput, CommitEventData, RecordUpsert, RepoEventType};
use tranquil_types::{CidLink, Did, Handle, Nsid, Rkey};
use uuid::Uuid;

use tranquil_store::RealIO;
use tranquil_store::eventlog::{EventLog, EventLogConfig};
use tranquil_store::metastore::handler::{
    CommitRequest, HandlerPool, MetastoreRequest, RecordRequest, RepoRequest,
};
use tranquil_store::metastore::{Metastore, MetastoreConfig};

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

struct UserInfo {
    user_id: Uuid,
    did: Did,
}

async fn seed_users(pool: &HandlerPool, count: usize) -> Vec<UserInfo> {
    let users: Vec<UserInfo> = (0..count)
        .map(|i| {
            let user_id = Uuid::new_v4();
            UserInfo {
                did: Did::from(format!("did:plc:prof{i:06x}{}", user_id.as_simple())),
                user_id,
            }
        })
        .collect();

    let batch_size = 500;
    let start = Instant::now();
    let total_batches = count.div_ceil(batch_size);
    futures::stream::iter(users.chunks(batch_size).enumerate())
        .fold((), |(), (batch_idx, batch)| async move {
            futures::stream::iter(batch.iter())
                .fold((), |(), user| async {
                    let (tx, rx) = oneshot::channel();
                    pool.send(MetastoreRequest::Repo(RepoRequest::CreateRepoFull {
                        user_id: user.user_id,
                        did: user.did.clone(),
                        handle: Handle::from(format!("u{}.prof.invalid", user.user_id.as_simple())),
                        repo_root_cid: test_cid(1),
                        repo_rev: "rev0000000000".to_string(),
                        tx,
                    }))
                    .unwrap();
                    rx.await.unwrap().unwrap();
                })
                .await;
            if (batch_idx + 1) % 100 == 0 || batch_idx + 1 == total_batches {
                println!(
                    "seeded {}/{} users, {:.1}s",
                    ((batch_idx + 1) * batch_size).min(count),
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

async fn seed_records(pool: &Arc<HandlerPool>, users: &[UserInfo], records_per_user: usize) {
    let start = Instant::now();
    let total = users.len();
    let batch_size = 500;
    let total_batches = total.div_ceil(batch_size);
    let collection = Nsid::from("app.bsky.feed.post".to_string());

    futures::stream::iter(users.chunks(batch_size).enumerate())
        .fold((), |(), (chunk_idx, chunk)| {
            let pool = Arc::clone(pool);
            let collection = collection.clone();
            async move {
                futures::stream::iter(chunk.iter())
                    .fold((), |(), user| {
                        let pool = &pool;
                        let collection = &collection;
                        async move {
                            let record_upserts: Vec<RecordUpsert> = (0..records_per_user)
                                .map(|i| RecordUpsert {
                                    collection: collection.clone(),
                                    rkey: Rkey::from(format!("rec{i:08}")),
                                    cid: test_cid(((i * 7 + 3) & 0xFF) as u8),
                                })
                                .collect();
                            let new_block_cids: Vec<Vec<u8>> = (0..records_per_user)
                                .map(|i| test_cid_bytes(((i * 11 + 5) & 0xFF) as u8))
                                .collect();
                            let input = ApplyCommitInput {
                                user_id: user.user_id,
                                did: user.did.clone(),
                                expected_root_cid: None,
                                new_root_cid: test_cid(2),
                                new_rev: "rev0000000001".to_string(),
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
                                    blocks: None,
                                    prev_data_cid: None,
                                    rev: Some("rev0000000001".to_string()),
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
                if (chunk_idx + 1) % 100 == 0 || chunk_idx + 1 == total_batches {
                    println!(
                        "seeded records for {}/{} users, {:.1}s",
                        ((chunk_idx + 1) * batch_size).min(total),
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

async fn profile_list_records(
    pool: &Arc<HandlerPool>,
    user_ids: &Arc<Vec<Uuid>>,
    concurrency: usize,
    seconds: u64,
) -> u64 {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let user_count = user_ids.len();

    let handles: Vec<_> = (0..concurrency)
        .map(|task_id| {
            let pool = Arc::clone(pool);
            let user_ids = Arc::clone(user_ids);
            tokio::spawn(async move {
                futures::stream::unfold(0usize, |i| {
                    let cont = Instant::now() < deadline;
                    async move { cont.then_some((i, i + 1)) }
                })
                .fold(0u64, |ops, i| {
                    let pool = &pool;
                    let user_ids = &user_ids;
                    async move {
                        let idx = (task_id * 997 + i * 31) % user_count;
                        let (tx, rx) = oneshot::channel();
                        pool.send(MetastoreRequest::Record(RecordRequest::ListRecords {
                            repo_id: user_ids[idx],
                            collection: Nsid::from("app.bsky.feed.post".to_string()),
                            cursor: None,
                            limit: 50,
                            reverse: false,
                            rkey_start: None,
                            rkey_end: None,
                            tx,
                        }))
                        .unwrap();
                        let _ = rx.await.unwrap().unwrap();
                        ops + 1
                    }
                })
                .await
            })
        })
        .collect();

    futures::stream::iter(handles)
        .fold(0u64, |acc, h| async move { acc + h.await.unwrap() })
        .await
}

async fn profile_get_record_cid(
    pool: &Arc<HandlerPool>,
    user_ids: &Arc<Vec<Uuid>>,
    concurrency: usize,
    seconds: u64,
    records_per_user: usize,
) -> u64 {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let user_count = user_ids.len();

    let handles: Vec<_> = (0..concurrency)
        .map(|task_id| {
            let pool = Arc::clone(pool);
            let user_ids = Arc::clone(user_ids);
            tokio::spawn(async move {
                futures::stream::unfold(0usize, |i| {
                    let cont = Instant::now() < deadline;
                    async move { cont.then_some((i, i + 1)) }
                })
                .fold(0u64, |ops, i| {
                    let pool = &pool;
                    let user_ids = &user_ids;
                    async move {
                        let user_idx = (task_id * 997 + i * 31) % user_count;
                        let rec_idx = (task_id * 13 + i * 7) % records_per_user;
                        let rkey = Rkey::from(format!("rec{rec_idx:08}"));
                        let (tx, rx) = oneshot::channel();
                        pool.send(MetastoreRequest::Record(RecordRequest::GetRecordCid {
                            repo_id: user_ids[user_idx],
                            collection: Nsid::from("app.bsky.feed.post".to_string()),
                            rkey,
                            tx,
                        }))
                        .unwrap();
                        let _ = rx.await.unwrap().unwrap();
                        ops + 1
                    }
                })
                .await
            })
        })
        .collect();

    futures::stream::iter(handles)
        .fold(0u64, |acc, h| async move { acc + h.await.unwrap() })
        .await
}

#[tokio::main]
async fn main() {
    let user_count = std::env::var("PROFILE_USERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300_000usize);
    let records_per_user = 10;
    let profile_seconds = std::env::var("PROFILE_SECONDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30u64);
    let concurrency = 100usize;

    let handler_threads = std::thread::available_parallelism()
        .map(|n| n.get().max(2) / 2)
        .unwrap_or(2);

    println!("-- profile reads --");
    println!("handler threads: {handler_threads}");
    println!("{user_count} users, {records_per_user} records each, {profile_seconds}s per phase");

    let metastore_dir = tempfile::TempDir::new().unwrap();
    let eventlog_dir = tempfile::TempDir::new().unwrap();
    let segments_dir = eventlog_dir.path().join("segments");
    std::fs::create_dir_all(&segments_dir).unwrap();

    let cache_bytes = (user_count as u64 * 10 * 300)
        .saturating_mul(2)
        .clamp(512 * 1024 * 1024, 8 * 1024 * 1024 * 1024);
    println!("cache size: {} MB", cache_bytes / (1024 * 1024));

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
        Some(handler_threads),
    ));

    let users = seed_users(&pool, user_count).await;
    seed_records(&pool, &users, records_per_user).await;

    println!("running major compaction...");
    let t = Instant::now();
    metastore.major_compact().unwrap();
    println!(
        "major compaction complete in {:.1}s",
        t.elapsed().as_secs_f64()
    );

    let user_ids: Arc<Vec<Uuid>> = Arc::new(users.iter().map(|u| u.user_id).collect());

    println!("-- listRecords, {concurrency} readers, {profile_seconds}s --");
    let list_ops = profile_list_records(&pool, &user_ids, concurrency, profile_seconds).await;
    println!(
        "listRecords: {list_ops} ops, {:.0} ops/sec",
        list_ops as f64 / profile_seconds as f64
    );

    println!("-- getRecordCid, {concurrency} readers, {profile_seconds}s --");
    let get_ops = profile_get_record_cid(
        &pool,
        &user_ids,
        concurrency,
        profile_seconds,
        records_per_user,
    )
    .await;
    println!(
        "getRecordCid: {get_ops} ops, {:.0} ops/sec",
        get_ops as f64 / profile_seconds as f64
    );

    println!("-- profile reads complete :D --");
}
