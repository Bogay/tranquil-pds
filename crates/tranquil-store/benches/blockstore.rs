use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use cid::Cid;
use futures::StreamExt;
use jacquard_repo::storage::BlockStore;
use multihash::Multihash;
use sha2::{Digest, Sha256};

use tranquil_store::blockstore::{
    BlockStoreConfig, DEFAULT_MAX_FILE_SIZE, GroupCommitConfig, TranquilBlockStore,
};

const DAG_CBOR_CODEC: u64 = 0x71;
const SHA2_256_CODE: u64 = 0x12;

fn make_block(index: usize) -> Vec<u8> {
    let size = if index.is_multiple_of(5) {
        1024 + (index.wrapping_mul(997)) % (63 * 1024)
    } else {
        64 + (index.wrapping_mul(131)) % 960
    };
    (0..size)
        .map(|i| (index.wrapping_mul(257).wrapping_add(i.wrapping_mul(131)) & 0xFF) as u8)
        .collect()
}

fn make_cid(data: &[u8]) -> Cid {
    let hash = Sha256::digest(data);
    let mh = Multihash::wrap(SHA2_256_CODE, &hash).unwrap();
    Cid::new_v1(DAG_CBOR_CODEC, mh)
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

fn open_store(dir: &Path) -> TranquilBlockStore {
    open_store_sharded(dir, 1)
}

fn open_store_sharded(dir: &Path, shard_count: u8) -> TranquilBlockStore {
    TranquilBlockStore::open(BlockStoreConfig {
        data_dir: dir.join("data"),
        index_dir: dir.join("index"),
        max_file_size: DEFAULT_MAX_FILE_SIZE,
        group_commit: GroupCommitConfig::default(),
        shard_count,
    })
    .unwrap()
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

async fn bench_write_throughput(block_count: usize, concurrency: usize) {
    let dir = bench_temp_dir();
    let store = open_store(dir.path());

    let blocks_per_task = block_count / concurrency;
    let actual_count = blocks_per_task * concurrency;
    let blocks: Vec<Vec<u8>> = (0..actual_count).map(make_block).collect();
    let total_bytes: usize = blocks.iter().map(Vec::len).sum();
    let first_error: Arc<std::sync::Once> = Arc::new(std::sync::Once::new());

    let start = Instant::now();

    let handles: Vec<_> = (0..concurrency)
        .map(|task_id| {
            let store = store.clone();
            let first_error = Arc::clone(&first_error);
            let task_blocks: Vec<Vec<u8>> =
                blocks[task_id * blocks_per_task..(task_id + 1) * blocks_per_task].to_vec();
            tokio::spawn(async move {
                let mut latencies = Vec::with_capacity(task_blocks.len());
                let mut errors = 0u64;
                futures::stream::iter(task_blocks)
                    .then(|block| {
                        let store = store.clone();
                        let first_error = Arc::clone(&first_error);
                        async move {
                            let t = Instant::now();
                            match store.put(&block).await {
                                Ok(_) => Ok(t.elapsed()),
                                Err(e) => {
                                    first_error.call_once(|| {
                                        eprintln!("first put error: {e:?}");
                                    });
                                    Err(())
                                }
                            }
                        }
                    })
                    .for_each(|result| {
                        match result {
                            Ok(d) => latencies.push(d),
                            Err(()) => errors += 1,
                        }
                        async {}
                    })
                    .await;
                (latencies, errors)
            })
        })
        .collect();

    let results: Vec<_> = futures::future::join_all(handles)
        .await
        .into_iter()
        .map(Result::unwrap)
        .collect();
    let elapsed = start.elapsed();

    let total_errors: u64 = results.iter().map(|(_, e)| e).sum();
    let mut all_latencies: Vec<Duration> = results.into_iter().flat_map(|(l, _)| l).collect();
    let successful = all_latencies.len();
    let stats = compute_stats(&mut all_latencies);

    let lat = format_latency(stats.as_ref());
    if total_errors > 0 {
        println!(
            "{successful} ok, {total_errors} errors, {:.0} blocks/sec, {:.1} MB/sec, {:.1}ms{lat}",
            successful as f64 / elapsed.as_secs_f64(),
            total_bytes as f64 / elapsed.as_secs_f64() / (1024.0 * 1024.0),
            elapsed.as_secs_f64() * 1000.0,
        );
    } else {
        println!(
            "{:.0} blocks/sec, {:.1} MB/sec, {:.1}ms{lat}",
            actual_count as f64 / elapsed.as_secs_f64(),
            total_bytes as f64 / elapsed.as_secs_f64() / (1024.0 * 1024.0),
            elapsed.as_secs_f64() * 1000.0,
        );
    }
}

async fn bench_read_throughput(block_count: usize, concurrency: usize) {
    let dir = bench_temp_dir();
    let store = open_store(dir.path());

    let cids_per_task = block_count / concurrency;
    let actual_count = cids_per_task * concurrency;
    let blocks: Vec<Vec<u8>> = (0..actual_count).map(make_block).collect();
    let cids: Vec<Cid> = {
        let pairs: Vec<(Cid, Bytes)> = blocks
            .iter()
            .map(|b| (make_cid(b), Bytes::from(b.clone())))
            .collect();
        let cids: Vec<Cid> = pairs.iter().map(|(c, _)| *c).collect();
        store.put_many(pairs).await.unwrap();
        cids
    };

    let run_reads = |label: &'static str, store: TranquilBlockStore, cids: Vec<Cid>| async move {
        let start = Instant::now();

        let handles: Vec<_> = (0..concurrency)
            .map(|task_id| {
                let store = store.clone();
                let task_cids: Vec<Cid> =
                    cids[task_id * cids_per_task..(task_id + 1) * cids_per_task].to_vec();
                tokio::spawn(async move {
                    futures::stream::iter(task_cids)
                        .then(|cid| {
                            let store = store.clone();
                            async move {
                                let t = Instant::now();
                                let result = store.get(&cid).await.unwrap();
                                assert!(result.is_some());
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
        let stats = compute_stats(&mut all_latencies);

        let lat = format_latency(stats.as_ref());
        println!(
            "{label}: {:.0} blocks/sec, {:.1}ms{lat}",
            actual_count as f64 / elapsed.as_secs_f64(),
            elapsed.as_secs_f64() * 1000.0,
        );
    };

    run_reads("hot", store.clone(), cids.clone()).await;

    #[cfg(target_os = "linux")]
    {
        if std::fs::write("/proc/sys/vm/drop_caches", "3").is_ok() {
            println!("dropped system page caches");
            std::thread::sleep(Duration::from_millis(100));
            run_reads("cold", store.clone(), cids).await;
        } else {
            println!("cold: skipped, no root");
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        println!("cold: skipped, not linux");
    }
}

async fn bench_mixed_workload(block_count: usize, concurrency: usize) {
    let dir = bench_temp_dir();
    let store = open_store(dir.path());

    let ops_per_task = block_count / concurrency;
    let actual_ops = ops_per_task * concurrency;
    let pre_populate = actual_ops / 2;
    let blocks: Vec<Vec<u8>> = (0..pre_populate).map(make_block).collect();
    let cids: Arc<Vec<Cid>> = Arc::new({
        let pairs: Vec<(Cid, Bytes)> = blocks
            .iter()
            .map(|b| (make_cid(b), Bytes::from(b.clone())))
            .collect();
        let cids: Vec<Cid> = pairs.iter().map(|(c, _)| *c).collect();
        store.put_many(pairs).await.unwrap();
        cids
    });

    let read_count = Arc::new(AtomicU64::new(0));
    let write_count = Arc::new(AtomicU64::new(0));

    let timer_jitters: Arc<parking_lot::Mutex<Vec<Duration>>> =
        Arc::new(parking_lot::Mutex::new(Vec::new()));
    let timer_jitters_ref = Arc::clone(&timer_jitters);
    let timer_handle = tokio::spawn(async move {
        let jitters: Vec<Duration> = futures::stream::iter(0..100)
            .then(|_| async {
                let expected = Duration::from_millis(1);
                let t = Instant::now();
                tokio::time::sleep(expected).await;
                t.elapsed().saturating_sub(expected)
            })
            .collect()
            .await;
        *timer_jitters_ref.lock() = jitters;
    });

    let start = Instant::now();

    let handles: Vec<_> = (0..concurrency)
        .map(|task_id| {
            let store = store.clone();
            let cids = Arc::clone(&cids);
            let read_count = Arc::clone(&read_count);
            let write_count = Arc::clone(&write_count);
            tokio::spawn(async move {
                futures::stream::iter(0..ops_per_task)
                    .then(|op_idx| {
                        let store = store.clone();
                        let cids = Arc::clone(&cids);
                        let read_count = Arc::clone(&read_count);
                        let write_count = Arc::clone(&write_count);
                        async move {
                            let is_read = op_idx % 5 != 0;
                            if is_read && !cids.is_empty() {
                                let global_idx = task_id * ops_per_task + op_idx;
                                let cid_idx = global_idx % cids.len();
                                if store.get(&cids[cid_idx]).await.is_ok() {
                                    read_count.fetch_add(1, Ordering::Relaxed);
                                }
                            } else {
                                let global_idx = task_id * ops_per_task + op_idx;
                                let block = make_block(pre_populate + global_idx);
                                if store.put(&block).await.is_ok() {
                                    write_count.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                    })
                    .collect::<Vec<()>>()
                    .await;
            })
        })
        .collect();

    futures::future::join_all(handles).await;
    timer_handle.await.unwrap();

    let elapsed = start.elapsed();
    let reads = read_count.load(Ordering::Relaxed);
    let writes = write_count.load(Ordering::Relaxed);
    let total = reads + writes;

    let jitters = timer_jitters.lock();
    let max_jitter = jitters.iter().max().copied().unwrap_or_default();
    let mean_jitter: Duration = if jitters.is_empty() {
        Duration::ZERO
    } else {
        let jitter_divisor = u32::try_from(jitters.len()).unwrap_or(u32::MAX);
        jitters.iter().sum::<Duration>() / jitter_divisor
    };

    println!(
        "{:.0} ops/sec, {} reads + {} writes, {:.1}ms total",
        total as f64 / elapsed.as_secs_f64(),
        reads,
        writes,
        elapsed.as_secs_f64() * 1000.0,
    );
    let starvation_warning = if max_jitter > Duration::from_millis(5) {
        " worker starvation detected"
    } else {
        ""
    };
    println!(
        "timer jitter: mean={:?} max={:?}{starvation_warning}",
        mean_jitter, max_jitter
    );
}

async fn bench_group_commit_effectiveness(block_count: usize) {
    println!("-- group commit effectiveness at {block_count} blocks --");

    let baseline_cycle_time = {
        let dir = bench_temp_dir();
        let store = open_store(dir.path());

        let start = Instant::now();
        futures::stream::iter(0..20)
            .then(|i| {
                let store = store.clone();
                async move {
                    let block = make_block(i);
                    store.put(&block).await.unwrap();
                }
            })
            .collect::<Vec<()>>()
            .await;
        let elapsed = start.elapsed();
        drop(store);
        elapsed.checked_div(20).unwrap_or(Duration::from_micros(1))
    };

    futures::stream::iter([1usize, 10, 50, 100])
        .then(|concurrency| {
            let baseline = baseline_cycle_time;
            async move {
                if block_count < concurrency {
                    return;
                }
                let dir = bench_temp_dir();
                let store = open_store(dir.path());
                let blocks_per_task = block_count / concurrency;
                let actual_count = blocks_per_task * concurrency;

                let start = Instant::now();

                let handles: Vec<_> = (0..concurrency)
                    .map(|task_id| {
                        let store = store.clone();
                        tokio::spawn(async move {
                            futures::stream::iter(0..blocks_per_task)
                                .then(|i| {
                                    let store = store.clone();
                                    async move {
                                        let block = make_block(task_id * blocks_per_task + i);
                                        store.put(&block).await.unwrap();
                                    }
                                })
                                .collect::<Vec<()>>()
                                .await;
                        })
                    })
                    .collect();

                futures::future::join_all(handles).await;
                let elapsed = start.elapsed();

                let blocks_per_sec = actual_count as f64 / elapsed.as_secs_f64();
                let est_fsyncs = elapsed.as_secs_f64() / baseline.as_secs_f64();
                let blocks_per_cycle = actual_count as f64 / est_fsyncs;

                println!(
                    "concurrency={concurrency}: {blocks_per_sec:.0} blocks/sec, {:.1}ms, ~{est_fsyncs:.0} commit cycles, {blocks_per_cycle:.1} blocks/cycle",
                    elapsed.as_secs_f64() * 1000.0,
                );

                drop(store);
                drop(dir);
            }
        })
        .collect::<Vec<()>>()
        .await;
}

async fn bench_sharded_write_throughput(block_count: usize, concurrency: usize, shard_count: u8) {
    let dir = bench_temp_dir();
    let store = open_store_sharded(dir.path(), shard_count);

    let blocks_per_task = block_count / concurrency;
    let actual_count = blocks_per_task * concurrency;
    let blocks: Vec<Vec<u8>> = (0..actual_count).map(make_block).collect();
    let total_bytes: usize = blocks.iter().map(Vec::len).sum();

    let start = Instant::now();

    let handles: Vec<_> = (0..concurrency)
        .map(|task_id| {
            let store = store.clone();
            let task_blocks: Vec<Vec<u8>> =
                blocks[task_id * blocks_per_task..(task_id + 1) * blocks_per_task].to_vec();
            tokio::spawn(async move {
                futures::stream::iter(task_blocks)
                    .then(|block| {
                        let store = store.clone();
                        async move {
                            store.put(&block).await.unwrap();
                        }
                    })
                    .collect::<Vec<()>>()
                    .await;
            })
        })
        .collect();

    futures::future::join_all(handles).await;
    let elapsed = start.elapsed();

    println!(
        "{:.0} blocks/sec, {:.1} MB/sec, {:.1}ms",
        actual_count as f64 / elapsed.as_secs_f64(),
        total_bytes as f64 / elapsed.as_secs_f64() / (1024.0 * 1024.0),
        elapsed.as_secs_f64() * 1000.0,
    );
}

fn bench_temp_dir() -> tempfile::TempDir {
    match std::env::var("BENCH_DIR") {
        Ok(dir) => tempfile::TempDir::new_in(dir).unwrap(),
        Err(_) => tempfile::TempDir::new().unwrap(),
    }
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let worker_threads = std::env::var("BENCH_WORKER_THREADS")
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(8)
        });
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .build()
        .unwrap();
    println!("tokio worker threads: {worker_threads}");

    let parse_env_list = |var: &str, defaults: Vec<usize>| -> Vec<usize> {
        std::env::var(var).map_or(defaults, |s| {
            s.split(',')
                .map(|n| {
                    let trimmed = n.trim();
                    trimmed
                        .replace('_', "")
                        .parse::<usize>()
                        .unwrap_or_else(|_| panic!("{var}: failed to parse {trimmed:?} as integer"))
                })
                .collect()
        })
    };
    let block_counts = parse_env_list("BENCH_BLOCK_COUNTS", vec![1_000, 10_000]);
    let concurrency_levels = parse_env_list("BENCH_CONCURRENCY", vec![1, 10, 50]);

    println!(
        "block counts: {:?}, concurrency: {:?}",
        block_counts, concurrency_levels
    );

    block_counts.iter().for_each(|&block_count| {
        concurrency_levels.iter().for_each(|&concurrency| {
            if block_count < concurrency {
                return;
            }

            println!(
                "-- write throughput: {} blocks, {} writers --",
                block_count, concurrency
            );
            rt.block_on(bench_write_throughput(block_count, concurrency));

            println!(
                "-- read throughput: {} blocks, {} readers --",
                block_count, concurrency
            );
            rt.block_on(bench_read_throughput(block_count, concurrency));

            println!(
                "-- mixed workload 80/20 r/w: {} ops, {} workers --",
                block_count, concurrency
            );
            rt.block_on(bench_mixed_workload(block_count, concurrency));
        });
    });

    rt.block_on(bench_group_commit_effectiveness(1000));

    let shard_counts = parse_env_list("BENCH_SHARDS", vec![1, 2, 4]);
    if shard_counts.iter().any(|&s| s > 1) {
        println!("\n-- sharded write throughput :p --");
        shard_counts.iter().for_each(|&shards| {
            block_counts.iter().for_each(|&block_count| {
                concurrency_levels.iter().for_each(|&concurrency| {
                    if block_count < concurrency {
                        return;
                    }
                    let sc = u8::try_from(shards).unwrap_or(4);
                    println!(
                        "-- sharded write: {} shards, {} blocks, {} writers --",
                        sc, block_count, concurrency
                    );
                    rt.block_on(bench_sharded_write_throughput(block_count, concurrency, sc));
                });
            });
        });
    }
}
