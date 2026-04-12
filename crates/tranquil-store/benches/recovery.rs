use std::path::Path;
use std::time::Instant;

use tranquil_store::blockstore::hash_index::BlockIndex;
use tranquil_store::blockstore::{
    CidBytes, DEFAULT_MAX_FILE_SIZE, DataFileId, DataFileWriter, HintFileWriter, hint_file_path,
    scan_hints_to_memory,
};
use tranquil_store::{OpenOptions, RealIO, StorageIO};

#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn test_cid(seed: u32) -> CidBytes {
    let le = seed.to_le_bytes();
    std::array::from_fn(|i| match i {
        0 => 0x01,
        1 => 0x71,
        2 => 0x12,
        3 => 0x20,
        4..8 => le[i - 4],
        _ => (seed as u8).wrapping_add(i as u8),
    })
}

fn block_data(seed: u32) -> Vec<u8> {
    let tag = seed.to_le_bytes();
    std::iter::repeat(tag).flatten().take(256).collect()
}

struct DirectSeeder<'a> {
    io: &'a RealIO,
    data_dir: &'a Path,
    file_id: DataFileId,
    data_writer: DataFileWriter<'a, RealIO>,
    hint_writer: HintFileWriter<'a, RealIO>,
    blocks_in_file: u64,
}

impl<'a> DirectSeeder<'a> {
    fn new(io: &'a RealIO, data_dir: &'a Path) -> Self {
        std::fs::create_dir_all(data_dir).unwrap();
        let file_id = DataFileId::new(0);

        let data_fd = io
            .open(
                &data_dir.join(format!("{file_id}.tqb")),
                OpenOptions::read_write(),
            )
            .unwrap();
        let data_writer = DataFileWriter::new(io, data_fd, file_id).unwrap();

        let hint_fd = io
            .open(
                &hint_file_path(data_dir, file_id),
                OpenOptions::read_write(),
            )
            .unwrap();
        let hint_writer = HintFileWriter::new(io, hint_fd);

        Self {
            io,
            data_dir,
            file_id,
            data_writer,
            hint_writer,
            blocks_in_file: 0,
        }
    }

    fn rotate(&mut self) {
        self.data_writer.sync().unwrap();
        self.hint_writer.sync().unwrap();

        self.file_id = self.file_id.next();

        let data_fd = self
            .io
            .open(
                &self.data_dir.join(format!("{}.tqb", self.file_id)),
                OpenOptions::read_write(),
            )
            .unwrap();
        self.data_writer = DataFileWriter::new(self.io, data_fd, self.file_id).unwrap();

        let hint_fd = self
            .io
            .open(
                &hint_file_path(self.data_dir, self.file_id),
                OpenOptions::read_write(),
            )
            .unwrap();
        self.hint_writer = HintFileWriter::new(self.io, hint_fd);
        self.blocks_in_file = 0;
    }

    fn append(&mut self, cid: &CidBytes, data: &[u8]) {
        if self.data_writer.position().raw() > DEFAULT_MAX_FILE_SIZE {
            self.rotate();
        }

        let loc = self.data_writer.append_block(cid, data).unwrap();
        self.hint_writer.append_hint(cid, &loc).unwrap();
        self.blocks_in_file += 1;

        if self.blocks_in_file.is_multiple_of(10_000) {
            self.data_writer.sync().unwrap();
            self.hint_writer.sync().unwrap();
        }
    }

    fn finish(&mut self) {
        self.data_writer.sync().unwrap();
        self.hint_writer.sync().unwrap();
        self.io.sync_dir(self.data_dir).unwrap();
    }
}

fn seed_blocks_direct(data_dir: &Path, count: u32) {
    let io = RealIO::new();
    let mut seeder = DirectSeeder::new(&io, data_dir);
    (0..count).for_each(|i| {
        let cid = test_cid(i);
        let data = block_data(i);
        seeder.append(&cid, &data);
    });
    seeder.finish();
}

fn read_rss_mb() -> f64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines().find(|l| l.starts_with("VmRSS:")).and_then(|l| {
                l.split_whitespace()
                    .nth(1)
                    .and_then(|v| v.parse::<f64>().ok())
            })
        })
        .map(|kb| kb / 1024.0)
        .unwrap_or(0.0)
}

fn bench_hint_scan_only(data_dir: &Path, block_count: u32) {
    let io = RealIO::new();

    let rss_before = read_rss_mb();
    let start = Instant::now();
    let (hint_index, _cursor) = scan_hints_to_memory(&io, data_dir).unwrap();
    let elapsed = start.elapsed();
    let rss_after = read_rss_mb();

    let entry_count = hint_index.len();
    let rss_delta = rss_after - rss_before;
    let bytes_per_entry = match entry_count {
        0 => 0.0,
        n => (rss_delta * 1024.0 * 1024.0) / n as f64,
    };

    println!(
        "hint scan to memory ({block_count} blocks): {:.3}s ({:.0} blocks/sec)",
        elapsed.as_secs_f64(),
        block_count as f64 / elapsed.as_secs_f64(),
    );
    println!(
        "  entries: {entry_count}, RSS: {rss_before:.1}MB -> {rss_after:.1}MB (delta: {rss_delta:.1}MB, {bytes_per_entry:.0} bytes/entry)"
    );

    drop(hint_index);
    let rss_after_drop = read_rss_mb();
    println!("  RSS after drop: {rss_after_drop:.1}MB");
}

fn bench_hash_table_rebuild_from_hints(data_dir: &Path, index_dir: &Path, block_count: u32) {
    let io = RealIO::new();
    let index = BlockIndex::open(index_dir).unwrap();

    let rss_before = read_rss_mb();
    let start = Instant::now();
    index.rebuild_from_hints(&io, data_dir).unwrap();
    let elapsed = start.elapsed();
    let rss_after = read_rss_mb();

    println!(
        "hash table rebuild from hints ({block_count} blocks): {:.3}s ({:.0} blocks/sec)",
        elapsed.as_secs_f64(),
        block_count as f64 / elapsed.as_secs_f64(),
    );
    println!(
        "  RSS: {rss_before:.1}MB -> {rss_after:.1}MB (delta: {:.1}MB)",
        rss_after - rss_before,
    );
}

fn bench_hash_table_rebuild_from_data_files(data_dir: &Path, index_dir: &Path, block_count: u32) {
    let io = RealIO::new();
    let index = BlockIndex::open(index_dir).unwrap();

    let start = Instant::now();
    index.rebuild_from_data_files(&io, data_dir).unwrap();
    let elapsed = start.elapsed();

    println!(
        "hash table rebuild from data files ({block_count} blocks): {:.3}s ({:.0} blocks/sec)",
        elapsed.as_secs_f64(),
        block_count as f64 / elapsed.as_secs_f64(),
    );
}

fn nuke_index(index_dir: &Path) {
    if index_dir.exists() {
        std::fs::remove_dir_all(index_dir).unwrap();
    }
    std::fs::create_dir_all(index_dir).unwrap();
}

fn run_scale(block_count: u32) {
    let label = match block_count {
        n if n >= 10_000_000 => format!("{}M blocks", n / 1_000_000),
        n if n >= 1_000_000 => format!("{}M blocks", n / 1_000_000),
        n => format!("{}K blocks", n / 1_000),
    };
    println!("\n-- {label} --");

    let dir = tempfile::TempDir::new().unwrap();
    let data_dir = dir.path().join("data");
    let index_dir = dir.path().join("index");

    println!("seeding {block_count} blocks, direct without index...");
    let seed_start = Instant::now();
    seed_blocks_direct(&data_dir, block_count);
    println!(
        "  blocks seeded in {:.1}s",
        seed_start.elapsed().as_secs_f64()
    );

    println!("\n-- hint scan to memory --");
    bench_hint_scan_only(&data_dir, block_count);

    println!("\n-- hash table rebuild from hints --");
    nuke_index(&index_dir);
    bench_hash_table_rebuild_from_hints(&data_dir, &index_dir, block_count);

    println!("\n-- hash table rebuild from data files --");
    nuke_index(&index_dir);
    bench_hash_table_rebuild_from_data_files(&data_dir, &index_dir, block_count);
}

fn parse_scales(input: &str) -> Vec<u32> {
    input
        .split(';')
        .map(|s| s.trim().replace('_', "").parse::<u32>().unwrap())
        .collect()
}

fn main() {
    let scales = parse_scales(
        &std::env::var("BENCH_RECOVERY_SCALES")
            .unwrap_or_else(|_| "100_000; 1_000_000; 10_000_000".into()),
    );

    println!("recovery performance benchmark, hash table index :3");
    println!("scales: {scales:?}");

    scales.iter().for_each(|&blocks| {
        run_scale(blocks);
    });
}
