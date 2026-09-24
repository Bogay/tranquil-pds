use std::sync::Arc;

use cid::Cid;
use jacquard_repo::mst::Mst;
use jacquard_repo::storage::BlockStore;
use tranquil_pds::repo::AnyBlockStore;
use tranquil_store::blockstore::{BlockStoreConfig, GroupCommitConfig, TranquilBlockStore};

const RECORD_COUNT: usize = 300;

fn open_store(dir: &std::path::Path) -> AnyBlockStore {
    let cfg = BlockStoreConfig {
        data_dir: dir.join("data"),
        index_dir: dir.join("index"),
        max_file_size: 64 * 1024,
        group_commit: GroupCommitConfig::default(),
        shard_count: 1,
    };
    AnyBlockStore::TranquilStore(TranquilBlockStore::open(cfg).expect("open block store"))
}

async fn build_repo(any: &AnyBlockStore) -> (Cid, Vec<(String, Cid)>) {
    let mut mst = Mst::new(Arc::new(any.clone()));
    let mut entries: Vec<(String, Cid)> = Vec::with_capacity(RECORD_COUNT);
    for i in 0..RECORD_COUNT {
        let key = format!("app.bsky.feed.post/{i:0>6}");
        let body = format!("record body number {i}").into_bytes();
        let cid = any.put(&body).await.expect("put record");
        mst.add_mut(&key, cid).await.expect("mst add");
        entries.push((key, cid));
    }
    let data_root = mst.persist().await.expect("persist mst");
    (data_root, entries)
}

fn shred_data_files(data_dir: &std::path::Path) {
    let mut shredded = false;
    for entry in std::fs::read_dir(data_dir).expect("read data dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("tqb") {
            continue;
        }
        let mut bytes = std::fs::read(&path).expect("read data file");
        let mut off = 5usize;
        while off + 48 < bytes.len() {
            bytes[off..off + 48].iter_mut().for_each(|b| *b = 0xFF);
            off += 192;
            shredded = true;
        }
        std::fs::write(&path, &bytes).expect("write corrupted data file");
    }
    assert!(shredded, "no .tqb data file was corrupted");
}

async fn walk_all(
    any: &AnyBlockStore,
    root: Cid,
    entries: &[(String, Cid)],
) -> Result<usize, String> {
    let mst = Mst::load(Arc::new(any.clone()), root, None);
    let mut resolved = 0usize;
    for (key, expected) in entries {
        match mst.get(key).await {
            Ok(Some(cid)) if cid == *expected => resolved += 1,
            Ok(Some(cid)) => {
                return Err(format!("{key}: resolved to {cid} != expected {expected}"));
            }
            Ok(None) => return Err(format!("{key}: missing")),
            Err(e) => return Err(format!("{key}: read error {e}")),
        }
    }
    Ok(resolved)
}

fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) {
    std::fs::create_dir_all(dst).expect("create dst dir");
    for entry in std::fs::read_dir(src).expect("read src dir") {
        let entry = entry.expect("dir entry");
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if from.is_dir() {
            copy_dir_recursive(&from, &to);
        } else {
            std::fs::copy(&from, &to).expect("copy file");
        }
    }
}

#[tokio::test]
async fn pristine_repo_survives_copy_and_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let any = open_store(dir.path());
    let (data_root, entries) = build_repo(&any).await;
    assert_eq!(
        walk_all(&any, data_root, &entries).await.expect("pristine"),
        RECORD_COUNT
    );

    let snap = tempfile::tempdir().expect("snap tempdir");
    copy_dir_recursive(dir.path(), snap.path());

    let reopened = open_store(snap.path());
    assert_eq!(
        walk_all(&reopened, data_root, &entries)
            .await
            .expect("pristine repo must survive copy+reopen"),
        RECORD_COUNT
    );
}

#[tokio::test]
async fn repair_survives_crash_and_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let any = open_store(dir.path());

    let (data_root, entries) = build_repo(&any).await;
    assert_eq!(
        walk_all(&any, data_root, &entries).await.expect("pristine"),
        RECORD_COUNT
    );

    shred_data_files(&dir.path().join("data"));
    assert!(
        walk_all(&any, data_root, &entries).await.is_err(),
        "corruption must break the walk"
    );

    let outcome = any
        .repair_structure(&entries, data_root)
        .await
        .expect("repair_structure");
    assert!(outcome.nodes_repaired > 0, "repair must rewrite a node");

    assert_eq!(
        walk_all(&any, data_root, &entries)
            .await
            .expect("in-process walk after repair"),
        RECORD_COUNT
    );

    let snap = tempfile::tempdir().expect("snap tempdir");
    copy_dir_recursive(dir.path(), snap.path());

    let reopened = open_store(snap.path());
    assert_eq!(
        walk_all(&reopened, data_root, &entries)
            .await
            .expect("every key must resolve after crash-recovery of a repair"),
        RECORD_COUNT,
        "repair did not survive reopen"
    );
}
