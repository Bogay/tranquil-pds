use std::path::Path;
use std::sync::Arc;

use cid::Cid;
use jacquard_repo::mst::Mst;
use jacquard_repo::storage::BlockStore;
use tranquil_pds::api::error::ApiError;
use tranquil_pds::repo::AnyBlockStore;
use tranquil_store::blockstore::{
    BLOCK_HEADER_SIZE, BlockStoreConfig, CID_SIZE, GroupCommitConfig, TranquilBlockStore,
};

const RECORD_COUNT: usize = 300;

fn open_store(dir: &Path) -> AnyBlockStore {
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

fn shred_data_files(data_dir: &Path) {
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

fn corrupt_block_with_cid(data_dir: &Path, target: &[u8]) -> bool {
    for entry in std::fs::read_dir(data_dir).expect("read data dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("tqb") {
            continue;
        }
        let mut bytes = std::fs::read(&path).expect("read data file");
        let mut pos = BLOCK_HEADER_SIZE;
        while pos + CID_SIZE + 4 <= bytes.len() {
            let cid = bytes[pos..pos + CID_SIZE].to_vec();
            let len = u32::from_le_bytes(
                bytes[pos + CID_SIZE..pos + CID_SIZE + 4]
                    .try_into()
                    .unwrap(),
            ) as usize;
            let data_start = pos + CID_SIZE + 4;
            let rec_end = data_start + len + 4;
            if rec_end > bytes.len() {
                break;
            }
            if cid.as_slice() == target && len > 0 {
                bytes[data_start] ^= 0xFF;
                std::fs::write(&path, &bytes).expect("write corrupted data file");
                return true;
            }
            pos = rec_end;
        }
    }
    false
}

#[tokio::test]
async fn corrupt_mst_node_classifies_as_repo_corruption() {
    let dir = tempfile::tempdir().expect("tempdir");
    let any = open_store(dir.path());
    let (root, entries) = build_repo(&any).await;

    shred_data_files(&dir.path().join("data"));

    let mst = Mst::load(Arc::new(any.clone()), root, None);
    let mut classified_corruption = false;
    for (key, _) in &entries {
        if let Err(e) = mst.get(key).await {
            assert!(
                ApiError::from_mst_error("audit", &e).is_repo_corruption(),
                "corrupt MST node must classify as RepoCorruption via from_mst_error; raw error: {e}"
            );
            assert!(
                ApiError::detail_is_repo_corruption(&e.to_string()),
                "to_string of corrupt-node error must carry the marker; raw error: {e}"
            );
            classified_corruption = true;
            break;
        }
    }
    assert!(
        classified_corruption,
        "shredded tree must produce at least one corrupt-node read error"
    );
}

#[tokio::test]
async fn missing_mst_node_classifies_as_repo_corruption() {
    let dir = tempfile::tempdir().expect("tempdir");
    let any = open_store(dir.path());
    let (root, entries) = build_repo(&any).await;

    let empty_dir = tempfile::tempdir().expect("empty tempdir");
    let empty = open_store(empty_dir.path());
    let mst = Mst::load(Arc::new(empty.clone()), root, None);

    let err = mst
        .get(&entries[0].0)
        .await
        .expect_err("loading a root absent from the store must error");

    assert!(
        ApiError::from_mst_error("audit", &err).is_repo_corruption(),
        "a missing MST node must classify as repairable so self-heal triggers; raw error: {err}"
    );
    assert!(
        ApiError::detail_is_repo_corruption(&format!("{err:#}")),
        "missing-node error must carry a repairable marker; raw error: {err}"
    );
}

#[tokio::test]
async fn leaf_block_corruption_is_not_repaired_by_structural_repair() {
    let dir = tempfile::tempdir().expect("tempdir");
    let any = open_store(dir.path());
    let (root, entries) = build_repo(&any).await;

    let (_, rec_cid) = &entries[0];
    assert!(
        any.get(rec_cid).await.expect("read leaf").is_some(),
        "leaf must be readable before corruption"
    );

    let target = rec_cid.to_bytes();
    assert!(
        corrupt_block_with_cid(&dir.path().join("data"), &target),
        "must locate the record leaf block to corrupt"
    );

    let read_err = any
        .get(rec_cid)
        .await
        .expect_err("corrupt leaf must fail to read");
    assert!(
        ApiError::detail_is_repo_corruption(&read_err.to_string()),
        "corrupt leaf read error must carry the marker; raw error: {read_err}"
    );

    let outcome = any
        .repair_structure(&entries, root)
        .await
        .expect("structural repair must succeed");
    assert_eq!(
        outcome.nodes_repaired, 0,
        "structural repair only touches MST nodes, so a leaf-only corruption yields zero repairs"
    );

    assert!(
        any.get(rec_cid).await.is_err(),
        "leaf corruption is NOT healed by structural repair"
    );
}
