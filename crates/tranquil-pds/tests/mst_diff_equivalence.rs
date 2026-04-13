use std::collections::BTreeSet;
use std::sync::Arc;

use cid::Cid;
use jacquard_repo::mst::Mst;
use jacquard_repo::storage::MemoryBlockStore;

fn test_cid(n: u32) -> Cid {
    let data = n.to_be_bytes();
    let mut buf = [0u8; 32];
    buf[..4].copy_from_slice(&data);
    buf[4] = (n >> 8) as u8 ^ 0xAB;
    buf[5] = (n & 0xFF) as u8 ^ 0xCD;
    let mh = multihash::Multihash::wrap(0x12, &buf).unwrap();
    Cid::new_v1(0x71, mh)
}

async fn compute_obsolete_full_walk<S: jacquard_repo::storage::BlockStore + Sync + Send + 'static>(
    old: &Mst<S>,
    new: &Mst<S>,
) -> BTreeSet<Cid> {
    let old_nodes = old.collect_node_cids().await.unwrap();
    let new_nodes = new.collect_node_cids().await.unwrap();
    let old_leaves = old.leaves().await.unwrap();
    let new_leaves = new.leaves().await.unwrap();
    let old_nodes_set: BTreeSet<Cid> = old_nodes.into_iter().collect();
    let new_nodes_set: BTreeSet<Cid> = new_nodes.into_iter().collect();
    let old_leaf_set: BTreeSet<Cid> = old_leaves.iter().map(|(_, cid)| *cid).collect();
    let new_leaf_set: BTreeSet<Cid> = new_leaves.iter().map(|(_, cid)| *cid).collect();
    old_nodes_set
        .difference(&new_nodes_set)
        .copied()
        .chain(old_leaf_set.difference(&new_leaf_set).copied())
        .collect()
}

fn compute_obsolete_from_diff(
    diff: &jacquard_repo::mst::diff::MstDiff,
) -> BTreeSet<Cid> {
    diff.removed_mst_blocks
        .iter()
        .copied()
        .chain(diff.removed_cids.iter().copied())
        .collect()
}

async fn assert_equivalence(
    old_records: &[(String, u32)],
    new_records: &[(String, u32)],
    scenario: &str,
) {
    let storage = Arc::new(MemoryBlockStore::new());

    let mut old_tree = Mst::new(storage.clone());
    for (key, val) in old_records {
        old_tree = old_tree.add(key, test_cid(*val)).await.unwrap();
    }
    let old_root = old_tree.persist().await.unwrap();

    let mut new_tree = Mst::new(storage.clone());
    for (key, val) in new_records {
        new_tree = new_tree.add(key, test_cid(*val)).await.unwrap();
    }
    let new_root = new_tree.persist().await.unwrap();

    let old_settled = Mst::load(storage.clone(), old_root, None);
    let new_settled = Mst::load(storage.clone(), new_root, None);

    let full_walk_obsolete = compute_obsolete_full_walk(&old_settled, &new_settled).await;

    let old_for_diff = Mst::load(storage.clone(), old_root, None);
    let new_for_diff = Mst::load(storage, new_root, None);
    let diff = old_for_diff.diff(&new_for_diff).await.unwrap();
    let diff_obsolete = compute_obsolete_from_diff(&diff);

    assert_eq!(
        full_walk_obsolete, diff_obsolete,
        "MISMATCH in scenario: {scenario}\n  full_walk count: {}\n  diff count: {}\n  in full_walk but not diff: {:?}\n  in diff but not full_walk: {:?}",
        full_walk_obsolete.len(),
        diff_obsolete.len(),
        full_walk_obsolete.difference(&diff_obsolete).collect::<Vec<_>>(),
        diff_obsolete.difference(&full_walk_obsolete).collect::<Vec<_>>(),
    );
}

fn make_key(collection: &str, i: u32) -> String {
    format!("{collection}/{i:06}")
}

fn generate_records(collection: &str, range: std::ops::Range<u32>) -> Vec<(String, u32)> {
    range.map(|i| (make_key(collection, i), i)).collect()
}

fn generate_multi_collection_records(
    collections: &[&str],
    per_collection: u32,
) -> Vec<(String, u32)> {
    collections
        .iter()
        .enumerate()
        .flat_map(|(ci, coll)| {
            let base = ci as u32 * per_collection;
            (0..per_collection).map(move |i| (make_key(coll, i), base + i))
        })
        .collect()
}

fn apply_scattered_updates(
    records: &[(String, u32)],
    stride: usize,
    cid_offset: u32,
) -> Vec<(String, u32)> {
    records
        .iter()
        .enumerate()
        .map(|(idx, (key, val))| {
            if idx % stride == 0 {
                (key.clone(), val + cid_offset)
            } else {
                (key.clone(), *val)
            }
        })
        .collect()
}

fn remove_every_nth(records: &[(String, u32)], n: usize) -> Vec<(String, u32)> {
    records
        .iter()
        .enumerate()
        .filter(|(idx, _)| idx % n != 0)
        .map(|(_, r)| r.clone())
        .collect()
}

fn remove_range(records: &[(String, u32)], start: usize, count: usize) -> Vec<(String, u32)> {
    records
        .iter()
        .enumerate()
        .filter(|(idx, _)| *idx < start || *idx >= start + count)
        .map(|(_, r)| r.clone())
        .collect()
}

fn keep_only_collection(records: &[(String, u32)], collection: &str) -> Vec<(String, u32)> {
    records
        .iter()
        .filter(|(key, _)| key.starts_with(collection))
        .cloned()
        .collect()
}

fn append_records(
    base: &[(String, u32)],
    collection: &str,
    range: std::ops::Range<u32>,
    cid_base: u32,
) -> Vec<(String, u32)> {
    let mut result = base.to_vec();
    result.extend(range.map(|i| (make_key(collection, i), cid_base + i)));
    result.sort_by(|(a, _), (b, _)| a.cmp(b));
    result
}

#[tokio::test]
async fn massive_tree_single_create() {
    let old = generate_records("app.bsky.feed.post", 0..2000);
    let new_rec = append_records(&old, "app.bsky.feed.post", 2000..2001, 2000);
    assert_equivalence(&old, &new_rec, "2000 records + 1 create").await;
}

#[tokio::test]
async fn massive_tree_single_delete() {
    let old = generate_records("app.bsky.feed.post", 0..2000);
    let new_rec = remove_range(&old, 1000, 1);
    assert_equivalence(&old, &new_rec, "2000 records - 1 delete from middle").await;
}

#[tokio::test]
async fn massive_tree_single_update() {
    let old = generate_records("app.bsky.feed.post", 0..2000);
    let new_rec: Vec<_> = old
        .iter()
        .map(|(k, v)| {
            if k == "app.bsky.feed.post/001000" {
                (k.clone(), v + 50000)
            } else {
                (k.clone(), *v)
            }
        })
        .collect();
    assert_equivalence(&old, &new_rec, "2000 records - 1 update in middle").await;
}

#[tokio::test]
async fn massive_tree_scattered_updates_every_3rd() {
    let old = generate_records("app.bsky.feed.post", 0..1500);
    let new_rec = apply_scattered_updates(&old, 3, 10000);
    assert_equivalence(&old, &new_rec, "1500 records - update every 3rd").await;
}

#[tokio::test]
async fn massive_tree_scattered_updates_every_7th() {
    let old = generate_records("app.bsky.feed.post", 0..2000);
    let new_rec = apply_scattered_updates(&old, 7, 20000);
    assert_equivalence(&old, &new_rec, "2000 records - update every 7th").await;
}

#[tokio::test]
async fn massive_tree_delete_every_2nd() {
    let old = generate_records("app.bsky.feed.post", 0..1000);
    let new_rec = remove_every_nth(&old, 2);
    assert_equivalence(&old, &new_rec, "1000 records - delete every 2nd").await;
}

#[tokio::test]
async fn massive_tree_delete_every_5th() {
    let old = generate_records("app.bsky.feed.post", 0..2000);
    let new_rec = remove_every_nth(&old, 5);
    assert_equivalence(&old, &new_rec, "2000 records - delete every 5th").await;
}

#[tokio::test]
async fn massive_tree_delete_first_half() {
    let old = generate_records("app.bsky.feed.post", 0..1500);
    let new_rec = remove_range(&old, 0, 750);
    assert_equivalence(&old, &new_rec, "1500 records - delete first 750").await;
}

#[tokio::test]
async fn massive_tree_delete_last_half() {
    let old = generate_records("app.bsky.feed.post", 0..1500);
    let new_rec = remove_range(&old, 750, 750);
    assert_equivalence(&old, &new_rec, "1500 records - delete last 750").await;
}

#[tokio::test]
async fn massive_tree_delete_middle_chunk() {
    let old = generate_records("app.bsky.feed.post", 0..2000);
    let new_rec = remove_range(&old, 800, 400);
    assert_equivalence(&old, &new_rec, "2000 records - delete 400 from middle").await;
}

#[tokio::test]
async fn empty_to_massive() {
    let new_rec = generate_records("app.bsky.feed.post", 0..1500);
    assert_equivalence(&[], &new_rec, "empty to 1500 records").await;
}

#[tokio::test]
async fn massive_to_empty() {
    let old = generate_records("app.bsky.feed.post", 0..1500);
    assert_equivalence(&old, &[], "1500 records to empty").await;
}

#[tokio::test]
async fn massive_complete_replacement() {
    let old = generate_records("app.bsky.feed.post", 0..1000);
    let new_rec = generate_records("app.bsky.feed.post", 1000..2000);
    assert_equivalence(&old, &new_rec, "1000 records fully replaced with 1000 different").await;
}

#[tokio::test]
async fn massive_no_change() {
    let records = generate_records("app.bsky.feed.post", 0..1500);
    assert_equivalence(&records, &records, "1500 records unchanged").await;
}

#[tokio::test]
async fn multi_collection_5_collections_500_each() {
    let collections = [
        "app.bsky.feed.like",
        "app.bsky.feed.post",
        "app.bsky.feed.repost",
        "app.bsky.graph.follow",
        "app.bsky.graph.block",
    ];
    let old = generate_multi_collection_records(&collections, 500);
    let new_rec = apply_scattered_updates(&old, 4, 30000);
    assert_equivalence(&old, &new_rec, "5 collections x 500 records - update every 4th").await;
}

#[tokio::test]
async fn multi_collection_wipe_one_collection() {
    let collections = [
        "app.bsky.feed.like",
        "app.bsky.feed.post",
        "app.bsky.feed.repost",
        "app.bsky.graph.follow",
    ];
    let old = generate_multi_collection_records(&collections, 400);

    let new_rec: Vec<_> = old
        .iter()
        .filter(|(key, _)| !key.starts_with("app.bsky.feed.repost"))
        .cloned()
        .collect();
    assert_equivalence(&old, &new_rec, "4 collections x 400 - wipe repost collection").await;
}

#[tokio::test]
async fn multi_collection_keep_only_one() {
    let collections = [
        "app.bsky.feed.like",
        "app.bsky.feed.post",
        "app.bsky.feed.repost",
        "app.bsky.graph.follow",
        "app.bsky.graph.block",
    ];
    let old = generate_multi_collection_records(&collections, 300);
    let new_rec = keep_only_collection(&old, "app.bsky.feed.post");
    assert_equivalence(&old, &new_rec, "5 collections x 300 - keep only posts").await;
}

#[tokio::test]
async fn multi_collection_add_new_collection() {
    let old_collections = [
        "app.bsky.feed.like",
        "app.bsky.feed.post",
    ];
    let old = generate_multi_collection_records(&old_collections, 500);
    let new_rec = append_records(&old, "app.bsky.graph.follow", 0..500, 40000);
    assert_equivalence(&old, &new_rec, "2 collections x 500 + add 500 follows").await;
}

#[tokio::test]
async fn mixed_ops_massive_tree() {
    let collections = [
        "app.bsky.feed.like",
        "app.bsky.feed.post",
        "app.bsky.feed.repost",
        "app.bsky.graph.follow",
    ];
    let old = generate_multi_collection_records(&collections, 400);

    let mut new_rec: Vec<_> = old
        .iter()
        .filter(|(key, _)| !key.starts_with("app.bsky.feed.repost"))
        .enumerate()
        .map(|(idx, (key, val))| {
            if key.starts_with("app.bsky.feed.like") && idx % 3 == 0 {
                (key.clone(), val + 50000)
            } else {
                (key.clone(), *val)
            }
        })
        .collect();

    new_rec.extend((0..200u32).map(|i| (make_key("app.bsky.graph.block", i), 60000 + i)));
    new_rec.sort_by(|(a, _), (b, _)| a.cmp(b));

    assert_equivalence(
        &old,
        &new_rec,
        "4 collections x 400: wipe reposts, update every 3rd like, add 200 blocks",
    )
    .await;
}

#[tokio::test]
async fn grow_tree_by_double() {
    let old = generate_records("app.bsky.feed.post", 0..1000);
    let new_rec = generate_records("app.bsky.feed.post", 0..2000);
    assert_equivalence(&old, &new_rec, "grow from 1000 to 2000").await;
}

#[tokio::test]
async fn shrink_tree_by_half() {
    let old = generate_records("app.bsky.feed.post", 0..2000);
    let new_rec = generate_records("app.bsky.feed.post", 0..1000);
    assert_equivalence(&old, &new_rec, "shrink from 2000 to 1000").await;
}

#[tokio::test]
async fn interleaved_keys_disjoint_ranges() {
    let old: Vec<_> = (0..1000u32)
        .map(|i| (make_key("app.bsky.feed.post", i * 2), i))
        .collect();
    let new_rec: Vec<_> = (0..1000u32)
        .map(|i| (make_key("app.bsky.feed.post", i * 2 + 1), i + 10000))
        .collect();
    assert_equivalence(&old, &new_rec, "1000 even-keyed records replaced by 1000 odd-keyed").await;
}

#[tokio::test]
async fn sparse_keys_wide_gaps() {
    let old: Vec<_> = (0..500u32)
        .map(|i| (make_key("app.bsky.feed.post", i * 100), i))
        .collect();
    let new_rec: Vec<_> = (0..500u32)
        .map(|i| {
            if i % 10 == 0 {
                (make_key("app.bsky.feed.post", i * 100), i + 70000)
            } else {
                (make_key("app.bsky.feed.post", i * 100), i)
            }
        })
        .collect();
    assert_equivalence(&old, &new_rec, "500 sparse keys - update every 10th").await;
}

#[tokio::test]
async fn many_collections_few_records_each() {
    let collections: Vec<String> = (0..50u32)
        .map(|i| format!("com.example.lexicon{i:02}.record"))
        .collect();
    let old: Vec<_> = collections
        .iter()
        .enumerate()
        .flat_map(|(ci, coll)| {
            let base = ci as u32 * 20;
            (0..20u32).map(move |i| (make_key(coll, i), base + i))
        })
        .collect();

    let new_rec: Vec<_> = old
        .iter()
        .enumerate()
        .filter_map(|(idx, (key, val))| {
            if idx % 15 == 0 {
                None
            } else if idx % 7 == 0 {
                Some((key.clone(), val + 80000))
            } else {
                Some((key.clone(), *val))
            }
        })
        .collect();

    assert_equivalence(&old, &new_rec, "50 collections x 20 records - delete every 15th, update every 7th").await;
}

#[tokio::test]
async fn update_all_records() {
    let old = generate_records("app.bsky.feed.post", 0..1000);
    let new_rec: Vec<_> = old
        .iter()
        .map(|(key, val)| (key.clone(), val + 90000))
        .collect();
    assert_equivalence(&old, &new_rec, "1000 records - update every single one").await;
}

#[tokio::test]
async fn delete_all_but_one() {
    let old = generate_records("app.bsky.feed.post", 0..1500);
    let new_rec = vec![old[750].clone()];
    assert_equivalence(&old, &new_rec, "1500 records - delete all but middle one").await;
}

#[tokio::test]
async fn one_to_massive() {
    let old = vec![(make_key("app.bsky.feed.post", 500), 500u32)];
    let new_rec = generate_records("app.bsky.feed.post", 0..1500);
    assert_equivalence(&old, &new_rec, "1 record to 1500 records").await;
}

#[tokio::test]
async fn delete_head_and_tail() {
    let old = generate_records("app.bsky.feed.post", 0..2000);
    let new_rec: Vec<_> = old[200..1800].to_vec();
    assert_equivalence(&old, &new_rec, "2000 records - delete first 200 and last 200").await;
}

#[tokio::test]
async fn keep_head_and_tail_only() {
    let old = generate_records("app.bsky.feed.post", 0..2000);
    let mut new_rec: Vec<_> = old[..100].to_vec();
    new_rec.extend_from_slice(&old[1900..]);
    assert_equivalence(&old, &new_rec, "2000 records - keep only first 100 and last 100").await;
}

#[tokio::test]
async fn massive_tree_update_first_and_last() {
    let old = generate_records("app.bsky.feed.post", 0..2000);
    let mut new_rec = old.clone();
    new_rec[0].1 += 99000;
    new_rec[1999].1 += 99000;
    assert_equivalence(&old, &new_rec, "2000 records - update only first and last").await;
}

#[tokio::test]
async fn overlapping_collection_swap() {
    let old_collections = [
        "app.bsky.feed.like",
        "app.bsky.feed.post",
        "app.bsky.feed.repost",
    ];
    let old = generate_multi_collection_records(&old_collections, 500);

    let mut new_rec: Vec<_> = old
        .iter()
        .filter(|(key, _)| key.starts_with("app.bsky.feed.post"))
        .cloned()
        .collect();
    new_rec.extend((0..500u32).map(|i| (make_key("app.bsky.graph.follow", i), 70000 + i)));
    new_rec.extend((0..500u32).map(|i| (make_key("app.bsky.graph.block", i), 71000 + i)));
    new_rec.sort_by(|(a, _), (b, _)| a.cmp(b));

    assert_equivalence(
        &old,
        &new_rec,
        "swap 2 of 3 collections, keep 1 (posts), 500 each",
    )
    .await;
}

#[tokio::test]
async fn swiss_cheese_deletions() {
    let old = generate_records("app.bsky.feed.post", 0..1500);
    let new_rec: Vec<_> = old
        .iter()
        .enumerate()
        .filter(|(idx, _)| {
            let bucket = idx / 50;
            bucket % 3 != 0
        })
        .map(|(_, r)| r.clone())
        .collect();
    assert_equivalence(&old, &new_rec, "1500 records - delete every 3rd chunk of 50").await;
}

#[tokio::test]
async fn mixed_ops_with_key_density_change() {
    let old: Vec<_> = (0..1000u32)
        .map(|i| (make_key("app.bsky.feed.post", i * 3), i))
        .collect();

    let mut new_rec: Vec<_> = old
        .iter()
        .filter(|(_, val)| val % 4 != 0)
        .cloned()
        .collect();
    new_rec.extend((0..500u32).map(|i| {
        (make_key("app.bsky.feed.post", i * 3 + 1), i + 100000)
    }));
    new_rec.sort_by(|(a, _), (b, _)| a.cmp(b));

    assert_equivalence(
        &old,
        &new_rec,
        "1000 sparse records: delete every 4th, insert 500 in gaps",
    )
    .await;
}
