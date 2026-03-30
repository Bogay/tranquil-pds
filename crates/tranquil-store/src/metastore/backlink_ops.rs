use std::sync::Arc;

use fjall::{Keyspace, OwnedWriteBatch};
use uuid::Uuid;

use super::MetastoreError;
use super::backlinks::{
    BacklinkValue, backlink_by_user_key, backlink_by_user_prefix, backlink_by_user_record_prefix,
    backlink_key, backlink_target_user_prefix, discriminant_to_path, path_to_discriminant,
};
use super::encoding::KeyReader;
use super::keys::{KeyTag, UserHash};
use super::user_hash::UserHashMap;

use tranquil_db_traits::Backlink;
use tranquil_types::{AtUri, Nsid};

pub(super) fn parse_backlink_by_user_fields(key_bytes: &[u8]) -> Option<(String, String, String)> {
    let mut reader = KeyReader::new(key_bytes);
    let tag = reader.tag()?;
    match tag == KeyTag::BACKLINK_BY_USER.raw() {
        true => {
            let _user_hash = reader.u64()?;
            let collection = reader.string()?;
            let rkey = reader.string()?;
            let link_target = reader.string()?;
            Some((collection, rkey, link_target))
        }
        false => None,
    }
}

pub(super) fn remove_backlinks_for_record(
    batch: &mut OwnedWriteBatch,
    indexes: &Keyspace,
    user_hash: UserHash,
    collection: &str,
    rkey: &str,
) -> Result<(), MetastoreError> {
    let record_prefix = backlink_by_user_record_prefix(user_hash, collection, rkey);
    indexes
        .prefix(record_prefix.as_slice())
        .try_for_each(|guard| {
            let (key_bytes, _) = guard.into_inner().map_err(MetastoreError::Fjall)?;

            let (_, _, link_target) = parse_backlink_by_user_fields(&key_bytes).ok_or(
                MetastoreError::CorruptData("unparseable BACKLINK_BY_USER key"),
            )?;

            let primary = backlink_key(&link_target, user_hash, collection, rkey);
            batch.remove(indexes, primary.as_slice());
            batch.remove(indexes, key_bytes.as_ref());

            Ok::<_, MetastoreError>(())
        })
}

pub struct BacklinkOps {
    indexes: Keyspace,
    user_hashes: Arc<UserHashMap>,
}

impl BacklinkOps {
    pub fn new(indexes: Keyspace, user_hashes: Arc<UserHashMap>) -> Self {
        Self {
            indexes,
            user_hashes,
        }
    }

    pub fn add_backlinks(
        &self,
        batch: &mut OwnedWriteBatch,
        user_hash: UserHash,
        backlinks: &[Backlink],
    ) -> Result<(), MetastoreError> {
        backlinks
            .iter()
            .try_for_each(|bl| self.add_single_backlink(batch, user_hash, bl))
    }

    fn add_single_backlink(
        &self,
        batch: &mut OwnedWriteBatch,
        user_hash: UserHash,
        bl: &Backlink,
    ) -> Result<(), MetastoreError> {
        let collection = bl.uri.collection().ok_or(MetastoreError::InvalidInput(
            "backlink uri missing collection",
        ))?;
        let rkey = bl
            .uri
            .rkey()
            .ok_or(MetastoreError::InvalidInput("backlink uri missing rkey"))?;

        let primary = backlink_key(&bl.link_to, user_hash, collection, rkey);
        let value = BacklinkValue {
            source_uri: bl.uri.as_str().to_owned(),
            path: path_to_discriminant(bl.path),
        };
        batch.insert(&self.indexes, primary.as_slice(), value.serialize());

        let reverse = backlink_by_user_key(user_hash, collection, rkey, &bl.link_to);
        batch.insert(&self.indexes, reverse.as_slice(), []);
        Ok(())
    }

    pub fn remove_backlinks_by_uri(
        &self,
        batch: &mut OwnedWriteBatch,
        user_hash: UserHash,
        uri: &AtUri,
    ) -> Result<(), MetastoreError> {
        let collection = uri.collection().ok_or(MetastoreError::InvalidInput(
            "backlink uri missing collection",
        ))?;
        let rkey = uri
            .rkey()
            .ok_or(MetastoreError::InvalidInput("backlink uri missing rkey"))?;

        remove_backlinks_for_record(batch, &self.indexes, user_hash, collection, rkey)
    }

    pub fn remove_backlinks_by_repo(
        &self,
        batch: &mut OwnedWriteBatch,
        user_hash: UserHash,
    ) -> Result<(), MetastoreError> {
        let user_prefix = backlink_by_user_prefix(user_hash);
        self.indexes
            .prefix(user_prefix.as_slice())
            .try_for_each(|guard| {
                let (key_bytes, _) = guard.into_inner().map_err(MetastoreError::Fjall)?;

                let (collection, rkey, link_target) = parse_backlink_by_user_fields(&key_bytes)
                    .ok_or(MetastoreError::CorruptData(
                        "unparseable BACKLINK_BY_USER key",
                    ))?;

                let primary = backlink_key(&link_target, user_hash, &collection, &rkey);
                batch.remove(&self.indexes, primary.as_slice());
                batch.remove(&self.indexes, key_bytes.as_ref());

                Ok::<_, MetastoreError>(())
            })
    }

    pub fn get_backlink_conflicts(
        &self,
        repo_id: Uuid,
        collection: &Nsid,
        backlinks: &[Backlink],
    ) -> Result<Vec<AtUri>, MetastoreError> {
        if backlinks.is_empty() {
            return Ok(Vec::new());
        }

        let user_hash = self
            .user_hashes
            .get(&repo_id)
            .ok_or(MetastoreError::InvalidInput("unknown repo_id"))?;

        let collection_str = collection.as_str();

        let mut seen = std::collections::HashSet::new();
        backlinks.iter().try_fold(Vec::new(), |mut conflicts, bl| {
            let prefix = backlink_target_user_prefix(&bl.link_to, user_hash);
            self.indexes
                .prefix(prefix.as_slice())
                .try_for_each(|guard| {
                    let (_, val_bytes) = guard.into_inner().map_err(MetastoreError::Fjall)?;

                    let val = BacklinkValue::deserialize(&val_bytes).ok_or(
                        MetastoreError::CorruptData("corrupt backlink value in indexes partition"),
                    )?;

                    let uri: AtUri = val.source_uri.into();
                    let matches_collection = uri.collection().is_some_and(|c| c == collection_str);
                    let matches_path = match discriminant_to_path(val.path) {
                        Some(p) => p == bl.path,
                        None => {
                            tracing::warn!(
                                discriminant = val.path,
                                uri = %uri,
                                "unknown backlink path discriminant in indexes partition"
                            );
                            false
                        }
                    };
                    if matches_collection && matches_path && !seen.contains(uri.as_str()) {
                        seen.insert(uri.as_str().to_owned());
                        conflicts.push(uri);
                    }

                    Ok::<_, MetastoreError>(())
                })?;
            Ok(conflicts)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metastore::backlinks::{backlink_by_user_prefix, backlink_target_prefix};
    use crate::metastore::partitions::Partition;
    use crate::metastore::{Metastore, MetastoreConfig};
    use tranquil_db_traits::{Backlink, BacklinkPath};
    use tranquil_types::{Did, Handle, Nsid};

    struct TestHarness {
        _dir: tempfile::TempDir,
        metastore: Metastore,
    }

    fn setup() -> TestHarness {
        let dir = tempfile::TempDir::new().unwrap();
        let metastore = Metastore::open(
            dir.path(),
            MetastoreConfig {
                cache_size_bytes: 64 * 1024 * 1024,
            },
        )
        .unwrap();
        TestHarness {
            _dir: dir,
            metastore,
        }
    }

    fn test_cid_link(seed: u8) -> tranquil_types::CidLink {
        let digest: [u8; 32] = std::array::from_fn(|i| seed.wrapping_add(i as u8));
        let mh = multihash::Multihash::<64>::wrap(0x12, &digest).unwrap();
        let c = cid::Cid::new_v1(0x71, mh);
        tranquil_types::CidLink::from_cid(&c)
    }

    fn create_repo(h: &TestHarness, name: &str, seed: u8) -> (Uuid, UserHash) {
        let user_id = Uuid::new_v4();
        let did = Did::from(format!("did:plc:{name}"));
        let handle = Handle::from(format!("{name}.test.invalid"));
        let cid = test_cid_link(seed);
        h.metastore
            .repo_ops()
            .create_repo(h.metastore.database(), user_id, &did, &handle, &cid, "rev0")
            .unwrap();
        let user_hash = h.metastore.user_hashes().get(&user_id).unwrap();
        (user_id, user_hash)
    }

    fn count_prefix(ks: &fjall::Keyspace, prefix: &[u8]) -> usize {
        ks.prefix(prefix)
            .map(|g| g.into_inner().expect("prefix scan must not fail in test"))
            .fold(0, |acc, _| acc + 1)
    }

    #[test]
    fn add_and_query_by_target() {
        let h = setup();
        let ops = h.metastore.backlink_ops();
        let (_user_id, user_hash) = create_repo(&h, "olaren", 1);

        let uri = AtUri::from_parts("did:plc:olaren", "app.bsky.feed.like", "3k2abc");
        let backlinks = vec![Backlink {
            uri: uri.clone(),
            path: BacklinkPath::SubjectUri,
            link_to: "at://did:plc:target/app.bsky.feed.post/3k2post".to_string(),
        }];

        let mut batch = h.metastore.database().batch();
        ops.add_backlinks(&mut batch, user_hash, &backlinks)
            .unwrap();
        batch.commit().unwrap();

        let indexes = h.metastore.partition(Partition::Indexes);
        let target_prefix =
            backlink_target_prefix("at://did:plc:target/app.bsky.feed.post/3k2post");
        assert_eq!(count_prefix(indexes, target_prefix.as_slice()), 1);

        let user_prefix = backlink_by_user_prefix(user_hash);
        assert_eq!(count_prefix(indexes, user_prefix.as_slice()), 1);
    }

    #[test]
    fn remove_by_uri_deletes_both_indexes() {
        let h = setup();
        let ops = h.metastore.backlink_ops();
        let (_user_id, user_hash) = create_repo(&h, "teq", 2);

        let uri = AtUri::from_parts("did:plc:teq", "app.bsky.graph.follow", "3k2fol");
        let backlinks = vec![Backlink {
            uri: uri.clone(),
            path: BacklinkPath::Subject,
            link_to: "did:plc:target_user".to_string(),
        }];

        let mut batch = h.metastore.database().batch();
        ops.add_backlinks(&mut batch, user_hash, &backlinks)
            .unwrap();
        batch.commit().unwrap();

        let indexes = h.metastore.partition(Partition::Indexes);
        assert_eq!(
            count_prefix(
                indexes,
                backlink_target_prefix("did:plc:target_user").as_slice()
            ),
            1
        );

        let mut batch = h.metastore.database().batch();
        ops.remove_backlinks_by_uri(&mut batch, user_hash, &uri)
            .unwrap();
        batch.commit().unwrap();

        assert_eq!(
            count_prefix(
                indexes,
                backlink_target_prefix("did:plc:target_user").as_slice()
            ),
            0
        );
        assert_eq!(
            count_prefix(indexes, backlink_by_user_prefix(user_hash).as_slice()),
            0
        );
    }

    #[test]
    fn remove_by_repo_deletes_all_user_backlinks() {
        let h = setup();
        let ops = h.metastore.backlink_ops();
        let (_user_id, user_hash) = create_repo(&h, "nel", 3);

        let backlinks: Vec<Backlink> = (0..5)
            .map(|i| Backlink {
                uri: AtUri::from_parts("did:plc:nel", "app.bsky.feed.like", &format!("3k2r{i}")),
                path: BacklinkPath::SubjectUri,
                link_to: format!("at://did:plc:target{i}/app.bsky.feed.post/3k2p{i}"),
            })
            .collect();

        let mut batch = h.metastore.database().batch();
        ops.add_backlinks(&mut batch, user_hash, &backlinks)
            .unwrap();
        batch.commit().unwrap();

        let indexes = h.metastore.partition(Partition::Indexes);
        assert_eq!(
            count_prefix(indexes, backlink_by_user_prefix(user_hash).as_slice()),
            5
        );

        let mut batch = h.metastore.database().batch();
        ops.remove_backlinks_by_repo(&mut batch, user_hash).unwrap();
        batch.commit().unwrap();

        assert_eq!(
            count_prefix(indexes, backlink_by_user_prefix(user_hash).as_slice()),
            0
        );

        (0..5).for_each(|i| {
            let target = format!("at://did:plc:target{i}/app.bsky.feed.post/3k2p{i}");
            let prefix = backlink_target_prefix(&target);
            assert_eq!(count_prefix(indexes, prefix.as_slice()), 0);
        });
    }

    #[test]
    fn get_backlink_conflicts_finds_matching() {
        let h = setup();
        let ops = h.metastore.backlink_ops();
        let (user_id, user_hash) = create_repo(&h, "lyna", 4);

        let existing = Backlink {
            uri: AtUri::from_parts("did:plc:lyna", "app.bsky.feed.like", "3k2old"),
            path: BacklinkPath::SubjectUri,
            link_to: "at://did:plc:someone/app.bsky.feed.post/3k2p1".to_string(),
        };

        let mut batch = h.metastore.database().batch();
        ops.add_backlinks(&mut batch, user_hash, &[existing])
            .unwrap();
        batch.commit().unwrap();

        let proposed = vec![Backlink {
            uri: AtUri::from_parts("did:plc:lyna", "app.bsky.feed.like", "3k2new"),
            path: BacklinkPath::SubjectUri,
            link_to: "at://did:plc:someone/app.bsky.feed.post/3k2p1".to_string(),
        }];

        let collection = Nsid::from("app.bsky.feed.like".to_string());
        let conflicts = ops
            .get_backlink_conflicts(user_id, &collection, &proposed)
            .unwrap();

        assert_eq!(conflicts.len(), 1);
        assert_eq!(
            conflicts[0].as_str(),
            "at://did:plc:lyna/app.bsky.feed.like/3k2old"
        );
    }

    #[test]
    fn get_backlink_conflicts_ignores_different_collection() {
        let h = setup();
        let ops = h.metastore.backlink_ops();
        let (user_id, user_hash) = create_repo(&h, "bailey", 5);

        let existing = Backlink {
            uri: AtUri::from_parts("did:plc:bailey", "app.bsky.feed.like", "3k2old"),
            path: BacklinkPath::SubjectUri,
            link_to: "at://did:plc:someone/app.bsky.feed.post/3k2p1".to_string(),
        };

        let mut batch = h.metastore.database().batch();
        ops.add_backlinks(&mut batch, user_hash, &[existing])
            .unwrap();
        batch.commit().unwrap();

        let proposed = vec![Backlink {
            uri: AtUri::from_parts("did:plc:bailey", "app.bsky.feed.repost", "3k2new"),
            path: BacklinkPath::SubjectUri,
            link_to: "at://did:plc:someone/app.bsky.feed.post/3k2p1".to_string(),
        }];

        let collection = Nsid::from("app.bsky.feed.repost".to_string());
        let conflicts = ops
            .get_backlink_conflicts(user_id, &collection, &proposed)
            .unwrap();

        assert!(conflicts.is_empty());
    }

    #[test]
    fn get_backlink_conflicts_ignores_different_path() {
        let h = setup();
        let ops = h.metastore.backlink_ops();
        let (user_id, user_hash) = create_repo(&h, "olaren", 6);

        let existing = Backlink {
            uri: AtUri::from_parts("did:plc:olaren", "app.bsky.graph.follow", "3k2old"),
            path: BacklinkPath::Subject,
            link_to: "did:plc:target".to_string(),
        };

        let mut batch = h.metastore.database().batch();
        ops.add_backlinks(&mut batch, user_hash, &[existing])
            .unwrap();
        batch.commit().unwrap();

        let proposed = vec![Backlink {
            uri: AtUri::from_parts("did:plc:olaren", "app.bsky.graph.follow", "3k2new"),
            path: BacklinkPath::SubjectUri,
            link_to: "did:plc:target".to_string(),
        }];

        let collection = Nsid::from("app.bsky.graph.follow".to_string());
        let conflicts = ops
            .get_backlink_conflicts(user_id, &collection, &proposed)
            .unwrap();

        assert!(conflicts.is_empty());
    }

    #[test]
    fn get_backlink_conflicts_ignores_other_users() {
        let h = setup();
        let ops = h.metastore.backlink_ops();
        let (_user_id_a, user_hash_a) = create_repo(&h, "teq", 7);
        let (user_id_b, _user_hash_b) = create_repo(&h, "nel", 8);

        let existing = Backlink {
            uri: AtUri::from_parts("did:plc:teq", "app.bsky.feed.like", "3k2old"),
            path: BacklinkPath::SubjectUri,
            link_to: "at://did:plc:target/app.bsky.feed.post/3k2p1".to_string(),
        };

        let mut batch = h.metastore.database().batch();
        ops.add_backlinks(&mut batch, user_hash_a, &[existing])
            .unwrap();
        batch.commit().unwrap();

        let proposed = vec![Backlink {
            uri: AtUri::from_parts("did:plc:nel", "app.bsky.feed.like", "3k2new"),
            path: BacklinkPath::SubjectUri,
            link_to: "at://did:plc:target/app.bsky.feed.post/3k2p1".to_string(),
        }];

        let collection = Nsid::from("app.bsky.feed.like".to_string());
        let conflicts = ops
            .get_backlink_conflicts(user_id_b, &collection, &proposed)
            .unwrap();

        assert!(conflicts.is_empty());
    }

    #[test]
    fn get_backlink_conflicts_includes_self_match() {
        let h = setup();
        let ops = h.metastore.backlink_ops();
        let (user_id, user_hash) = create_repo(&h, "lyna", 12);

        let existing = Backlink {
            uri: AtUri::from_parts("did:plc:lyna", "app.bsky.feed.like", "3k2same"),
            path: BacklinkPath::SubjectUri,
            link_to: "at://did:plc:someone/app.bsky.feed.post/3k2p1".to_string(),
        };

        let mut batch = h.metastore.database().batch();
        ops.add_backlinks(&mut batch, user_hash, &[existing])
            .unwrap();
        batch.commit().unwrap();

        let proposed = vec![Backlink {
            uri: AtUri::from_parts("did:plc:lyna", "app.bsky.feed.like", "3k2same"),
            path: BacklinkPath::SubjectUri,
            link_to: "at://did:plc:someone/app.bsky.feed.post/3k2p1".to_string(),
        }];

        let collection = Nsid::from("app.bsky.feed.like".to_string());
        let conflicts = ops
            .get_backlink_conflicts(user_id, &collection, &proposed)
            .unwrap();

        assert_eq!(conflicts.len(), 1);
    }

    #[test]
    fn empty_backlinks_returns_empty_conflicts() {
        let h = setup();
        let ops = h.metastore.backlink_ops();
        let (user_id, _user_hash) = create_repo(&h, "bailey", 9);

        let collection = Nsid::from("app.bsky.feed.like".to_string());
        let conflicts = ops
            .get_backlink_conflicts(user_id, &collection, &[])
            .unwrap();
        assert!(conflicts.is_empty());
    }

    #[test]
    fn remove_by_uri_only_removes_matching_rkey() {
        let h = setup();
        let ops = h.metastore.backlink_ops();
        let (_user_id, user_hash) = create_repo(&h, "bailey", 10);

        let bl1 = Backlink {
            uri: AtUri::from_parts("did:plc:bailey", "app.bsky.feed.like", "3k2aaa"),
            path: BacklinkPath::SubjectUri,
            link_to: "at://did:plc:t1/app.bsky.feed.post/p1".to_string(),
        };
        let bl2 = Backlink {
            uri: AtUri::from_parts("did:plc:bailey", "app.bsky.feed.like", "3k2bbb"),
            path: BacklinkPath::SubjectUri,
            link_to: "at://did:plc:t2/app.bsky.feed.post/p2".to_string(),
        };

        let mut batch = h.metastore.database().batch();
        ops.add_backlinks(&mut batch, user_hash, &[bl1.clone(), bl2])
            .unwrap();
        batch.commit().unwrap();

        let indexes = h.metastore.partition(Partition::Indexes);
        assert_eq!(
            count_prefix(indexes, backlink_by_user_prefix(user_hash).as_slice()),
            2
        );

        let mut batch = h.metastore.database().batch();
        ops.remove_backlinks_by_uri(&mut batch, user_hash, &bl1.uri)
            .unwrap();
        batch.commit().unwrap();

        assert_eq!(
            count_prefix(indexes, backlink_by_user_prefix(user_hash).as_slice()),
            1
        );
        assert_eq!(
            count_prefix(
                indexes,
                backlink_target_prefix("at://did:plc:t1/app.bsky.feed.post/p1").as_slice()
            ),
            0
        );
        assert_eq!(
            count_prefix(
                indexes,
                backlink_target_prefix("at://did:plc:t2/app.bsky.feed.post/p2").as_slice()
            ),
            1
        );
    }

    #[test]
    fn conflicts_deduplicates_results() {
        let h = setup();
        let ops = h.metastore.backlink_ops();
        let (user_id, user_hash) = create_repo(&h, "kate", 11);

        let existing = Backlink {
            uri: AtUri::from_parts("did:plc:kate", "app.bsky.feed.like", "3k2old"),
            path: BacklinkPath::SubjectUri,
            link_to: "at://did:plc:someone/app.bsky.feed.post/3k2p1".to_string(),
        };

        let mut batch = h.metastore.database().batch();
        ops.add_backlinks(&mut batch, user_hash, &[existing])
            .unwrap();
        batch.commit().unwrap();

        let proposed = vec![
            Backlink {
                uri: AtUri::from_parts("did:plc:kate", "app.bsky.feed.like", "3k2new1"),
                path: BacklinkPath::SubjectUri,
                link_to: "at://did:plc:someone/app.bsky.feed.post/3k2p1".to_string(),
            },
            Backlink {
                uri: AtUri::from_parts("did:plc:kate", "app.bsky.feed.like", "3k2new2"),
                path: BacklinkPath::SubjectUri,
                link_to: "at://did:plc:someone/app.bsky.feed.post/3k2p1".to_string(),
            },
        ];

        let collection = Nsid::from("app.bsky.feed.like".to_string());
        let conflicts = ops
            .get_backlink_conflicts(user_id, &collection, &proposed)
            .unwrap();

        assert_eq!(conflicts.len(), 1);
    }
}
