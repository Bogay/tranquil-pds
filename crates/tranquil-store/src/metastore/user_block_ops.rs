use std::collections::HashSet;
use std::sync::Arc;

use fjall::Keyspace;
use uuid::Uuid;

use super::MetastoreError;
use super::encoding::{KeyReader, exclusive_upper_bound};
use super::keys::UserHash;
use super::scan::{count_prefix, delete_all_by_prefix};
use super::user_blocks::{user_block_key, user_block_rev_prefix, user_block_user_prefix};
use super::user_hash::UserHashMap;

pub struct UserBlockOps {
    repo_data: Keyspace,
    user_hashes: Arc<UserHashMap>,
}

impl UserBlockOps {
    pub fn new(repo_data: Keyspace, user_hashes: Arc<UserHashMap>) -> Self {
        Self {
            repo_data,
            user_hashes,
        }
    }

    pub fn insert_user_blocks<C: AsRef<[u8]>>(
        &self,
        batch: &mut fjall::OwnedWriteBatch,
        user_hash: UserHash,
        block_cids: &[C],
        repo_rev: &str,
    ) -> Result<(), MetastoreError> {
        let existing: HashSet<Vec<u8>> = match block_cids.is_empty() {
            true => HashSet::new(),
            false => {
                let prefix = user_block_user_prefix(user_hash);
                self.repo_data
                    .prefix(prefix.as_slice())
                    .filter_map(|guard| {
                        let (key_bytes, _) = guard.into_inner().ok()?;
                        extract_cid_from_key(&key_bytes).map(|c| c.to_vec())
                    })
                    .collect()
            }
        };

        block_cids.iter().try_for_each(|cid| {
            let cid = cid.as_ref();
            match cid.is_empty() {
                true => Err(MetastoreError::InvalidInput("block CID must not be empty")),
                false => {
                    if !existing.contains(cid) {
                        let key = user_block_key(user_hash, repo_rev, cid);
                        batch.insert(&self.repo_data, key.as_slice(), []);
                    }
                    Ok(())
                }
            }
        })
    }

    pub fn delete_user_blocks<C: AsRef<[u8]>>(
        &self,
        batch: &mut fjall::OwnedWriteBatch,
        user_hash: UserHash,
        block_cids: &[C],
        rev: &str,
    ) -> Result<(), MetastoreError> {
        block_cids.iter().try_for_each(|cid| {
            let cid = cid.as_ref();
            match cid.is_empty() {
                true => Err(MetastoreError::InvalidInput("block CID must not be empty")),
                false => {
                    let key = user_block_key(user_hash, rev, cid);
                    batch.remove(&self.repo_data, key.as_slice());
                    Ok(())
                }
            }
        })
    }

    pub fn delete_user_blocks_by_cid<C: AsRef<[u8]>>(
        &self,
        batch: &mut fjall::OwnedWriteBatch,
        user_hash: UserHash,
        block_cids: &[C],
    ) -> Result<(), MetastoreError> {
        match block_cids.is_empty() {
            true => Ok(()),
            false => {
                let cid_set: HashSet<&[u8]> = block_cids.iter().map(|c| c.as_ref()).collect();
                let prefix = user_block_user_prefix(user_hash);
                self.repo_data
                    .prefix(prefix.as_slice())
                    .try_for_each(|guard| {
                        let (key_bytes, _) = guard.into_inner().map_err(MetastoreError::Fjall)?;
                        match extract_cid_from_key(&key_bytes) {
                            Some(cid) if cid_set.contains(cid.as_slice()) => {
                                batch.remove(&self.repo_data, key_bytes.as_ref());
                                Ok(())
                            }
                            _ => Ok(()),
                        }
                    })
            }
        }
    }

    pub fn delete_all_user_blocks(
        &self,
        batch: &mut fjall::OwnedWriteBatch,
        user_hash: UserHash,
    ) -> Result<(), MetastoreError> {
        let prefix = user_block_user_prefix(user_hash);
        delete_all_by_prefix(&self.repo_data, batch, prefix.as_slice())
    }

    pub fn get_user_block_cids_since_rev(
        &self,
        user_id: Uuid,
        since_rev: &str,
    ) -> Result<Vec<Vec<u8>>, MetastoreError> {
        let user_hash = match self.user_hashes.get(&user_id) {
            Some(h) => h,
            None => return Ok(Vec::new()),
        };

        let since_prefix = user_block_rev_prefix(user_hash, since_rev);
        let since_upper = exclusive_upper_bound(since_prefix.as_slice())
            .expect("user block rev prefix always contains non-0xFF bytes");

        let user_prefix = user_block_user_prefix(user_hash);
        let user_upper = exclusive_upper_bound(user_prefix.as_slice())
            .expect("user block user prefix always contains non-0xFF bytes");

        self.repo_data
            .range(since_upper.as_slice()..user_upper.as_slice())
            .map(|guard| {
                let (key_bytes, _) = guard.into_inner().map_err(MetastoreError::Fjall)?;
                extract_cid_from_key(&key_bytes)
                    .ok_or(MetastoreError::CorruptData("invalid user_blocks key"))
            })
            .collect()
    }

    pub fn find_unreferenced(&self, candidate_cids: &[Vec<u8>]) -> Vec<Vec<u8>> {
        match candidate_cids.is_empty() {
            true => Vec::new(),
            false => {
                let mut remaining: HashSet<Vec<u8>> = candidate_cids.iter().cloned().collect();
                let tag_prefix = super::keys::KeyTag::USER_BLOCKS.raw();
                let mut iter = self.repo_data.prefix([tag_prefix]);
                loop {
                    match remaining.is_empty() {
                        true => break,
                        false => match iter.next() {
                            None => break,
                            Some(guard) => {
                                if let Ok((key_bytes, _)) = guard.into_inner()
                                    && let Some(cid) = extract_cid_from_key(&key_bytes)
                                {
                                    remaining.remove(&cid);
                                }
                            }
                        },
                    }
                }
                remaining.into_iter().collect()
            }
        }
    }

    pub fn count_user_blocks(&self, user_id: Uuid) -> Result<i64, MetastoreError> {
        let user_hash = match self.user_hashes.get(&user_id) {
            Some(h) => h,
            None => return Ok(0),
        };
        let prefix = user_block_user_prefix(user_hash);
        count_prefix(&self.repo_data, prefix.as_slice())
    }
}

fn extract_cid_from_key(key_bytes: &[u8]) -> Option<Vec<u8>> {
    let mut reader = KeyReader::new(key_bytes);
    reader.tag()?;
    reader.u64()?;
    reader.string()?;
    match reader.remaining().is_empty() {
        true => None,
        false => Some(reader.remaining().to_vec()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metastore::{Metastore, MetastoreConfig};

    fn open_fresh() -> (tempfile::TempDir, Metastore) {
        let dir = tempfile::TempDir::new().unwrap();
        let ms = Metastore::open(
            dir.path(),
            MetastoreConfig {
                cache_size_bytes: 64 * 1024 * 1024,
            },
        )
        .unwrap();
        (dir, ms)
    }

    fn setup_user(ms: &Metastore) -> (Uuid, UserHash) {
        let uuid = Uuid::new_v4();
        let hash = UserHash::from_did("did:plc:testuser1");
        let mut batch = ms.database().batch();
        ms.user_hashes()
            .stage_insert(&mut batch, uuid, hash)
            .unwrap();
        batch.commit().unwrap();
        (uuid, hash)
    }

    #[test]
    fn insert_and_count() {
        let (_dir, ms) = open_fresh();
        let (uuid, hash) = setup_user(&ms);
        let ops = ms.user_block_ops();

        let cids = vec![vec![0x01, 0x71], vec![0x02, 0x72], vec![0x03, 0x73]];

        let mut batch = ms.database().batch();
        ops.insert_user_blocks(&mut batch, hash, &cids, "rev1")
            .unwrap();
        batch.commit().unwrap();

        assert_eq!(ops.count_user_blocks(uuid).unwrap(), 3);
    }

    #[test]
    fn get_since_rev_returns_later_revisions() {
        let (_dir, ms) = open_fresh();
        let (uuid, hash) = setup_user(&ms);
        let ops = ms.user_block_ops();

        let cids_abc = vec![vec![0x01], vec![0x02]];
        let cids_def = vec![vec![0x03]];

        let mut batch = ms.database().batch();
        ops.insert_user_blocks(&mut batch, hash, &cids_abc, "abc")
            .unwrap();
        ops.insert_user_blocks(&mut batch, hash, &cids_def, "def")
            .unwrap();
        batch.commit().unwrap();

        let since_abc = ops.get_user_block_cids_since_rev(uuid, "abc").unwrap();
        assert_eq!(since_abc.len(), 1);
        assert_eq!(since_abc[0], vec![0x03]);

        let since_def = ops.get_user_block_cids_since_rev(uuid, "def").unwrap();
        assert!(since_def.is_empty());
    }

    #[test]
    fn get_since_rev_with_both_revisions() {
        let (_dir, ms) = open_fresh();
        let (uuid, hash) = setup_user(&ms);
        let ops = ms.user_block_ops();

        let cids_r1 = vec![vec![0x01]];
        let cids_r2 = vec![vec![0x02]];

        let mut batch = ms.database().batch();
        ops.insert_user_blocks(&mut batch, hash, &cids_r1, "aaa")
            .unwrap();
        ops.insert_user_blocks(&mut batch, hash, &cids_r2, "bbb")
            .unwrap();
        batch.commit().unwrap();

        let since_before = ops.get_user_block_cids_since_rev(uuid, "aaa").unwrap();
        assert_eq!(since_before.len(), 1);
        assert_eq!(since_before[0], vec![0x02]);

        let all = ops.get_user_block_cids_since_rev(uuid, "").unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn delete_blocks_at_rev() {
        let (_dir, ms) = open_fresh();
        let (uuid, hash) = setup_user(&ms);
        let ops = ms.user_block_ops();

        let cids = vec![vec![0x01], vec![0x02], vec![0x03]];

        let mut batch = ms.database().batch();
        ops.insert_user_blocks(&mut batch, hash, &cids, "rev1")
            .unwrap();
        batch.commit().unwrap();
        assert_eq!(ops.count_user_blocks(uuid).unwrap(), 3);

        let to_delete = vec![vec![0x01], vec![0x03]];
        let mut batch = ms.database().batch();
        ops.delete_user_blocks(&mut batch, hash, &to_delete, "rev1")
            .unwrap();
        batch.commit().unwrap();

        assert_eq!(ops.count_user_blocks(uuid).unwrap(), 1);
    }

    #[test]
    fn delete_wrong_rev_is_noop() {
        let (_dir, ms) = open_fresh();
        let (uuid, hash) = setup_user(&ms);
        let ops = ms.user_block_ops();

        let cids = vec![vec![0x01], vec![0x02]];

        let mut batch = ms.database().batch();
        ops.insert_user_blocks(&mut batch, hash, &cids, "rev1")
            .unwrap();
        batch.commit().unwrap();

        let mut batch = ms.database().batch();
        ops.delete_user_blocks(&mut batch, hash, &cids, "wrong_rev")
            .unwrap();
        batch.commit().unwrap();

        assert_eq!(ops.count_user_blocks(uuid).unwrap(), 2);
    }

    #[test]
    fn delete_all_user_blocks_clears_all_revisions() {
        let (_dir, ms) = open_fresh();
        let (uuid, hash) = setup_user(&ms);
        let ops = ms.user_block_ops();

        let mut batch = ms.database().batch();
        ops.insert_user_blocks(&mut batch, hash, &[vec![0x01], vec![0x02]], "rev1")
            .unwrap();
        ops.insert_user_blocks(&mut batch, hash, &[vec![0x03]], "rev2")
            .unwrap();
        batch.commit().unwrap();
        assert_eq!(ops.count_user_blocks(uuid).unwrap(), 3);

        let mut batch = ms.database().batch();
        ops.delete_all_user_blocks(&mut batch, hash).unwrap();
        batch.commit().unwrap();

        assert_eq!(ops.count_user_blocks(uuid).unwrap(), 0);
    }

    #[test]
    fn empty_rev_scan_returns_empty() {
        let (_dir, ms) = open_fresh();
        let (uuid, _hash) = setup_user(&ms);
        let ops = ms.user_block_ops();

        let result = ops.get_user_block_cids_since_rev(uuid, "anything").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn unknown_user_returns_zero_count() {
        let (_dir, ms) = open_fresh();
        let ops = ms.user_block_ops();
        let unknown = Uuid::new_v4();
        assert_eq!(ops.count_user_blocks(unknown).unwrap(), 0);
    }

    #[test]
    fn blocks_survive_reopen() {
        let dir = tempfile::TempDir::new().unwrap();
        let uuid = Uuid::new_v4();
        let hash = UserHash::from_did("did:plc:persist");

        {
            let ms = Metastore::open(
                dir.path(),
                MetastoreConfig {
                    cache_size_bytes: 64 * 1024 * 1024,
                },
            )
            .unwrap();
            let mut batch = ms.database().batch();
            ms.user_hashes()
                .stage_insert(&mut batch, uuid, hash)
                .unwrap();
            batch.commit().unwrap();

            let ops = ms.user_block_ops();
            let cids = vec![vec![0xAA, 0xBB], vec![0xCC, 0xDD]];
            let mut batch = ms.database().batch();
            ops.insert_user_blocks(&mut batch, hash, &cids, "rev1")
                .unwrap();
            batch.commit().unwrap();
            ms.persist().unwrap();
        }

        {
            let ms = Metastore::open(
                dir.path(),
                MetastoreConfig {
                    cache_size_bytes: 64 * 1024 * 1024,
                },
            )
            .unwrap();
            let ops = ms.user_block_ops();
            assert_eq!(ops.count_user_blocks(uuid).unwrap(), 2);
        }
    }

    #[test]
    fn multiple_users_isolated() {
        let (_dir, ms) = open_fresh();

        let uuid1 = Uuid::new_v4();
        let hash1 = UserHash::from_did("did:plc:user1");
        let uuid2 = Uuid::new_v4();
        let hash2 = UserHash::from_did("did:plc:user2");

        let mut batch = ms.database().batch();
        ms.user_hashes()
            .stage_insert(&mut batch, uuid1, hash1)
            .unwrap();
        ms.user_hashes()
            .stage_insert(&mut batch, uuid2, hash2)
            .unwrap();
        batch.commit().unwrap();

        let ops = ms.user_block_ops();

        let mut batch = ms.database().batch();
        ops.insert_user_blocks(&mut batch, hash1, &[vec![0x01], vec![0x02]], "rev1")
            .unwrap();
        ops.insert_user_blocks(&mut batch, hash2, &[vec![0x03]], "rev1")
            .unwrap();
        batch.commit().unwrap();

        assert_eq!(ops.count_user_blocks(uuid1).unwrap(), 2);
        assert_eq!(ops.count_user_blocks(uuid2).unwrap(), 1);

        let mut batch = ms.database().batch();
        ops.delete_user_blocks(&mut batch, hash1, &[vec![0x01]], "rev1")
            .unwrap();
        batch.commit().unwrap();

        assert_eq!(ops.count_user_blocks(uuid1).unwrap(), 1);
        assert_eq!(ops.count_user_blocks(uuid2).unwrap(), 1);
    }

    #[test]
    fn delete_all_does_not_affect_other_users() {
        let (_dir, ms) = open_fresh();

        let uuid1 = Uuid::new_v4();
        let hash1 = UserHash::from_did("did:plc:user1");
        let uuid2 = Uuid::new_v4();
        let hash2 = UserHash::from_did("did:plc:user2");

        let mut batch = ms.database().batch();
        ms.user_hashes()
            .stage_insert(&mut batch, uuid1, hash1)
            .unwrap();
        ms.user_hashes()
            .stage_insert(&mut batch, uuid2, hash2)
            .unwrap();
        batch.commit().unwrap();

        let ops = ms.user_block_ops();

        let mut batch = ms.database().batch();
        ops.insert_user_blocks(&mut batch, hash1, &[vec![0x01]], "rev1")
            .unwrap();
        ops.insert_user_blocks(&mut batch, hash2, &[vec![0x02]], "rev1")
            .unwrap();
        batch.commit().unwrap();

        let mut batch = ms.database().batch();
        ops.delete_all_user_blocks(&mut batch, hash1).unwrap();
        batch.commit().unwrap();

        assert_eq!(ops.count_user_blocks(uuid1).unwrap(), 0);
        assert_eq!(ops.count_user_blocks(uuid2).unwrap(), 1);
    }

    #[test]
    fn cids_with_null_bytes_roundtrip_through_storage() {
        let (_dir, ms) = open_fresh();
        let (uuid, hash) = setup_user(&ms);
        let ops = ms.user_block_ops();

        let cids = vec![
            vec![0x00, 0x00, 0x01],
            vec![0x00, 0x01, 0x00, 0x00],
            vec![0x00, 0x00],
        ];

        let mut batch = ms.database().batch();
        ops.insert_user_blocks(&mut batch, hash, &cids, "rev1")
            .unwrap();
        batch.commit().unwrap();

        assert_eq!(ops.count_user_blocks(uuid).unwrap(), 3);

        let retrieved = ops.get_user_block_cids_since_rev(uuid, "").unwrap();
        assert_eq!(retrieved.len(), 3);
        let mut expected = cids.clone();
        expected.sort();
        assert_eq!(retrieved, expected);
    }

    #[test]
    fn insert_empty_cid_is_rejected() {
        let (_dir, ms) = open_fresh();
        let (_uuid, hash) = setup_user(&ms);
        let ops = ms.user_block_ops();

        let cids = vec![vec![]];
        let mut batch = ms.database().batch();
        let result = ops.insert_user_blocks(&mut batch, hash, &cids, "rev1");
        assert!(matches!(result, Err(MetastoreError::InvalidInput(_))));
    }

    #[test]
    fn delete_empty_cid_is_rejected() {
        let (_dir, ms) = open_fresh();
        let (_uuid, hash) = setup_user(&ms);
        let ops = ms.user_block_ops();

        let cids = vec![vec![]];
        let mut batch = ms.database().batch();
        let result = ops.delete_user_blocks(&mut batch, hash, &cids, "rev1");
        assert!(matches!(result, Err(MetastoreError::InvalidInput(_))));
    }

    #[test]
    fn since_rev_nonexistent_returns_later_revisions() {
        let (_dir, ms) = open_fresh();
        let (uuid, hash) = setup_user(&ms);
        let ops = ms.user_block_ops();

        let mut batch = ms.database().batch();
        ops.insert_user_blocks(&mut batch, hash, &[vec![0x01]], "aaa")
            .unwrap();
        ops.insert_user_blocks(&mut batch, hash, &[vec![0x02]], "bbb")
            .unwrap();
        ops.insert_user_blocks(&mut batch, hash, &[vec![0x03]], "ddd")
            .unwrap();
        batch.commit().unwrap();

        let result = ops.get_user_block_cids_since_rev(uuid, "aab").unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], vec![0x02]);
        assert_eq!(result[1], vec![0x03]);

        let result = ops.get_user_block_cids_since_rev(uuid, "ccc").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], vec![0x03]);
    }
}
