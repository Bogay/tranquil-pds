use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;
use std::sync::Arc;

use fjall::{Database, Keyspace};
use smallvec::SmallVec;
use uuid::Uuid;

use super::MetastoreError;
use super::blobs::{BlobMetaValue, blob_by_cid_key, blob_meta_key, blob_user_prefix, blobs_prefix};
use super::commit_ops::{RecordBlobsValue, record_blobs_user_prefix};
use super::encoding::{KeyReader, exclusive_upper_bound};
use super::keys::{KeyTag, UserHash};
use super::repo_ops::bytes_to_cid_link;
use super::scan::{count_prefix, point_lookup};
use super::user_hash::UserHashMap;
use tranquil_types::CidLink;

const DELETE_BATCH_SIZE: usize = 1024;

pub struct BlobOps {
    db: Database,
    repo_data: Keyspace,
    user_hashes: Arc<UserHashMap>,
}

impl BlobOps {
    pub fn new(db: Database, repo_data: Keyspace, user_hashes: Arc<UserHashMap>) -> Self {
        Self {
            db,
            repo_data,
            user_hashes,
        }
    }

    fn resolve_user_hash(&self, user_id: Uuid) -> Result<UserHash, MetastoreError> {
        self.user_hashes
            .get(&user_id)
            .ok_or(MetastoreError::InvalidInput("unknown user_id"))
    }

    pub fn insert_blob(
        &self,
        cid: &CidLink,
        mime_type: &str,
        size_bytes: i64,
        created_by_user: Uuid,
        storage_key: &str,
    ) -> Result<Option<CidLink>, MetastoreError> {
        if size_bytes < 0 {
            return Err(MetastoreError::InvalidInput(
                "size_bytes must be non-negative",
            ));
        }

        let user_hash = self.resolve_user_hash(created_by_user)?;
        let cid_str = cid.as_str();

        let cid_index_key = blob_by_cid_key(cid_str);
        let existing = self
            .repo_data
            .get(cid_index_key.as_slice())
            .map_err(MetastoreError::Fjall)?;
        if existing.is_some() {
            return Ok(None);
        }

        let value = BlobMetaValue {
            size_bytes,
            mime_type: mime_type.to_owned(),
            storage_key: storage_key.to_owned(),
            takedown_ref: None,
            created_at_ms: chrono::Utc::now().timestamp_millis(),
        };

        let primary_key = blob_meta_key(user_hash, cid_str);

        let mut batch = self.db.batch();
        batch.insert(&self.repo_data, primary_key.as_slice(), value.serialize());
        batch.insert(
            &self.repo_data,
            cid_index_key.as_slice(),
            user_hash.raw().to_be_bytes(),
        );
        batch.commit().map_err(MetastoreError::Fjall)?;

        Ok(Some(cid.clone()))
    }

    fn lookup_user_hash_by_cid(&self, cid_str: &str) -> Result<Option<UserHash>, MetastoreError> {
        let key = blob_by_cid_key(cid_str);
        match self
            .repo_data
            .get(key.as_slice())
            .map_err(MetastoreError::Fjall)?
        {
            Some(raw) => {
                let arr: [u8; 8] = raw
                    .as_ref()
                    .try_into()
                    .map_err(|_| MetastoreError::CorruptData("blob_by_cid value not 8 bytes"))?;
                Ok(Some(UserHash::from_raw(u64::from_be_bytes(arr))))
            }
            None => Ok(None),
        }
    }

    fn get_blob_value(&self, cid: &CidLink) -> Result<Option<BlobMetaValue>, MetastoreError> {
        let cid_str = cid.as_str();
        let user_hash = match self.lookup_user_hash_by_cid(cid_str)? {
            Some(h) => h,
            None => return Ok(None),
        };
        let key = blob_meta_key(user_hash, cid_str);
        point_lookup(
            &self.repo_data,
            key.as_slice(),
            BlobMetaValue::deserialize,
            "corrupt blob_meta value",
        )
    }

    pub fn get_blob_metadata(
        &self,
        cid: &CidLink,
    ) -> Result<Option<tranquil_db_traits::BlobMetadata>, MetastoreError> {
        Ok(self
            .get_blob_value(cid)?
            .map(|v| tranquil_db_traits::BlobMetadata {
                storage_key: v.storage_key,
                mime_type: v.mime_type,
                size_bytes: v.size_bytes,
            }))
    }

    pub fn get_blob_with_takedown(
        &self,
        cid: &CidLink,
    ) -> Result<Option<tranquil_db_traits::BlobWithTakedown>, MetastoreError> {
        Ok(self
            .get_blob_value(cid)?
            .map(|v| tranquil_db_traits::BlobWithTakedown {
                cid: cid.clone(),
                takedown_ref: v.takedown_ref,
            }))
    }

    pub fn get_blob_storage_key(&self, cid: &CidLink) -> Result<Option<String>, MetastoreError> {
        Ok(self.get_blob_value(cid)?.map(|v| v.storage_key))
    }

    pub fn list_blobs_by_user(
        &self,
        user_id: Uuid,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Vec<CidLink>, MetastoreError> {
        let user_hash = self.resolve_user_hash(user_id)?;
        let prefix = blob_user_prefix(user_hash);
        let upper = exclusive_upper_bound(prefix.as_slice())
            .expect("blob user prefix always contains non-0xFF bytes");

        let range_start: SmallVec<[u8; 128]> = match cursor {
            Some(c) => {
                let mut cursor_key = blob_meta_key(user_hash, c);
                cursor_key.push(0x00);
                cursor_key
            }
            None => prefix,
        };

        self.repo_data
            .range(range_start.as_slice()..upper.as_slice())
            .map(|guard| {
                let (key_bytes, _) = guard.into_inner().map_err(MetastoreError::Fjall)?;
                parse_blob_cid_from_key(key_bytes.as_ref())
            })
            .take(limit)
            .collect()
    }

    pub fn count_blobs_by_user(&self, user_id: Uuid) -> Result<i64, MetastoreError> {
        let user_hash = self.resolve_user_hash(user_id)?;
        let prefix = blob_user_prefix(user_hash);
        count_prefix(&self.repo_data, prefix.as_slice())
    }

    pub fn sum_blob_storage(&self) -> Result<i64, MetastoreError> {
        let prefix = blobs_prefix();
        self.repo_data
            .prefix(prefix.as_slice())
            .try_fold(0i64, |acc, guard| {
                let (_, val_bytes) = guard.into_inner().map_err(MetastoreError::Fjall)?;
                let value = BlobMetaValue::deserialize(&val_bytes)
                    .ok_or(MetastoreError::CorruptData("corrupt blob_meta in sum"))?;
                Ok::<_, MetastoreError>(acc.saturating_add(value.size_bytes))
            })
    }

    pub fn update_blob_takedown(
        &self,
        cid: &CidLink,
        takedown_ref: Option<&str>,
    ) -> Result<bool, MetastoreError> {
        let cid_str = cid.as_str();
        let user_hash = match self.lookup_user_hash_by_cid(cid_str)? {
            Some(h) => h,
            None => return Ok(false),
        };
        let key = blob_meta_key(user_hash, cid_str);
        let mut value = match point_lookup(
            &self.repo_data,
            key.as_slice(),
            BlobMetaValue::deserialize,
            "corrupt blob_meta value",
        )? {
            Some(v) => v,
            None => return Ok(false),
        };

        value.takedown_ref = takedown_ref.map(str::to_owned);
        let mut batch = self.db.batch();
        batch.insert(&self.repo_data, key.as_slice(), value.serialize());
        batch.commit().map_err(MetastoreError::Fjall)?;
        Ok(true)
    }

    pub fn delete_blob_by_cid(&self, cid: &CidLink) -> Result<bool, MetastoreError> {
        let cid_str = cid.as_str();
        let user_hash = match self.lookup_user_hash_by_cid(cid_str)? {
            Some(h) => h,
            None => return Ok(false),
        };

        let primary_key = blob_meta_key(user_hash, cid_str);
        let exists = self
            .repo_data
            .get(primary_key.as_slice())
            .map_err(MetastoreError::Fjall)?
            .is_some();
        if !exists {
            return Ok(false);
        }

        let cid_index_key = blob_by_cid_key(cid_str);

        let mut batch = self.db.batch();
        batch.remove(&self.repo_data, primary_key.as_slice());
        batch.remove(&self.repo_data, cid_index_key.as_slice());
        batch.commit().map_err(MetastoreError::Fjall)?;

        Ok(true)
    }

    pub fn delete_blobs_by_user(&self, user_id: Uuid) -> Result<u64, MetastoreError> {
        let user_hash = self.resolve_user_hash(user_id)?;
        let prefix = blob_user_prefix(user_hash);
        let user_hash_bytes = user_hash.raw().to_be_bytes();

        let (final_batch, remaining, total) = self
            .repo_data
            .prefix(prefix.as_slice())
            .map(|guard| {
                let (key_bytes, _) = guard.into_inner().map_err(MetastoreError::Fjall)?;
                parse_blob_cid_from_key(key_bytes.as_ref()).map(|c| c.as_str().to_owned())
            })
            .try_fold(
                (self.db.batch(), 0usize, 0u64),
                |(mut batch, count, total), entry: Result<_, MetastoreError>| {
                    let cid_str = entry?;
                    batch.remove(
                        &self.repo_data,
                        blob_meta_key(user_hash, &cid_str).as_slice(),
                    );
                    let cid_index_key = blob_by_cid_key(&cid_str);
                    let owns_cid = self
                        .repo_data
                        .get(cid_index_key.as_slice())
                        .map_err(MetastoreError::Fjall)?
                        .is_some_and(|raw| raw.as_ref() == user_hash_bytes);
                    if owns_cid {
                        batch.remove(&self.repo_data, cid_index_key.as_slice());
                    }
                    let new_count = count + 1;
                    if new_count >= DELETE_BATCH_SIZE {
                        batch.commit().map_err(MetastoreError::Fjall)?;
                        let flushed = u64::try_from(new_count).unwrap_or(u64::MAX);
                        Ok::<_, MetastoreError>((self.db.batch(), 0, total.saturating_add(flushed)))
                    } else {
                        Ok((batch, new_count, total))
                    }
                },
            )?;

        if remaining > 0 {
            final_batch.commit().map_err(MetastoreError::Fjall)?;
            let flushed = u64::try_from(remaining).unwrap_or(u64::MAX);
            Ok(total.saturating_add(flushed))
        } else {
            Ok(total)
        }
    }

    pub fn get_blob_storage_keys_by_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<String>, MetastoreError> {
        let user_hash = self.resolve_user_hash(user_id)?;
        let prefix = blob_user_prefix(user_hash);

        self.repo_data
            .prefix(prefix.as_slice())
            .map(|guard| {
                let (_, val_bytes) = guard.into_inner().map_err(MetastoreError::Fjall)?;
                let value = BlobMetaValue::deserialize(&val_bytes)
                    .ok_or(MetastoreError::CorruptData("corrupt blob_meta value"))?;
                Ok(value.storage_key)
            })
            .collect()
    }

    pub fn list_missing_blobs(
        &self,
        repo_id: Uuid,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Vec<tranquil_db_traits::MissingBlobInfo>, MetastoreError> {
        let user_hash = self.resolve_user_hash(repo_id)?;
        let rb_prefix = record_blobs_user_prefix(user_hash);

        let missing: BTreeMap<String, String> = self
            .repo_data
            .prefix(rb_prefix.as_slice())
            .try_fold(BTreeMap::new(), |mut acc, guard| {
                let (key_bytes, val_bytes) = guard.into_inner().map_err(MetastoreError::Fjall)?;
                let record_uri = parse_record_blobs_uri(&key_bytes)
                    .ok_or(MetastoreError::CorruptData("corrupt record_blobs key"))?;
                let blob_cid_bytes = RecordBlobsValue::deserialize(&val_bytes)
                    .map(|v| v.blob_cid_bytes)
                    .ok_or(MetastoreError::CorruptData("corrupt record_blobs value"))?;

                blob_cid_bytes.into_iter().try_for_each(
                    |cid_bytes| -> Result<(), MetastoreError> {
                        let cid_link = bytes_to_cid_link(&cid_bytes)?;
                        let cid_str = cid_link.as_str().to_owned();
                        if acc.contains_key(&cid_str) {
                            return Ok(());
                        }
                        let key = blob_meta_key(user_hash, &cid_str);
                        let exists = self
                            .repo_data
                            .get(key.as_slice())
                            .map_err(MetastoreError::Fjall)?
                            .is_some();
                        if !exists {
                            acc.insert(cid_str, record_uri.clone());
                        }
                        Ok(())
                    },
                )?;

                Ok::<_, MetastoreError>(acc)
            })?;

        let start = cursor.map_or(Bound::Unbounded, Bound::Excluded);
        Ok(missing
            .range::<str, _>((start, Bound::Unbounded))
            .take(limit)
            .map(|(cid_str, uri)| tranquil_db_traits::MissingBlobInfo {
                blob_cid: CidLink::from(cid_str.clone()),
                record_uri: tranquil_types::AtUri::from(uri.clone()),
            })
            .collect())
    }

    fn collect_referenced_cid_bytes(
        &self,
        user_hash: UserHash,
    ) -> Result<BTreeSet<Vec<u8>>, MetastoreError> {
        let rb_prefix = record_blobs_user_prefix(user_hash);
        self.repo_data
            .prefix(rb_prefix.as_slice())
            .try_fold(BTreeSet::new(), |mut acc, guard| {
                let (_, val_bytes) = guard.into_inner().map_err(MetastoreError::Fjall)?;
                let blob_cids = RecordBlobsValue::deserialize(&val_bytes)
                    .map(|v| v.blob_cid_bytes)
                    .ok_or(MetastoreError::CorruptData("corrupt record_blobs value"))?;
                acc.extend(blob_cids);
                Ok::<_, MetastoreError>(acc)
            })
    }

    pub fn count_distinct_record_blobs(&self, repo_id: Uuid) -> Result<i64, MetastoreError> {
        let user_hash = self.resolve_user_hash(repo_id)?;
        let distinct = self.collect_referenced_cid_bytes(user_hash)?;
        Ok(i64::try_from(distinct.len()).unwrap_or(i64::MAX))
    }

    pub fn get_blobs_for_export(
        &self,
        repo_id: Uuid,
    ) -> Result<Vec<tranquil_db_traits::BlobForExport>, MetastoreError> {
        let user_hash = self.resolve_user_hash(repo_id)?;
        let referenced_cids = self.collect_referenced_cid_bytes(user_hash)?;

        referenced_cids
            .into_iter()
            .filter_map(|cid_bytes| {
                let cid_link = match bytes_to_cid_link(&cid_bytes) {
                    Ok(c) => c,
                    Err(e) => return Some(Err(e)),
                };
                let key = blob_meta_key(user_hash, cid_link.as_str());
                match point_lookup(
                    &self.repo_data,
                    key.as_slice(),
                    BlobMetaValue::deserialize,
                    "corrupt blob_meta value",
                ) {
                    Ok(Some(v)) => Some(Ok(tranquil_db_traits::BlobForExport {
                        cid: cid_link,
                        storage_key: v.storage_key,
                        mime_type: v.mime_type,
                    })),
                    Ok(None) => None,
                    Err(e) => Some(Err(e)),
                }
            })
            .collect()
    }
}

fn parse_blob_cid_from_key(key: &[u8]) -> Result<CidLink, MetastoreError> {
    let mut reader = KeyReader::new(key);
    let tag = reader
        .tag()
        .ok_or(MetastoreError::CorruptData("corrupt blob key: missing tag"))?;
    if tag != KeyTag::BLOBS.raw() {
        return Err(MetastoreError::CorruptData(
            "corrupt blob key: unexpected tag",
        ));
    }
    reader.u64().ok_or(MetastoreError::CorruptData(
        "corrupt blob key: missing user_hash",
    ))?;
    reader
        .string()
        .map(CidLink::from)
        .ok_or(MetastoreError::CorruptData("corrupt blob key: missing cid"))
}

fn parse_record_blobs_uri(key: &[u8]) -> Option<String> {
    let mut reader = KeyReader::new(key);
    let tag = reader.tag()?;
    if tag != KeyTag::RECORD_BLOBS.raw() {
        return None;
    }
    reader.u64()?;
    reader.string()
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
        let user_id = Uuid::new_v4();
        let did = format!("did:plc:blob_test_{}", user_id);
        let user_hash = UserHash::from_did(&did);
        let mut batch = ms.database().batch();
        ms.user_hashes()
            .stage_insert(&mut batch, user_id, user_hash)
            .unwrap();
        batch.commit().unwrap();
        (user_id, user_hash)
    }

    fn test_cid_link(seed: u8) -> CidLink {
        let digest: [u8; 32] = std::array::from_fn(|i| seed.wrapping_add(i as u8));
        let mh = multihash::Multihash::<64>::wrap(0x12, &digest).unwrap();
        let c = cid::Cid::new_v1(0x71, mh);
        CidLink::from_cid(&c)
    }

    #[test]
    fn insert_and_get_metadata_roundtrip() {
        let (_dir, ms) = open_fresh();
        let (user_id, _) = setup_user(&ms);
        let ops = ms.blob_ops();

        let cid = test_cid_link(1);
        let result = ops
            .insert_blob(&cid, "image/png", 1024, user_id, "blobs/a/b")
            .unwrap();
        assert_eq!(result, Some(cid.clone()));

        let meta = ops.get_blob_metadata(&cid).unwrap().unwrap();
        assert_eq!(meta.storage_key, "blobs/a/b");
        assert_eq!(meta.mime_type, "image/png");
        assert_eq!(meta.size_bytes, 1024);
    }

    #[test]
    fn insert_duplicate_returns_none() {
        let (_dir, ms) = open_fresh();
        let (user_id, _) = setup_user(&ms);
        let ops = ms.blob_ops();

        let cid = test_cid_link(2);
        assert!(
            ops.insert_blob(&cid, "image/png", 100, user_id, "k1")
                .unwrap()
                .is_some()
        );
        assert!(
            ops.insert_blob(&cid, "image/png", 100, user_id, "k1")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn insert_same_cid_different_user_returns_none() {
        let (_dir, ms) = open_fresh();
        let (user_a, _) = setup_user(&ms);
        let (user_b, _) = setup_user(&ms);
        let ops = ms.blob_ops();

        let cid = test_cid_link(80);
        assert!(
            ops.insert_blob(&cid, "image/png", 100, user_a, "ka")
                .unwrap()
                .is_some()
        );
        assert!(
            ops.insert_blob(&cid, "image/png", 100, user_b, "kb")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn get_blob_with_takedown_no_takedown() {
        let (_dir, ms) = open_fresh();
        let (user_id, _) = setup_user(&ms);
        let ops = ms.blob_ops();

        let cid = test_cid_link(3);
        ops.insert_blob(&cid, "text/plain", 10, user_id, "k")
            .unwrap();

        let result = ops.get_blob_with_takedown(&cid).unwrap().unwrap();
        assert_eq!(result.cid, cid);
        assert!(result.takedown_ref.is_none());
    }

    #[test]
    fn update_takedown_and_read_back() {
        let (_dir, ms) = open_fresh();
        let (user_id, _) = setup_user(&ms);
        let ops = ms.blob_ops();

        let cid = test_cid_link(4);
        ops.insert_blob(&cid, "text/plain", 10, user_id, "k")
            .unwrap();

        assert!(ops.update_blob_takedown(&cid, Some("mod-42")).unwrap());
        let result = ops.get_blob_with_takedown(&cid).unwrap().unwrap();
        assert_eq!(result.takedown_ref.as_deref(), Some("mod-42"));

        assert!(ops.update_blob_takedown(&cid, None).unwrap());
        let result = ops.get_blob_with_takedown(&cid).unwrap().unwrap();
        assert!(result.takedown_ref.is_none());
    }

    #[test]
    fn update_takedown_nonexistent_returns_false() {
        let (_dir, ms) = open_fresh();
        let ops = ms.blob_ops();
        let cid = test_cid_link(99);
        assert!(!ops.update_blob_takedown(&cid, Some("x")).unwrap());
    }

    #[test]
    fn get_blob_storage_key() {
        let (_dir, ms) = open_fresh();
        let (user_id, _) = setup_user(&ms);
        let ops = ms.blob_ops();

        let cid = test_cid_link(5);
        ops.insert_blob(&cid, "image/jpeg", 500, user_id, "blobs/x/y")
            .unwrap();

        assert_eq!(
            ops.get_blob_storage_key(&cid).unwrap().as_deref(),
            Some("blobs/x/y")
        );
    }

    #[test]
    fn list_blobs_by_user_with_pagination() {
        let (_dir, ms) = open_fresh();
        let (user_id, _) = setup_user(&ms);
        let ops = ms.blob_ops();

        let cids: Vec<CidLink> = (0..5).map(|i| test_cid_link(10 + i)).collect();
        cids.iter().enumerate().for_each(|(i, cid)| {
            ops.insert_blob(cid, "image/png", i as i64, user_id, &format!("k{i}"))
                .unwrap();
        });

        let page1 = ops.list_blobs_by_user(user_id, None, 3).unwrap();
        assert_eq!(page1.len(), 3);

        let cursor = page1.last().unwrap().as_str();
        let page2 = ops.list_blobs_by_user(user_id, Some(cursor), 3).unwrap();
        assert_eq!(page2.len(), 2);

        let all = ops.list_blobs_by_user(user_id, None, 100).unwrap();
        assert_eq!(all.len(), 5);
    }

    #[test]
    fn count_blobs_by_user() {
        let (_dir, ms) = open_fresh();
        let (user_id, _) = setup_user(&ms);
        let ops = ms.blob_ops();

        assert_eq!(ops.count_blobs_by_user(user_id).unwrap(), 0);

        (0..3).for_each(|i| {
            ops.insert_blob(
                &test_cid_link(20 + i),
                "image/png",
                100,
                user_id,
                &format!("k{i}"),
            )
            .unwrap();
        });

        assert_eq!(ops.count_blobs_by_user(user_id).unwrap(), 3);
    }

    #[test]
    fn sum_blob_storage() {
        let (_dir, ms) = open_fresh();
        let (user_id, _) = setup_user(&ms);
        let ops = ms.blob_ops();

        assert_eq!(ops.sum_blob_storage().unwrap(), 0);

        ops.insert_blob(&test_cid_link(30), "a/b", 100, user_id, "k0")
            .unwrap();
        ops.insert_blob(&test_cid_link(31), "a/b", 250, user_id, "k1")
            .unwrap();

        assert_eq!(ops.sum_blob_storage().unwrap(), 350);
    }

    #[test]
    fn delete_blob_by_cid() {
        let (_dir, ms) = open_fresh();
        let (user_id, _) = setup_user(&ms);
        let ops = ms.blob_ops();

        let cid = test_cid_link(40);
        ops.insert_blob(&cid, "image/png", 100, user_id, "k")
            .unwrap();

        assert!(ops.delete_blob_by_cid(&cid).unwrap());
        assert!(ops.get_blob_metadata(&cid).unwrap().is_none());
        assert!(!ops.delete_blob_by_cid(&cid).unwrap());
    }

    #[test]
    fn delete_blob_cleans_up_indexes() {
        let (_dir, ms) = open_fresh();
        let (user_id, _) = setup_user(&ms);
        let ops = ms.blob_ops();

        let cid = test_cid_link(41);
        ops.insert_blob(&cid, "image/png", 100, user_id, "storage/abc")
            .unwrap();
        assert!(ops.get_blob_storage_key(&cid).unwrap().is_some());

        ops.delete_blob_by_cid(&cid).unwrap();

        assert!(ops.lookup_user_hash_by_cid(cid.as_str()).unwrap().is_none());
    }

    #[test]
    fn delete_blobs_by_user() {
        let (_dir, ms) = open_fresh();
        let (user_id, _) = setup_user(&ms);
        let ops = ms.blob_ops();

        (0..4).for_each(|i| {
            ops.insert_blob(&test_cid_link(50 + i), "a/b", 10, user_id, &format!("k{i}"))
                .unwrap();
        });

        let deleted = ops.delete_blobs_by_user(user_id).unwrap();
        assert_eq!(deleted, 4);
        assert_eq!(ops.count_blobs_by_user(user_id).unwrap(), 0);
    }

    #[test]
    fn delete_blobs_by_user_cleans_all_indexes() {
        let (_dir, ms) = open_fresh();
        let (user_id, _) = setup_user(&ms);
        let ops = ms.blob_ops();

        let cid = test_cid_link(81);
        ops.insert_blob(&cid, "a/b", 10, user_id, "storage/del_test")
            .unwrap();

        ops.delete_blobs_by_user(user_id).unwrap();

        assert!(ops.lookup_user_hash_by_cid(cid.as_str()).unwrap().is_none());
    }

    #[test]
    fn insert_blob_rejects_negative_size() {
        let (_dir, ms) = open_fresh();
        let (user_id, _) = setup_user(&ms);
        let ops = ms.blob_ops();

        let result = ops.insert_blob(&test_cid_link(90), "a/b", -1, user_id, "k");
        assert!(result.is_err());
    }

    #[test]
    fn get_blob_storage_keys_by_user() {
        let (_dir, ms) = open_fresh();
        let (user_id, _) = setup_user(&ms);
        let ops = ms.blob_ops();

        ops.insert_blob(&test_cid_link(60), "a/b", 10, user_id, "alpha")
            .unwrap();
        ops.insert_blob(&test_cid_link(61), "a/b", 10, user_id, "beta")
            .unwrap();

        let mut keys = ops.get_blob_storage_keys_by_user(user_id).unwrap();
        keys.sort();
        assert_eq!(keys, vec!["alpha", "beta"]);
    }

    #[test]
    fn get_metadata_for_nonexistent_returns_none() {
        let (_dir, ms) = open_fresh();
        let ops = ms.blob_ops();
        assert!(ops.get_blob_metadata(&test_cid_link(99)).unwrap().is_none());
    }

    #[test]
    fn blobs_isolated_between_users() {
        let (_dir, ms) = open_fresh();
        let (user_a, _) = setup_user(&ms);
        let (user_b, _) = setup_user(&ms);
        let ops = ms.blob_ops();

        ops.insert_blob(&test_cid_link(70), "a/b", 10, user_a, "ka")
            .unwrap();
        ops.insert_blob(&test_cid_link(71), "a/b", 20, user_b, "kb")
            .unwrap();

        assert_eq!(ops.count_blobs_by_user(user_a).unwrap(), 1);
        assert_eq!(ops.count_blobs_by_user(user_b).unwrap(), 1);
        assert_eq!(ops.sum_blob_storage().unwrap(), 30);
    }
}
