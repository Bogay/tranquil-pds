use std::sync::Arc;

use fjall::Keyspace;
use smallvec::SmallVec;
use uuid::Uuid;

use super::MetastoreError;
use super::encoding::{KeyReader, exclusive_upper_bound};
use super::keys::UserHash;
use super::records::{
    RecordValue, record_collection_prefix, record_key, record_user_prefix, records_prefix,
};
use super::repo_ops::{bytes_to_cid_link, cid_link_to_bytes};
use super::scan::{count_prefix, delete_all_by_prefix, point_lookup};
use super::user_hash::UserHashMap;

use tranquil_types::{CidLink, Nsid, Rkey};

pub struct RecordWrite<'a> {
    pub collection: &'a Nsid,
    pub rkey: &'a Rkey,
    pub cid: &'a CidLink,
}

pub struct RecordDelete<'a> {
    pub collection: &'a Nsid,
    pub rkey: &'a Rkey,
}

pub struct ListRecordsQuery<'a> {
    pub user_id: Uuid,
    pub collection: &'a Nsid,
    pub cursor: Option<&'a Rkey>,
    pub limit: usize,
    pub reverse: bool,
    pub rkey_start: Option<&'a Rkey>,
    pub rkey_end: Option<&'a Rkey>,
}

#[derive(Debug, Clone)]
pub struct RecordInfo {
    pub rkey: Rkey,
    pub record_cid: CidLink,
}

#[derive(Debug, Clone)]
pub struct FullRecordInfo {
    pub collection: Nsid,
    pub rkey: Rkey,
    pub record_cid: CidLink,
}

#[derive(Debug, Clone)]
pub struct RecordWithTakedown {
    pub id: Uuid,
    pub collection: Nsid,
    pub rkey: Rkey,
    pub takedown_ref: Option<String>,
}

pub struct RecordOps {
    repo_data: Keyspace,
    user_hashes: Arc<UserHashMap>,
}

impl RecordOps {
    pub fn new(repo_data: Keyspace, user_hashes: Arc<UserHashMap>) -> Self {
        Self {
            repo_data,
            user_hashes,
        }
    }

    pub fn upsert_records(
        &self,
        batch: &mut fjall::OwnedWriteBatch,
        user_hash: UserHash,
        records: &[RecordWrite<'_>],
    ) -> Result<(), MetastoreError> {
        records.iter().try_for_each(|rec| {
            let key = record_key(user_hash, rec.collection.as_str(), rec.rkey.as_str());
            let cid_bytes = cid_link_to_bytes(rec.cid)?;
            let existing_takedown = self
                .repo_data
                .get(key.as_slice())
                .map_err(MetastoreError::Fjall)?
                .and_then(|raw| RecordValue::deserialize(&raw))
                .and_then(|v| v.takedown_ref);
            let value = RecordValue {
                record_cid: cid_bytes,
                takedown_ref: existing_takedown,
            };
            batch.insert(&self.repo_data, key.as_slice(), value.serialize());
            Ok::<(), MetastoreError>(())
        })
    }

    pub fn delete_records(
        &self,
        batch: &mut fjall::OwnedWriteBatch,
        user_hash: UserHash,
        records: &[RecordDelete<'_>],
    ) {
        records.iter().for_each(|rec| {
            let key = record_key(user_hash, rec.collection.as_str(), rec.rkey.as_str());
            batch.remove(&self.repo_data, key.as_slice());
        });
    }

    pub fn delete_all_records(
        &self,
        batch: &mut fjall::OwnedWriteBatch,
        user_hash: UserHash,
    ) -> Result<(), MetastoreError> {
        let prefix = record_user_prefix(user_hash);
        delete_all_by_prefix(&self.repo_data, batch, prefix.as_slice())
    }

    pub fn get_record_cid(
        &self,
        user_id: Uuid,
        collection: &Nsid,
        rkey: &Rkey,
    ) -> Result<Option<CidLink>, MetastoreError> {
        let user_hash = match self.user_hashes.get(&user_id) {
            Some(h) => h,
            None => return Ok(None),
        };
        let key = record_key(user_hash, collection.as_str(), rkey.as_str());

        point_lookup(
            &self.repo_data,
            key.as_slice(),
            RecordValue::deserialize,
            "invalid record value",
        )?
        .map(|v| bytes_to_cid_link(&v.record_cid))
        .transpose()
    }

    pub fn list_records(
        &self,
        query: &ListRecordsQuery<'_>,
    ) -> Result<Vec<RecordInfo>, MetastoreError> {
        let user_hash = match self.user_hashes.get(&query.user_id) {
            Some(h) => h,
            None => return Ok(Vec::new()),
        };

        let coll_str = query.collection.as_str();
        let coll_prefix = record_collection_prefix(user_hash, coll_str);
        let coll_upper = exclusive_upper_bound(coll_prefix.as_slice())
            .expect("collection prefix always contains non-0xFF bytes");

        let start_key = query
            .rkey_start
            .map(|rs| record_key(user_hash, coll_str, rs.as_str()));
        let end_key_upper = query
            .rkey_end
            .map(|re| record_key(user_hash, coll_str, re.as_str()))
            .map(|ek| {
                exclusive_upper_bound(ek.as_slice())
                    .expect("record key always contains non-0xFF bytes")
            });
        let cursor_key = query
            .cursor
            .map(|c| record_key(user_hash, coll_str, c.as_str()));

        let mut range_lo: &[u8] = coll_prefix.as_slice();
        let mut range_hi: &[u8] = coll_upper.as_slice();

        if let Some(sk) = start_key.as_ref().filter(|sk| sk.as_slice() > range_lo) {
            range_lo = sk.as_slice();
        }

        if let Some(eu) = end_key_upper.as_ref().filter(|eu| eu.as_slice() < range_hi) {
            range_hi = eu.as_slice();
        }

        let effective_cursor = match query.reverse {
            false => {
                if let Some(ck) = cursor_key.as_ref().filter(|ck| ck.as_slice() < range_hi) {
                    range_hi = ck.as_slice();
                }
                None
            }
            true => {
                let narrowed = cursor_key.as_ref().filter(|ck| ck.as_slice() > range_lo);
                match narrowed {
                    Some(ck) => {
                        range_lo = ck.as_slice();
                        Some(ck.as_slice())
                    }
                    None => None,
                }
            }
        };

        match range_lo >= range_hi {
            true => Ok(Vec::new()),
            false => match query.reverse {
                false => self.list_records_reverse(range_lo, range_hi, query.limit),
                true => {
                    self.list_records_forward(range_lo, range_hi, effective_cursor, query.limit)
                }
            },
        }
    }

    fn list_records_forward(
        &self,
        range_start: &[u8],
        range_end: &[u8],
        cursor_key: Option<&[u8]>,
        limit: usize,
    ) -> Result<Vec<RecordInfo>, MetastoreError> {
        self.repo_data
            .range(range_start..range_end)
            .filter_map(|guard| {
                let (key_bytes, val_bytes) = match guard.into_inner() {
                    Ok(pair) => pair,
                    Err(e) => return Some(Err(MetastoreError::Fjall(e))),
                };

                match cursor_key {
                    Some(ck) if key_bytes.as_ref() <= ck => None,
                    _ => Some(decode_record_info(&key_bytes, &val_bytes)),
                }
            })
            .take(limit)
            .collect()
    }

    fn list_records_reverse(
        &self,
        range_start: &[u8],
        range_end: &[u8],
        limit: usize,
    ) -> Result<Vec<RecordInfo>, MetastoreError> {
        self.repo_data
            .range(range_start..range_end)
            .rev()
            .map(|guard| {
                let (key_bytes, val_bytes) = guard.into_inner().map_err(MetastoreError::Fjall)?;
                decode_record_info(&key_bytes, &val_bytes)
            })
            .take(limit)
            .collect()
    }

    pub fn get_all_records(&self, user_id: Uuid) -> Result<Vec<FullRecordInfo>, MetastoreError> {
        let user_hash = match self.user_hashes.get(&user_id) {
            Some(h) => h,
            None => return Ok(Vec::new()),
        };
        let prefix = record_user_prefix(user_hash);

        self.repo_data
            .prefix(prefix.as_slice())
            .map(|guard| {
                let (key_bytes, val_bytes) = guard.into_inner().map_err(MetastoreError::Fjall)?;
                decode_full_record_info(&key_bytes, &val_bytes)
            })
            .collect()
    }

    pub fn list_collections(&self, user_id: Uuid) -> Result<Vec<Nsid>, MetastoreError> {
        let user_hash = match self.user_hashes.get(&user_id) {
            Some(h) => h,
            None => return Ok(Vec::new()),
        };
        let user_pfx = record_user_prefix(user_hash);
        let user_upper = exclusive_upper_bound(user_pfx.as_slice())
            .expect("user prefix always contains non-0xFF bytes");

        let mut collections: Vec<Nsid> = Vec::new();
        let mut seek_from: SmallVec<[u8; 128]> = user_pfx.clone();

        loop {
            let entry = self
                .repo_data
                .range(seek_from.as_slice()..user_upper.as_slice())
                .next();
            let guard = match entry {
                Some(g) => g,
                None => break,
            };
            let (key_bytes, _) = guard.into_inner().map_err(MetastoreError::Fjall)?;
            let collection = parse_record_key_collection(&key_bytes)
                .ok_or(MetastoreError::CorruptData("invalid record key"))?;
            let coll_prefix = record_collection_prefix(user_hash, &collection);
            seek_from = exclusive_upper_bound(coll_prefix.as_slice())
                .expect("collection prefix always contains non-0xFF bytes");
            collections.push(Nsid::from(collection));
        }

        Ok(collections)
    }

    pub fn count_records(&self, user_id: Uuid) -> Result<i64, MetastoreError> {
        let user_hash = match self.user_hashes.get(&user_id) {
            Some(h) => h,
            None => return Ok(0),
        };
        let prefix = record_user_prefix(user_hash);
        count_prefix(&self.repo_data, prefix.as_slice())
    }

    pub fn count_all_records(&self) -> Result<i64, MetastoreError> {
        let prefix = records_prefix();
        count_prefix(&self.repo_data, prefix.as_slice())
    }

    pub fn get_record_by_cid(
        &self,
        cid: &CidLink,
        scope_user: Option<Uuid>,
    ) -> Result<Option<RecordWithTakedown>, MetastoreError> {
        let target_bytes = cid_link_to_bytes(cid)?;
        let prefix = match scope_user {
            Some(uid) => match self.user_hashes.get(&uid) {
                Some(hash) => record_user_prefix(hash),
                None => return Ok(None),
            },
            None => records_prefix(),
        };

        self.repo_data
            .prefix(prefix.as_slice())
            .find_map(|guard| {
                let (key_bytes, val_bytes) = match guard.into_inner() {
                    Ok(pair) => pair,
                    Err(e) => return Some(Err(MetastoreError::Fjall(e))),
                };
                let value = match RecordValue::deserialize(&val_bytes) {
                    Some(v) => v,
                    None => return Some(Err(MetastoreError::CorruptData("invalid record value"))),
                };

                match value.record_cid == target_bytes {
                    true => {
                        let (coll_str, rkey_str) = match parse_record_key_fields(&key_bytes) {
                            Some(pair) => pair,
                            None => {
                                return Some(Err(MetastoreError::CorruptData(
                                    "invalid record key",
                                )));
                            }
                        };
                        let user_hash = match parse_record_key_user_hash(&key_bytes) {
                            Some(h) => h,
                            None => {
                                return Some(Err(MetastoreError::CorruptData(
                                    "invalid record key",
                                )));
                            }
                        };
                        let user_id = match self.user_hashes.get_uuid(&user_hash) {
                            Some(id) => id,
                            None => {
                                return Some(Err(MetastoreError::CorruptData(
                                    "record user_hash has no reverse mapping",
                                )));
                            }
                        };
                        Some(Ok(RecordWithTakedown {
                            id: user_id,
                            collection: Nsid::from(coll_str),
                            rkey: Rkey::from(rkey_str),
                            takedown_ref: value.takedown_ref,
                        }))
                    }
                    false => None,
                }
            })
            .transpose()
    }

    pub fn set_record_takedown(
        &self,
        db: &fjall::Database,
        cid: &CidLink,
        takedown_ref: Option<&str>,
        scope_user: Option<Uuid>,
    ) -> Result<(), MetastoreError> {
        let target_bytes = cid_link_to_bytes(cid)?;
        let prefix = match scope_user {
            Some(uid) => match self.user_hashes.get(&uid) {
                Some(hash) => record_user_prefix(hash),
                None => return Ok(()),
            },
            None => records_prefix(),
        };

        let found = self
            .repo_data
            .prefix(prefix.as_slice())
            .find_map(|guard| {
                let (key_bytes, val_bytes) = match guard.into_inner() {
                    Ok(pair) => pair,
                    Err(e) => return Some(Err(MetastoreError::Fjall(e))),
                };
                let value = match RecordValue::deserialize(&val_bytes) {
                    Some(v) => v,
                    None => return Some(Err(MetastoreError::CorruptData("invalid record value"))),
                };
                match value.record_cid == target_bytes {
                    true => Some(Ok((key_bytes.to_vec(), value))),
                    false => None,
                }
            })
            .transpose()?;

        match found {
            Some((key, mut value)) => {
                value.takedown_ref = takedown_ref.map(str::to_string);
                let mut batch = db.batch();
                batch.insert(&self.repo_data, &key, value.serialize());
                batch.commit().map_err(MetastoreError::Fjall)
            }
            None => Ok(()),
        }
    }
}

fn decode_record_info(key_bytes: &[u8], val_bytes: &[u8]) -> Result<RecordInfo, MetastoreError> {
    let value = RecordValue::deserialize(val_bytes)
        .ok_or(MetastoreError::CorruptData("invalid record value"))?;
    let (_collection, rkey) = parse_record_key_fields(key_bytes)
        .ok_or(MetastoreError::CorruptData("invalid record key"))?;
    let cid = bytes_to_cid_link(&value.record_cid)?;
    Ok(RecordInfo {
        rkey: Rkey::from(rkey),
        record_cid: cid,
    })
}

fn decode_full_record_info(
    key_bytes: &[u8],
    val_bytes: &[u8],
) -> Result<FullRecordInfo, MetastoreError> {
    let value = RecordValue::deserialize(val_bytes)
        .ok_or(MetastoreError::CorruptData("invalid record value"))?;
    let (collection, rkey) = parse_record_key_fields(key_bytes)
        .ok_or(MetastoreError::CorruptData("invalid record key"))?;
    let cid = bytes_to_cid_link(&value.record_cid)?;
    Ok(FullRecordInfo {
        collection: Nsid::from(collection),
        rkey: Rkey::from(rkey),
        record_cid: cid,
    })
}

fn parse_record_key_fields(key_bytes: &[u8]) -> Option<(String, String)> {
    let mut reader = KeyReader::new(key_bytes);
    let _tag = reader.tag()?;
    let _user_hash = reader.u64()?;
    let collection = reader.string()?;
    let rkey = reader.string()?;
    Some((collection, rkey))
}

fn parse_record_key_collection(key_bytes: &[u8]) -> Option<String> {
    let mut reader = KeyReader::new(key_bytes);
    let _tag = reader.tag()?;
    let _user_hash = reader.u64()?;
    reader.string()
}

fn parse_record_key_user_hash(key_bytes: &[u8]) -> Option<UserHash> {
    let mut reader = KeyReader::new(key_bytes);
    let _tag = reader.tag()?;
    let hash = reader.u64()?;
    Some(UserHash::from_raw(hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metastore::{Metastore, MetastoreConfig};

    fn test_config() -> MetastoreConfig {
        MetastoreConfig {
            cache_size_bytes: 64 * 1024 * 1024,
        }
    }

    fn test_cid_link(seed: u8) -> CidLink {
        let digest: [u8; 32] = std::array::from_fn(|i| seed.wrapping_add(i as u8));
        let mh = multihash::Multihash::<64>::wrap(0x12, &digest).unwrap();
        let c = cid::Cid::new_v1(0x71, mh);
        CidLink::from_cid(&c)
    }

    fn open_fresh() -> (tempfile::TempDir, Metastore) {
        let dir = tempfile::TempDir::new().unwrap();
        let ms = Metastore::open(dir.path(), test_config()).unwrap();
        (dir, ms)
    }

    fn test_did(name: &str) -> tranquil_types::Did {
        tranquil_types::Did::from(format!("did:plc:{name}"))
    }

    fn test_handle(name: &str) -> tranquil_types::Handle {
        tranquil_types::Handle::from(format!("{name}.test.invalid"))
    }

    fn setup_user(ms: &Metastore) -> (Uuid, super::super::keys::UserHash) {
        let user_id = Uuid::new_v4();
        let did = test_did("testuser");
        let handle = test_handle("testuser");
        let cid = test_cid_link(0);
        ms.repo_ops()
            .create_repo(ms.database(), user_id, &did, &handle, &cid, "rev0")
            .unwrap();
        let user_hash = ms.user_hashes().get(&user_id).unwrap();
        (user_id, user_hash)
    }

    fn rw<'a>(collection: &'a Nsid, rkey: &'a Rkey, cid: &'a CidLink) -> RecordWrite<'a> {
        RecordWrite {
            collection,
            rkey,
            cid,
        }
    }

    fn rd<'a>(collection: &'a Nsid, rkey: &'a Rkey) -> RecordDelete<'a> {
        RecordDelete { collection, rkey }
    }

    fn lrq<'a>(
        user_id: Uuid,
        collection: &'a Nsid,
        cursor: Option<&'a Rkey>,
        limit: usize,
        reverse: bool,
        rkey_start: Option<&'a Rkey>,
        rkey_end: Option<&'a Rkey>,
    ) -> ListRecordsQuery<'a> {
        ListRecordsQuery {
            user_id,
            collection,
            cursor,
            limit,
            reverse,
            rkey_start,
            rkey_end,
        }
    }

    #[test]
    fn upsert_and_get_record() {
        let (_dir, ms) = open_fresh();
        let (user_id, user_hash) = setup_user(&ms);
        let rec_ops = ms.record_ops();

        let collection = Nsid::from("app.bsky.feed.post".to_string());
        let rkey = Rkey::from("3k2abcd".to_string());
        let cid = test_cid_link(1);

        let mut batch = ms.database().batch();
        rec_ops
            .upsert_records(&mut batch, user_hash, &[rw(&collection, &rkey, &cid)])
            .unwrap();
        batch.commit().unwrap();

        let found = rec_ops.get_record_cid(user_id, &collection, &rkey).unwrap();
        assert_eq!(found, Some(cid));
    }

    #[test]
    fn get_record_returns_none_for_missing() {
        let (_dir, ms) = open_fresh();
        let (user_id, _) = setup_user(&ms);
        let rec_ops = ms.record_ops();

        let collection = Nsid::from("app.bsky.feed.post".to_string());
        let rkey = Rkey::from("nonexistent".to_string());
        assert!(
            rec_ops
                .get_record_cid(user_id, &collection, &rkey)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn upsert_overwrites_existing() {
        let (_dir, ms) = open_fresh();
        let (user_id, user_hash) = setup_user(&ms);
        let rec_ops = ms.record_ops();

        let collection = Nsid::from("app.bsky.feed.post".to_string());
        let rkey = Rkey::from("3k2abcd".to_string());
        let cid1 = test_cid_link(1);
        let cid2 = test_cid_link(2);

        let mut batch = ms.database().batch();
        rec_ops
            .upsert_records(&mut batch, user_hash, &[rw(&collection, &rkey, &cid1)])
            .unwrap();
        batch.commit().unwrap();

        let mut batch = ms.database().batch();
        rec_ops
            .upsert_records(&mut batch, user_hash, &[rw(&collection, &rkey, &cid2)])
            .unwrap();
        batch.commit().unwrap();

        let found = rec_ops.get_record_cid(user_id, &collection, &rkey).unwrap();
        assert_eq!(found, Some(cid2));
    }

    #[test]
    fn delete_records_removes_entries() {
        let (_dir, ms) = open_fresh();
        let (user_id, user_hash) = setup_user(&ms);
        let rec_ops = ms.record_ops();

        let collection = Nsid::from("app.bsky.feed.post".to_string());
        let rkey = Rkey::from("3k2abcd".to_string());
        let cid = test_cid_link(1);

        let mut batch = ms.database().batch();
        rec_ops
            .upsert_records(&mut batch, user_hash, &[rw(&collection, &rkey, &cid)])
            .unwrap();
        batch.commit().unwrap();

        let mut batch = ms.database().batch();
        rec_ops.delete_records(&mut batch, user_hash, &[rd(&collection, &rkey)]);
        batch.commit().unwrap();

        assert!(
            rec_ops
                .get_record_cid(user_id, &collection, &rkey)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn delete_all_records_clears_user() {
        let (_dir, ms) = open_fresh();
        let (user_id, user_hash) = setup_user(&ms);
        let rec_ops = ms.record_ops();

        let coll1 = Nsid::from("app.bsky.feed.post".to_string());
        let coll2 = Nsid::from("app.bsky.feed.like".to_string());
        let rkey_a = Rkey::from("a".to_string());
        let rkey_b = Rkey::from("b".to_string());
        let cid1 = test_cid_link(1);
        let cid2 = test_cid_link(2);

        let mut batch = ms.database().batch();
        rec_ops
            .upsert_records(
                &mut batch,
                user_hash,
                &[rw(&coll1, &rkey_a, &cid1), rw(&coll2, &rkey_b, &cid2)],
            )
            .unwrap();
        batch.commit().unwrap();

        assert_eq!(rec_ops.count_records(user_id).unwrap(), 2);

        let mut batch = ms.database().batch();
        rec_ops.delete_all_records(&mut batch, user_hash).unwrap();
        batch.commit().unwrap();

        assert_eq!(rec_ops.count_records(user_id).unwrap(), 0);
    }

    #[test]
    fn list_records_default_desc_with_limit() {
        let (_dir, ms) = open_fresh();
        let (user_id, user_hash) = setup_user(&ms);
        let rec_ops = ms.record_ops();

        let collection = Nsid::from("app.bsky.feed.post".to_string());
        let rkeys: Vec<Rkey> = (0..5).map(|i| Rkey::from(format!("rkey{i:03}"))).collect();
        let cids: Vec<CidLink> = (0..5).map(|i| test_cid_link(i + 1)).collect();

        let writes: Vec<RecordWrite<'_>> = rkeys
            .iter()
            .zip(cids.iter())
            .map(|(rk, c)| rw(&collection, rk, c))
            .collect();

        let mut batch = ms.database().batch();
        rec_ops
            .upsert_records(&mut batch, user_hash, &writes)
            .unwrap();
        batch.commit().unwrap();

        let results = rec_ops
            .list_records(&lrq(user_id, &collection, None, 3, false, None, None))
            .unwrap();
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].rkey.as_str(), "rkey004");
        assert_eq!(results[1].rkey.as_str(), "rkey003");
        assert_eq!(results[2].rkey.as_str(), "rkey002");
    }

    #[test]
    fn list_records_default_desc_with_cursor() {
        let (_dir, ms) = open_fresh();
        let (user_id, user_hash) = setup_user(&ms);
        let rec_ops = ms.record_ops();

        let collection = Nsid::from("app.bsky.feed.post".to_string());
        let rkeys: Vec<Rkey> = (0..5).map(|i| Rkey::from(format!("rkey{i:03}"))).collect();
        let cids: Vec<CidLink> = (0..5).map(|i| test_cid_link(i + 1)).collect();

        let writes: Vec<RecordWrite<'_>> = rkeys
            .iter()
            .zip(cids.iter())
            .map(|(rk, c)| rw(&collection, rk, c))
            .collect();

        let mut batch = ms.database().batch();
        rec_ops
            .upsert_records(&mut batch, user_hash, &writes)
            .unwrap();
        batch.commit().unwrap();

        let cursor = Rkey::from("rkey003".to_string());
        let results = rec_ops
            .list_records(&lrq(
                user_id,
                &collection,
                Some(&cursor),
                10,
                false,
                None,
                None,
            ))
            .unwrap();
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].rkey.as_str(), "rkey002");
        assert_eq!(results[1].rkey.as_str(), "rkey001");
        assert_eq!(results[2].rkey.as_str(), "rkey000");
    }

    #[test]
    fn list_records_reverse_asc() {
        let (_dir, ms) = open_fresh();
        let (user_id, user_hash) = setup_user(&ms);
        let rec_ops = ms.record_ops();

        let collection = Nsid::from("app.bsky.feed.post".to_string());
        let rkeys: Vec<Rkey> = (0..5).map(|i| Rkey::from(format!("rkey{i:03}"))).collect();
        let cids: Vec<CidLink> = (0..5).map(|i| test_cid_link(i + 1)).collect();

        let writes: Vec<RecordWrite<'_>> = rkeys
            .iter()
            .zip(cids.iter())
            .map(|(rk, c)| rw(&collection, rk, c))
            .collect();

        let mut batch = ms.database().batch();
        rec_ops
            .upsert_records(&mut batch, user_hash, &writes)
            .unwrap();
        batch.commit().unwrap();

        let results = rec_ops
            .list_records(&lrq(user_id, &collection, None, 3, true, None, None))
            .unwrap();
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].rkey.as_str(), "rkey000");
        assert_eq!(results[1].rkey.as_str(), "rkey001");
        assert_eq!(results[2].rkey.as_str(), "rkey002");
    }

    #[test]
    fn list_records_reverse_asc_with_cursor() {
        let (_dir, ms) = open_fresh();
        let (user_id, user_hash) = setup_user(&ms);
        let rec_ops = ms.record_ops();

        let collection = Nsid::from("app.bsky.feed.post".to_string());
        let rkeys: Vec<Rkey> = (0..5).map(|i| Rkey::from(format!("rkey{i:03}"))).collect();
        let cids: Vec<CidLink> = (0..5).map(|i| test_cid_link(i + 1)).collect();

        let writes: Vec<RecordWrite<'_>> = rkeys
            .iter()
            .zip(cids.iter())
            .map(|(rk, c)| rw(&collection, rk, c))
            .collect();

        let mut batch = ms.database().batch();
        rec_ops
            .upsert_records(&mut batch, user_hash, &writes)
            .unwrap();
        batch.commit().unwrap();

        let cursor = Rkey::from("rkey001".to_string());
        let results = rec_ops
            .list_records(&lrq(
                user_id,
                &collection,
                Some(&cursor),
                10,
                true,
                None,
                None,
            ))
            .unwrap();
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].rkey.as_str(), "rkey002");
        assert_eq!(results[1].rkey.as_str(), "rkey003");
        assert_eq!(results[2].rkey.as_str(), "rkey004");
    }

    #[test]
    fn list_records_default_desc_rkey_range_bounds() {
        let (_dir, ms) = open_fresh();
        let (user_id, user_hash) = setup_user(&ms);
        let rec_ops = ms.record_ops();

        let collection = Nsid::from("app.bsky.feed.post".to_string());
        let rkeys: Vec<Rkey> = (0..10).map(|i| Rkey::from(format!("rkey{i:03}"))).collect();
        let cids: Vec<CidLink> = (0..10).map(|i| test_cid_link(i + 1)).collect();

        let writes: Vec<RecordWrite<'_>> = rkeys
            .iter()
            .zip(cids.iter())
            .map(|(rk, c)| rw(&collection, rk, c))
            .collect();

        let mut batch = ms.database().batch();
        rec_ops
            .upsert_records(&mut batch, user_hash, &writes)
            .unwrap();
        batch.commit().unwrap();

        let rkey_start = Rkey::from("rkey003".to_string());
        let rkey_end = Rkey::from("rkey006".to_string());
        let results = rec_ops
            .list_records(&lrq(
                user_id,
                &collection,
                None,
                100,
                false,
                Some(&rkey_start),
                Some(&rkey_end),
            ))
            .unwrap();
        assert_eq!(results.len(), 4);
        assert_eq!(results[0].rkey.as_str(), "rkey006");
        assert_eq!(results[3].rkey.as_str(), "rkey003");
    }

    #[test]
    fn get_all_records_across_collections() {
        let (_dir, ms) = open_fresh();
        let (user_id, user_hash) = setup_user(&ms);
        let rec_ops = ms.record_ops();

        let coll1 = Nsid::from("app.bsky.feed.like".to_string());
        let coll2 = Nsid::from("app.bsky.feed.post".to_string());
        let rkey_a = Rkey::from("a".to_string());
        let rkey_b = Rkey::from("b".to_string());
        let rkey_c = Rkey::from("c".to_string());
        let cid1 = test_cid_link(1);
        let cid2 = test_cid_link(2);
        let cid3 = test_cid_link(3);

        let mut batch = ms.database().batch();
        rec_ops
            .upsert_records(
                &mut batch,
                user_hash,
                &[
                    rw(&coll1, &rkey_a, &cid1),
                    rw(&coll2, &rkey_b, &cid2),
                    rw(&coll1, &rkey_c, &cid3),
                ],
            )
            .unwrap();
        batch.commit().unwrap();

        let all = rec_ops.get_all_records(user_id).unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].collection.as_str(), "app.bsky.feed.like");
        assert_eq!(all[1].collection.as_str(), "app.bsky.feed.like");
        assert_eq!(all[2].collection.as_str(), "app.bsky.feed.post");
    }

    #[test]
    fn list_collections_returns_distinct_sorted() {
        let (_dir, ms) = open_fresh();
        let (user_id, user_hash) = setup_user(&ms);
        let rec_ops = ms.record_ops();

        let coll1 = Nsid::from("app.bsky.feed.like".to_string());
        let coll2 = Nsid::from("app.bsky.feed.post".to_string());
        let coll3 = Nsid::from("app.bsky.graph.follow".to_string());
        let rkeys: Vec<Rkey> = ["a", "b", "c", "d", "e"]
            .iter()
            .map(|s| Rkey::from(s.to_string()))
            .collect();
        let cids: Vec<CidLink> = (1..=5).map(test_cid_link).collect();

        let mut batch = ms.database().batch();
        rec_ops
            .upsert_records(
                &mut batch,
                user_hash,
                &[
                    rw(&coll1, &rkeys[0], &cids[0]),
                    rw(&coll2, &rkeys[1], &cids[1]),
                    rw(&coll1, &rkeys[2], &cids[2]),
                    rw(&coll3, &rkeys[3], &cids[3]),
                    rw(&coll2, &rkeys[4], &cids[4]),
                ],
            )
            .unwrap();
        batch.commit().unwrap();

        let collections = rec_ops.list_collections(user_id).unwrap();
        assert_eq!(collections.len(), 3);
        assert_eq!(collections[0].as_str(), "app.bsky.feed.like");
        assert_eq!(collections[1].as_str(), "app.bsky.feed.post");
        assert_eq!(collections[2].as_str(), "app.bsky.graph.follow");
    }

    #[test]
    fn count_records_and_count_all() {
        let (_dir, ms) = open_fresh();
        let (user_id, user_hash) = setup_user(&ms);
        let rec_ops = ms.record_ops();

        assert_eq!(rec_ops.count_records(user_id).unwrap(), 0);
        assert_eq!(rec_ops.count_all_records().unwrap(), 0);

        let collection = Nsid::from("app.bsky.feed.post".to_string());
        let rkey_a = Rkey::from("a".to_string());
        let rkey_b = Rkey::from("b".to_string());
        let cid1 = test_cid_link(1);
        let cid2 = test_cid_link(2);

        let mut batch = ms.database().batch();
        rec_ops
            .upsert_records(
                &mut batch,
                user_hash,
                &[
                    rw(&collection, &rkey_a, &cid1),
                    rw(&collection, &rkey_b, &cid2),
                ],
            )
            .unwrap();
        batch.commit().unwrap();

        assert_eq!(rec_ops.count_records(user_id).unwrap(), 2);
        assert_eq!(rec_ops.count_all_records().unwrap(), 2);
    }

    #[test]
    fn records_isolated_between_users() {
        let (_dir, ms) = open_fresh();
        let rec_ops = ms.record_ops();

        let user1 = Uuid::new_v4();
        let did1 = test_did("user1");
        let handle1 = test_handle("user1");
        ms.repo_ops()
            .create_repo(
                ms.database(),
                user1,
                &did1,
                &handle1,
                &test_cid_link(0),
                "r",
            )
            .unwrap();
        let hash1 = ms.user_hashes().get(&user1).unwrap();

        let user2 = Uuid::new_v4();
        let did2 = test_did("user2");
        let handle2 = test_handle("user2");
        ms.repo_ops()
            .create_repo(
                ms.database(),
                user2,
                &did2,
                &handle2,
                &test_cid_link(0),
                "r",
            )
            .unwrap();
        let hash2 = ms.user_hashes().get(&user2).unwrap();

        let collection = Nsid::from("app.bsky.feed.post".to_string());
        let rkey_a = Rkey::from("a".to_string());
        let rkey_b = Rkey::from("b".to_string());
        let cid1 = test_cid_link(1);
        let cid2 = test_cid_link(2);

        let mut batch = ms.database().batch();
        rec_ops
            .upsert_records(&mut batch, hash1, &[rw(&collection, &rkey_a, &cid1)])
            .unwrap();
        rec_ops
            .upsert_records(&mut batch, hash2, &[rw(&collection, &rkey_b, &cid2)])
            .unwrap();
        batch.commit().unwrap();

        assert_eq!(rec_ops.count_records(user1).unwrap(), 1);
        assert_eq!(rec_ops.count_records(user2).unwrap(), 1);
        assert_eq!(rec_ops.count_all_records().unwrap(), 2);
    }

    #[test]
    fn get_record_by_cid_finds_match() {
        let (_dir, ms) = open_fresh();
        let (user_id, user_hash) = setup_user(&ms);
        let rec_ops = ms.record_ops();

        let collection = Nsid::from("app.bsky.feed.post".to_string());
        let rkey = Rkey::from("r1".to_string());
        let cid = test_cid_link(42);

        let mut batch = ms.database().batch();
        rec_ops
            .upsert_records(&mut batch, user_hash, &[rw(&collection, &rkey, &cid)])
            .unwrap();
        batch.commit().unwrap();

        let found = rec_ops.get_record_by_cid(&cid, None).unwrap().unwrap();
        assert_eq!(found.id, user_id);
        assert_eq!(found.collection.as_str(), "app.bsky.feed.post");
        assert_eq!(found.rkey.as_str(), "r1");
        assert!(found.takedown_ref.is_none());
    }

    #[test]
    fn get_record_by_cid_returns_none_for_missing() {
        let (_dir, ms) = open_fresh();
        let rec_ops = ms.record_ops();
        assert!(
            rec_ops
                .get_record_by_cid(&test_cid_link(99), None)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn get_record_by_cid_scoped_to_user() {
        let (_dir, ms) = open_fresh();
        let (user_id, user_hash) = setup_user(&ms);
        let rec_ops = ms.record_ops();

        let collection = Nsid::from("app.bsky.feed.post".to_string());
        let rkey = Rkey::from("r1".to_string());
        let cid = test_cid_link(42);

        let mut batch = ms.database().batch();
        rec_ops
            .upsert_records(&mut batch, user_hash, &[rw(&collection, &rkey, &cid)])
            .unwrap();
        batch.commit().unwrap();

        let found = rec_ops
            .get_record_by_cid(&cid, Some(user_id))
            .unwrap()
            .unwrap();
        assert_eq!(found.id, user_id);

        let other_user = Uuid::new_v4();
        assert!(
            rec_ops
                .get_record_by_cid(&cid, Some(other_user))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn set_and_get_takedown() {
        let (_dir, ms) = open_fresh();
        let (user_id, user_hash) = setup_user(&ms);
        let rec_ops = ms.record_ops();

        let collection = Nsid::from("app.bsky.feed.post".to_string());
        let rkey = Rkey::from("r1".to_string());
        let cid = test_cid_link(42);

        let mut batch = ms.database().batch();
        rec_ops
            .upsert_records(&mut batch, user_hash, &[rw(&collection, &rkey, &cid)])
            .unwrap();
        batch.commit().unwrap();

        rec_ops
            .set_record_takedown(ms.database(), &cid, Some("DMCA-789"), None)
            .unwrap();

        let found = rec_ops.get_record_by_cid(&cid, None).unwrap().unwrap();
        assert_eq!(found.id, user_id);
        assert_eq!(found.takedown_ref.as_deref(), Some("DMCA-789"));

        rec_ops
            .set_record_takedown(ms.database(), &cid, None, None)
            .unwrap();

        let found = rec_ops.get_record_by_cid(&cid, None).unwrap().unwrap();
        assert!(found.takedown_ref.is_none());
    }

    #[test]
    fn upsert_preserves_existing_takedown() {
        let (_dir, ms) = open_fresh();
        let (_user_id, user_hash) = setup_user(&ms);
        let rec_ops = ms.record_ops();

        let collection = Nsid::from("app.bsky.feed.post".to_string());
        let rkey = Rkey::from("r1".to_string());
        let cid1 = test_cid_link(1);
        let cid2 = test_cid_link(2);

        let mut batch = ms.database().batch();
        rec_ops
            .upsert_records(&mut batch, user_hash, &[rw(&collection, &rkey, &cid1)])
            .unwrap();
        batch.commit().unwrap();

        rec_ops
            .set_record_takedown(ms.database(), &cid1, Some("DMCA-999"), None)
            .unwrap();

        let mut batch = ms.database().batch();
        rec_ops
            .upsert_records(&mut batch, user_hash, &[rw(&collection, &rkey, &cid2)])
            .unwrap();
        batch.commit().unwrap();

        let found = rec_ops.get_record_by_cid(&cid2, None).unwrap().unwrap();
        assert_eq!(found.takedown_ref.as_deref(), Some("DMCA-999"));
    }

    #[test]
    fn records_survive_reopen() {
        let dir = tempfile::TempDir::new().unwrap();
        let user_id;
        let collection = Nsid::from("app.bsky.feed.post".to_string());
        let rkey = Rkey::from("durable".to_string());
        let cid = test_cid_link(77);

        {
            let ms = Metastore::open(dir.path(), test_config()).unwrap();
            user_id = Uuid::new_v4();
            let did = test_did("persist");
            let handle = test_handle("persist");
            ms.repo_ops()
                .create_repo(
                    ms.database(),
                    user_id,
                    &did,
                    &handle,
                    &test_cid_link(0),
                    "r",
                )
                .unwrap();
            let user_hash = ms.user_hashes().get(&user_id).unwrap();

            let rec_ops = ms.record_ops();
            let mut batch = ms.database().batch();
            rec_ops
                .upsert_records(&mut batch, user_hash, &[rw(&collection, &rkey, &cid)])
                .unwrap();
            batch.commit().unwrap();
            ms.persist().unwrap();
        }

        {
            let ms = Metastore::open(dir.path(), test_config()).unwrap();
            let rec_ops = ms.record_ops();
            let found = rec_ops.get_record_cid(user_id, &collection, &rkey).unwrap();
            assert_eq!(found, Some(cid));
        }
    }

    #[test]
    fn rkey_ordering_matches_lexicographic() {
        let (_dir, ms) = open_fresh();
        let (user_id, user_hash) = setup_user(&ms);
        let rec_ops = ms.record_ops();

        let collection = Nsid::from("app.bsky.feed.post".to_string());
        let rkeys_unordered = ["zebra", "apple", "mango", "banana"];

        let rkeys: Vec<Rkey> = rkeys_unordered
            .iter()
            .map(|rk| Rkey::from(rk.to_string()))
            .collect();
        let cids: Vec<CidLink> = (0..rkeys.len())
            .map(|i| test_cid_link(i as u8 + 1))
            .collect();

        let writes: Vec<RecordWrite<'_>> = rkeys
            .iter()
            .zip(cids.iter())
            .map(|(rk, c)| rw(&collection, rk, c))
            .collect();

        let mut batch = ms.database().batch();
        rec_ops
            .upsert_records(&mut batch, user_hash, &writes)
            .unwrap();
        batch.commit().unwrap();

        let results = rec_ops
            .list_records(&lrq(user_id, &collection, None, 100, false, None, None))
            .unwrap();
        let result_rkeys: Vec<&str> = results.iter().map(|r| r.rkey.as_str()).collect();
        assert_eq!(result_rkeys, ["zebra", "mango", "banana", "apple"]);
    }

    #[test]
    fn record_with_empty_rkey() {
        let (_dir, ms) = open_fresh();
        let (user_id, user_hash) = setup_user(&ms);
        let rec_ops = ms.record_ops();

        let collection = Nsid::from("app.bsky.feed.post".to_string());
        let rkey = Rkey::from(String::new());
        let cid = test_cid_link(1);

        let mut batch = ms.database().batch();
        rec_ops
            .upsert_records(&mut batch, user_hash, &[rw(&collection, &rkey, &cid)])
            .unwrap();
        batch.commit().unwrap();

        let found = rec_ops.get_record_cid(user_id, &collection, &rkey).unwrap();
        assert_eq!(found, Some(cid));

        let results = rec_ops
            .list_records(&lrq(user_id, &collection, None, 100, false, None, None))
            .unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn record_with_null_bytes_in_rkey() {
        let (_dir, ms) = open_fresh();
        let (user_id, user_hash) = setup_user(&ms);
        let rec_ops = ms.record_ops();

        let collection = Nsid::from("app.bsky.feed.post".to_string());
        let rkey_with_null = Rkey::from("abc\x00def".to_string());
        let rkey_plain = Rkey::from("abc".to_string());
        let cid1 = test_cid_link(1);
        let cid2 = test_cid_link(2);

        let mut batch = ms.database().batch();
        rec_ops
            .upsert_records(
                &mut batch,
                user_hash,
                &[
                    rw(&collection, &rkey_with_null, &cid1),
                    rw(&collection, &rkey_plain, &cid2),
                ],
            )
            .unwrap();
        batch.commit().unwrap();

        let found1 = rec_ops
            .get_record_cid(user_id, &collection, &rkey_with_null)
            .unwrap();
        assert_eq!(found1, Some(cid1));

        let found2 = rec_ops
            .get_record_cid(user_id, &collection, &rkey_plain)
            .unwrap();
        assert_eq!(found2, Some(cid2));

        let results = rec_ops
            .list_records(&lrq(user_id, &collection, None, 100, false, None, None))
            .unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].rkey.as_str(), "abc\x00def");
        assert_eq!(results[1].rkey.as_str(), "abc");
    }

    #[test]
    fn record_with_null_bytes_in_collection() {
        let (_dir, ms) = open_fresh();
        let (user_id, user_hash) = setup_user(&ms);
        let rec_ops = ms.record_ops();

        let coll_normal = Nsid::from("app.bsky.feed.post".to_string());
        let coll_with_null = Nsid::from("app.bsky.feed.post\x00extra".to_string());
        let rkey = Rkey::from("r1".to_string());
        let cid1 = test_cid_link(1);
        let cid2 = test_cid_link(2);

        let mut batch = ms.database().batch();
        rec_ops
            .upsert_records(
                &mut batch,
                user_hash,
                &[
                    rw(&coll_normal, &rkey, &cid1),
                    rw(&coll_with_null, &rkey, &cid2),
                ],
            )
            .unwrap();
        batch.commit().unwrap();

        let found1 = rec_ops
            .get_record_cid(user_id, &coll_normal, &rkey)
            .unwrap();
        assert_eq!(found1, Some(cid1));

        let found2 = rec_ops
            .get_record_cid(user_id, &coll_with_null, &rkey)
            .unwrap();
        assert_eq!(found2, Some(cid2));

        let results_normal = rec_ops
            .list_records(&lrq(user_id, &coll_normal, None, 100, false, None, None))
            .unwrap();
        assert_eq!(results_normal.len(), 1);

        let results_null = rec_ops
            .list_records(&lrq(user_id, &coll_with_null, None, 100, false, None, None))
            .unwrap();
        assert_eq!(results_null.len(), 1);

        let collections = rec_ops.list_collections(user_id).unwrap();
        assert_eq!(collections.len(), 2);
    }

    #[test]
    fn list_records_cursor_before_all_returns_empty() {
        let (_dir, ms) = open_fresh();
        let (user_id, user_hash) = setup_user(&ms);
        let rec_ops = ms.record_ops();

        let collection = Nsid::from("app.bsky.feed.post".to_string());
        let rkeys: Vec<Rkey> = (0..5).map(|i| Rkey::from(format!("rkey{i:03}"))).collect();
        let cids: Vec<CidLink> = (0..5).map(|i| test_cid_link(i + 1)).collect();

        let writes: Vec<RecordWrite<'_>> = rkeys
            .iter()
            .zip(cids.iter())
            .map(|(rk, c)| rw(&collection, rk, c))
            .collect();

        let mut batch = ms.database().batch();
        rec_ops
            .upsert_records(&mut batch, user_hash, &writes)
            .unwrap();
        batch.commit().unwrap();

        let cursor = Rkey::from("a".to_string());
        let results = rec_ops
            .list_records(&lrq(
                user_id,
                &collection,
                Some(&cursor),
                100,
                false,
                None,
                None,
            ))
            .unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn list_records_reverse_asc_with_rkey_bounds() {
        let (_dir, ms) = open_fresh();
        let (user_id, user_hash) = setup_user(&ms);
        let rec_ops = ms.record_ops();

        let collection = Nsid::from("app.bsky.feed.post".to_string());
        let rkeys: Vec<Rkey> = (0..10).map(|i| Rkey::from(format!("rkey{i:03}"))).collect();
        let cids: Vec<CidLink> = (0..10).map(|i| test_cid_link(i + 1)).collect();

        let writes: Vec<RecordWrite<'_>> = rkeys
            .iter()
            .zip(cids.iter())
            .map(|(rk, c)| rw(&collection, rk, c))
            .collect();

        let mut batch = ms.database().batch();
        rec_ops
            .upsert_records(&mut batch, user_hash, &writes)
            .unwrap();
        batch.commit().unwrap();

        let rkey_start = Rkey::from("rkey002".to_string());
        let rkey_end = Rkey::from("rkey007".to_string());
        let results = rec_ops
            .list_records(&lrq(
                user_id,
                &collection,
                None,
                100,
                true,
                Some(&rkey_start),
                Some(&rkey_end),
            ))
            .unwrap();
        assert_eq!(results.len(), 6);
        assert_eq!(results[0].rkey.as_str(), "rkey002");
        assert_eq!(results[5].rkey.as_str(), "rkey007");
    }

    #[test]
    fn list_records_default_desc_cursor_narrows_range() {
        let (_dir, ms) = open_fresh();
        let (user_id, user_hash) = setup_user(&ms);
        let rec_ops = ms.record_ops();

        let collection = Nsid::from("app.bsky.feed.post".to_string());
        let rkeys: Vec<Rkey> = (0..10).map(|i| Rkey::from(format!("rkey{i:03}"))).collect();
        let cids: Vec<CidLink> = (0..10).map(|i| test_cid_link(i + 1)).collect();

        let writes: Vec<RecordWrite<'_>> = rkeys
            .iter()
            .zip(cids.iter())
            .map(|(rk, c)| rw(&collection, rk, c))
            .collect();

        let mut batch = ms.database().batch();
        rec_ops
            .upsert_records(&mut batch, user_hash, &writes)
            .unwrap();
        batch.commit().unwrap();

        let cursor = Rkey::from("rkey005".to_string());
        let results = rec_ops
            .list_records(&lrq(
                user_id,
                &collection,
                Some(&cursor),
                3,
                false,
                None,
                None,
            ))
            .unwrap();
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].rkey.as_str(), "rkey004");
        assert_eq!(results[1].rkey.as_str(), "rkey003");
        assert_eq!(results[2].rkey.as_str(), "rkey002");
    }

    #[test]
    fn exclusive_upper_bound_basic() {
        let prefix = &[0x01, 0x02, 0x03];
        let upper = exclusive_upper_bound(prefix).unwrap();
        assert_eq!(upper.as_slice(), &[0x01, 0x02, 0x04]);
    }

    #[test]
    fn exclusive_upper_bound_with_trailing_ff() {
        let prefix = &[0x01, 0xFF, 0xFF];
        let upper = exclusive_upper_bound(prefix).unwrap();
        assert_eq!(upper.as_slice(), &[0x02]);
    }

    #[test]
    fn exclusive_upper_bound_all_ff_returns_none() {
        assert!(exclusive_upper_bound(&[0xFF, 0xFF, 0xFF]).is_none());
    }

    #[test]
    fn exclusive_upper_bound_empty_returns_none() {
        assert!(exclusive_upper_bound(&[]).is_none());
    }

    #[test]
    fn exclusive_upper_bound_preserves_prefix_ordering() {
        let prefix = &[
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2A, 0x61, 0x00, 0x00,
        ];
        let upper = exclusive_upper_bound(prefix).unwrap();

        let key_inside = {
            let mut k = prefix.to_vec();
            k.extend_from_slice(&[0x62, 0x00, 0x00]);
            k
        };
        assert!(key_inside.as_slice() < upper.as_slice());

        let key_outside = {
            let mut k = Vec::from(&prefix[..prefix.len() - 2]);
            k.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
            k
        };
        assert!(key_outside.as_slice() >= upper.as_slice());
    }
}
