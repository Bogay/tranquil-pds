use chrono::{DateTime, TimeZone, Utc};
use fjall::Keyspace;
use std::sync::Arc;
use uuid::Uuid;

use super::MetastoreError;
use super::encoding::KeyReader;
use super::keys::{KeyTag, UserHash};
use super::repo_meta::{RepoMetaValue, RepoStatus, handle_key, repo_meta_key, repo_meta_prefix};
use super::scan::{count_prefix, point_lookup};
use super::user_hash::UserHashMap;

use tranquil_types::{CidLink, Did, Handle};

pub struct RepoOps {
    repo_data: Keyspace,
    user_hashes: Arc<UserHashMap>,
}

impl RepoOps {
    pub fn new(repo_data: Keyspace, user_hashes: Arc<UserHashMap>) -> Self {
        Self {
            repo_data,
            user_hashes,
        }
    }

    pub fn create_repo(
        &self,
        db: &fjall::Database,
        user_id: Uuid,
        did: &Did,
        handle: &Handle,
        repo_root_cid: &CidLink,
        repo_rev: &str,
    ) -> Result<(), MetastoreError> {
        let user_hash = UserHash::from_did(did.as_str());
        let mut batch = db.batch();

        self.user_hashes
            .stage_insert(&mut batch, user_id, user_hash)?;

        let cid_bytes = cid_link_to_bytes(repo_root_cid)?;
        let handle_lower = handle.as_str().to_ascii_lowercase();

        let value = RepoMetaValue {
            repo_root_cid: cid_bytes,
            repo_rev: repo_rev.to_string(),
            handle: handle_lower.clone(),
            status: RepoStatus::Active,
            deactivated_at_ms: None,
            takedown_ref: None,
            did: Some(did.as_str().to_string()),
        };

        batch.insert(
            &self.repo_data,
            repo_meta_key(user_hash).as_slice(),
            value.serialize(),
        );

        batch.insert(
            &self.repo_data,
            handle_key(&handle_lower).as_slice(),
            user_hash.raw().to_be_bytes(),
        );

        match batch.commit() {
            Ok(()) => Ok(()),
            Err(e) => {
                self.user_hashes.rollback_insert(&user_id, &user_hash);
                Err(MetastoreError::Fjall(e))
            }
        }
    }

    pub fn get_repo_meta(
        &self,
        user_id: Uuid,
    ) -> Result<Option<(UserHash, RepoMetaValue)>, MetastoreError> {
        let user_hash = match self.user_hashes.get(&user_id) {
            Some(h) => h,
            None => return Ok(None),
        };
        let key = repo_meta_key(user_hash);
        Ok(point_lookup(
            &self.repo_data,
            key.as_slice(),
            RepoMetaValue::deserialize,
            "invalid repo_meta value",
        )?
        .map(|v| (user_hash, v)))
    }

    pub fn write_repo_meta(
        &self,
        batch: &mut fjall::OwnedWriteBatch,
        user_hash: UserHash,
        value: &RepoMetaValue,
    ) {
        batch.insert(
            &self.repo_data,
            repo_meta_key(user_hash).as_slice(),
            value.serialize(),
        );
    }

    pub(crate) fn update_repo_root(
        &self,
        db: &fjall::Database,
        user_id: Uuid,
        repo_root_cid: &CidLink,
        repo_rev: &str,
    ) -> Result<(), MetastoreError> {
        let user_hash = self.resolve_user_hash(user_id)?;
        let key = repo_meta_key(user_hash);

        let mut value = self.get_meta_value(key.as_slice())?;
        let cid_bytes = cid_link_to_bytes(repo_root_cid)?;
        value.repo_root_cid = cid_bytes;
        value.repo_rev = repo_rev.to_string();

        let mut batch = db.batch();
        batch.insert(&self.repo_data, key.as_slice(), value.serialize());
        batch.commit().map_err(MetastoreError::Fjall)
    }

    pub(crate) fn update_repo_rev(
        &self,
        db: &fjall::Database,
        user_id: Uuid,
        repo_rev: &str,
    ) -> Result<(), MetastoreError> {
        let user_hash = self.resolve_user_hash(user_id)?;
        let key = repo_meta_key(user_hash);

        let mut value = self.get_meta_value(key.as_slice())?;
        value.repo_rev = repo_rev.to_string();

        let mut batch = db.batch();
        batch.insert(&self.repo_data, key.as_slice(), value.serialize());
        batch.commit().map_err(MetastoreError::Fjall)
    }

    pub fn update_repo_status(
        &self,
        db: &fjall::Database,
        did: &Did,
        takedown: Option<bool>,
        takedown_ref: Option<&str>,
        deactivated: Option<bool>,
    ) -> Result<(), MetastoreError> {
        let user_hash = UserHash::from_did(did.as_str());
        let key = repo_meta_key(user_hash);
        let existing = point_lookup(
            &self.repo_data,
            key.as_slice(),
            RepoMetaValue::deserialize,
            "invalid repo_meta value",
        )?;
        let mut value = match existing {
            Some(v) => v,
            None => {
                tracing::warn!(
                    did = did.as_str(),
                    "update_repo_status: repo not found in metastore"
                );
                return Ok(());
            }
        };

        match value.status {
            RepoStatus::Suspended | RepoStatus::Deleted => return Ok(()),
            _ => {}
        }

        if let Some(taken_down) = takedown {
            value.takedown_ref = match taken_down {
                true => Some(takedown_ref.unwrap_or("").to_owned()),
                false => None,
            };
        }
        if let Some(now_deactivated) = deactivated {
            value.deactivated_at_ms = match now_deactivated {
                true => value.deactivated_at_ms.or_else(|| {
                    Some(u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or(0))
                }),
                false => None,
            };
        }

        let is_taken_down = match takedown {
            Some(v) => v,
            None => value.takedown_ref.is_some(),
        };
        value.status = match (is_taken_down, value.deactivated_at_ms.is_some()) {
            (true, _) => RepoStatus::Takendown,
            (false, true) => RepoStatus::Deactivated,
            (false, false) => RepoStatus::Active,
        };

        let mut batch = db.batch();
        batch.insert(&self.repo_data, key.as_slice(), value.serialize());
        batch.commit().map_err(MetastoreError::Fjall)
    }

    pub fn update_handle(
        &self,
        db: &fjall::Database,
        user_id: Uuid,
        new_handle: &Handle,
    ) -> Result<(), MetastoreError> {
        let user_hash = self.resolve_user_hash(user_id)?;
        let key = repo_meta_key(user_hash);
        let mut value = self.get_meta_value(key.as_slice())?;
        let new_lower = new_handle.as_str().to_ascii_lowercase();

        let mut batch = db.batch();

        match value.handle.is_empty() {
            true => {}
            false => batch.remove(&self.repo_data, handle_key(&value.handle).as_slice()),
        }

        batch.insert(
            &self.repo_data,
            handle_key(&new_lower).as_slice(),
            user_hash.raw().to_be_bytes(),
        );

        value.handle = new_lower;
        batch.insert(&self.repo_data, key.as_slice(), value.serialize());

        batch.commit().map_err(MetastoreError::Fjall)
    }

    pub fn delete_repo(&self, db: &fjall::Database, user_id: Uuid) -> Result<(), MetastoreError> {
        let user_hash = self.resolve_user_hash(user_id)?;
        let key = repo_meta_key(user_hash);

        let meta = self.get_meta_value(key.as_slice())?;

        let mut batch = db.batch();
        batch.remove(&self.repo_data, key.as_slice());

        match meta.handle.is_empty() {
            true => {}
            false => batch.remove(&self.repo_data, handle_key(&meta.handle).as_slice()),
        }

        self.user_hashes.stage_remove(&mut batch, &user_id);

        match batch.commit() {
            Ok(()) => Ok(()),
            Err(e) => {
                self.user_hashes.rollback_remove(user_id, user_hash);
                Err(MetastoreError::Fjall(e))
            }
        }
    }

    pub fn get_repo(&self, user_id: Uuid) -> Result<Option<RepoInfo>, MetastoreError> {
        let user_hash = match self.user_hashes.get(&user_id) {
            Some(h) => h,
            None => return Ok(None),
        };
        let key = repo_meta_key(user_hash);
        point_lookup(
            &self.repo_data,
            key.as_slice(),
            RepoMetaValue::deserialize,
            "invalid repo_meta value",
        )?
        .map(|value| {
            let cid = bytes_to_cid_link(&value.repo_root_cid)?;
            Ok(RepoInfo {
                user_id,
                repo_root_cid: cid,
                repo_rev: Some(value.repo_rev),
            })
        })
        .transpose()
    }

    pub fn get_repo_root_for_update(
        &self,
        user_id: Uuid,
    ) -> Result<Option<CidLink>, MetastoreError> {
        let user_hash = match self.user_hashes.get(&user_id) {
            Some(h) => h,
            None => return Ok(None),
        };
        let key = repo_meta_key(user_hash);
        point_lookup(
            &self.repo_data,
            key.as_slice(),
            RepoMetaValue::deserialize,
            "invalid repo_meta value",
        )?
        .map(|v| bytes_to_cid_link(&v.repo_root_cid))
        .transpose()
    }

    pub fn get_repo_root_by_did(&self, did: &Did) -> Result<Option<CidLink>, MetastoreError> {
        let user_hash = UserHash::from_did(did.as_str());
        let key = repo_meta_key(user_hash);
        point_lookup(
            &self.repo_data,
            key.as_slice(),
            RepoMetaValue::deserialize,
            "invalid repo_meta value",
        )?
        .map(|v| bytes_to_cid_link(&v.repo_root_cid))
        .transpose()
    }

    pub fn get_repo_root_cid_by_user_id(
        &self,
        user_id: Uuid,
    ) -> Result<Option<CidLink>, MetastoreError> {
        self.get_repo_root_for_update(user_id)
    }

    pub fn count_repos(&self) -> Result<i64, MetastoreError> {
        let prefix = repo_meta_prefix();
        count_prefix(&self.repo_data, prefix.as_slice())
    }

    pub fn get_repos_without_rev(
        &self,
        limit: usize,
    ) -> Result<Vec<RepoWithoutRevEntry>, MetastoreError> {
        let prefix = repo_meta_prefix();
        self.repo_data
            .prefix(prefix.as_slice())
            .filter_map(|guard| {
                let (key_bytes, val_bytes) = match guard.into_inner() {
                    Ok(pair) => pair,
                    Err(e) => return Some(Err(MetastoreError::Fjall(e))),
                };
                let value = match RepoMetaValue::deserialize(&val_bytes) {
                    Some(v) => v,
                    None => {
                        return Some(Err(MetastoreError::CorruptData("invalid repo_meta value")));
                    }
                };
                match value.repo_rev.is_empty() {
                    true => Some(decode_without_rev_entry(
                        &key_bytes,
                        &value,
                        &self.user_hashes,
                    )),
                    false => None,
                }
            })
            .take(limit)
            .collect()
    }

    pub fn get_account_with_repo(
        &self,
        did: &Did,
    ) -> Result<Option<RepoAccountEntry>, MetastoreError> {
        let user_hash = UserHash::from_did(did.as_str());
        let key = repo_meta_key(user_hash);
        point_lookup(
            &self.repo_data,
            key.as_slice(),
            RepoMetaValue::deserialize,
            "invalid repo_meta value",
        )?
        .map(|value| {
            let user_id =
                self.user_hashes
                    .get_uuid(&user_hash)
                    .ok_or(MetastoreError::CorruptData(
                        "user_hash has no reverse mapping",
                    ))?;
            let cid = Some(bytes_to_cid_link(&value.repo_root_cid)?);
            let deactivated_at = value
                .deactivated_at_ms
                .and_then(|ms| i64::try_from(ms).ok())
                .and_then(|ms| Utc.timestamp_millis_opt(ms).single());
            Ok(RepoAccountEntry {
                user_id,
                did: did.clone(),
                deactivated_at,
                takedown_ref: value.takedown_ref,
                repo_root_cid: cid,
            })
        })
        .transpose()
    }

    pub fn list_repos_paginated(
        &self,
        cursor_user_hash: Option<u64>,
        limit: usize,
    ) -> Result<Vec<RepoListEntry>, MetastoreError> {
        const _: () = assert!(KeyTag::REPO_META.raw() < 0xFF);
        let upper = KeyTag::REPO_META.exclusive_prefix_bound();

        let start = match cursor_user_hash {
            Some(cursor) => match cursor.checked_add(1) {
                Some(next) => repo_meta_key(UserHash::from_raw(next)),
                None => return Ok(Vec::new()),
            },
            None => repo_meta_prefix(),
        };

        self.repo_data
            .range(start.as_slice()..upper.as_slice())
            .take(limit)
            .map(|guard| {
                let (k, v) = guard.into_inner().map_err(MetastoreError::Fjall)?;
                decode_list_entry_from_kv(&k, &v, &self.user_hashes)
            })
            .collect()
    }

    fn resolve_user_hash(&self, user_id: Uuid) -> Result<UserHash, MetastoreError> {
        self.user_hashes
            .get(&user_id)
            .ok_or(MetastoreError::InvalidInput("unknown user_id"))
    }

    fn get_meta_value(&self, key: &[u8]) -> Result<RepoMetaValue, MetastoreError> {
        point_lookup(
            &self.repo_data,
            key,
            RepoMetaValue::deserialize,
            "invalid repo_meta value",
        )?
        .ok_or(MetastoreError::CorruptData("repo_meta not found"))
    }

    pub fn lookup_handle(&self, handle: &Handle) -> Result<Option<Uuid>, MetastoreError> {
        let handle_lower = handle.as_str().to_ascii_lowercase();
        let key = handle_key(&handle_lower);

        match self
            .repo_data
            .get(key.as_slice())
            .map_err(MetastoreError::Fjall)?
        {
            Some(raw) => {
                let user_hash = parse_handle_value(&raw)?;
                self.user_hashes
                    .get_uuid(&user_hash)
                    .ok_or(MetastoreError::CorruptData(
                        "handle maps to unknown user_hash",
                    ))
                    .map(Some)
            }
            None => Ok(None),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RepoInfo {
    pub user_id: Uuid,
    pub repo_root_cid: CidLink,
    pub repo_rev: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RepoWithoutRevEntry {
    pub user_id: Uuid,
    pub repo_root_cid: CidLink,
}

#[derive(Debug, Clone)]
pub struct RepoAccountEntry {
    pub user_id: Uuid,
    pub did: Did,
    pub deactivated_at: Option<DateTime<Utc>>,
    pub takedown_ref: Option<String>,
    pub repo_root_cid: Option<CidLink>,
}

#[derive(Debug, Clone)]
pub struct RepoListEntry {
    pub user_id: Uuid,
    pub user_hash: UserHash,
    pub did: Option<String>,
    pub deactivated_at: Option<DateTime<Utc>>,
    pub takedown_ref: Option<String>,
    pub repo_root_cid: CidLink,
    pub repo_rev: Option<String>,
}

fn decode_list_entry_from_kv(
    key_bytes: &[u8],
    val_bytes: &[u8],
    user_hashes: &UserHashMap,
) -> Result<RepoListEntry, MetastoreError> {
    let value = RepoMetaValue::deserialize(val_bytes)
        .ok_or(MetastoreError::CorruptData("invalid repo_meta value"))?;
    let user_hash = parse_repo_meta_key_hash(key_bytes)
        .ok_or(MetastoreError::CorruptData("invalid repo_meta key"))?;
    let user_id = user_hashes
        .get_uuid(&user_hash)
        .ok_or(MetastoreError::CorruptData(
            "user_hash has no reverse mapping",
        ))?;
    let cid = bytes_to_cid_link(&value.repo_root_cid)?;
    let deactivated_at = value
        .deactivated_at_ms
        .and_then(|ms| i64::try_from(ms).ok())
        .and_then(|ms| Utc.timestamp_millis_opt(ms).single());
    Ok(RepoListEntry {
        user_id,
        user_hash,
        did: value.did,
        deactivated_at,
        takedown_ref: value.takedown_ref,
        repo_root_cid: cid,
        repo_rev: match value.repo_rev.is_empty() {
            true => None,
            false => Some(value.repo_rev),
        },
    })
}

fn decode_without_rev_entry(
    key_bytes: &[u8],
    value: &RepoMetaValue,
    user_hashes: &UserHashMap,
) -> Result<RepoWithoutRevEntry, MetastoreError> {
    let user_hash = parse_repo_meta_key_hash(key_bytes)
        .ok_or(MetastoreError::CorruptData("invalid repo_meta key"))?;
    let user_id = user_hashes
        .get_uuid(&user_hash)
        .ok_or(MetastoreError::CorruptData(
            "user_hash has no reverse mapping",
        ))?;
    let cid = bytes_to_cid_link(&value.repo_root_cid)?;
    Ok(RepoWithoutRevEntry {
        user_id,
        repo_root_cid: cid,
    })
}

pub(crate) fn cid_link_to_bytes(cid_link: &CidLink) -> Result<Vec<u8>, MetastoreError> {
    let cid = cid_link.to_cid().ok_or(MetastoreError::InvalidInput(
        "CidLink does not contain a valid CID",
    ))?;
    Ok(cid.to_bytes())
}

pub(crate) fn bytes_to_cid_link(bytes: &[u8]) -> Result<CidLink, MetastoreError> {
    let cid = cid::Cid::read_bytes(std::io::Cursor::new(bytes))
        .map_err(|_| MetastoreError::CorruptData("invalid CID bytes in repo_meta"))?;
    Ok(CidLink::from_cid(&cid))
}

fn parse_handle_value(raw: &[u8]) -> Result<UserHash, MetastoreError> {
    let bytes: [u8; 8] = raw
        .try_into()
        .map_err(|_| MetastoreError::CorruptData("handle value not 8 bytes"))?;
    Ok(UserHash::from_raw(u64::from_be_bytes(bytes)))
}

fn parse_repo_meta_key_hash(key_bytes: &[u8]) -> Option<UserHash> {
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

    fn test_did(name: &str) -> Did {
        Did::from(format!("did:plc:{name}"))
    }

    fn test_handle(name: &str) -> Handle {
        Handle::from(format!("{name}.test.invalid"))
    }

    #[test]
    fn create_and_get_repo() {
        let (_dir, ms) = open_fresh();
        let ops = ms.repo_ops();
        let user_id = uuid::Uuid::new_v4();
        let did = test_did("alice");
        let handle = test_handle("alice");
        let cid = test_cid_link(1);

        ops.create_repo(ms.database(), user_id, &did, &handle, &cid, "rev1")
            .unwrap();

        let repo = ops.get_repo(user_id).unwrap().unwrap();
        assert_eq!(repo.user_id, user_id);
        assert_eq!(repo.repo_root_cid, cid);
        assert_eq!(repo.repo_rev.as_deref(), Some("rev1"));
    }

    #[test]
    fn get_repo_returns_none_for_unknown() {
        let (_dir, ms) = open_fresh();
        let ops = ms.repo_ops();
        assert!(ops.get_repo(uuid::Uuid::new_v4()).unwrap().is_none());
    }

    #[test]
    fn update_repo_root() {
        let (_dir, ms) = open_fresh();
        let ops = ms.repo_ops();
        let user_id = uuid::Uuid::new_v4();
        let did = test_did("bob");
        let handle = test_handle("bob");
        let cid1 = test_cid_link(1);
        let cid2 = test_cid_link(2);

        ops.create_repo(ms.database(), user_id, &did, &handle, &cid1, "rev1")
            .unwrap();
        ops.update_repo_root(ms.database(), user_id, &cid2, "rev2")
            .unwrap();

        let repo = ops.get_repo(user_id).unwrap().unwrap();
        assert_eq!(repo.repo_root_cid, cid2);
        assert_eq!(repo.repo_rev.as_deref(), Some("rev2"));
    }

    #[test]
    fn update_repo_rev() {
        let (_dir, ms) = open_fresh();
        let ops = ms.repo_ops();
        let user_id = uuid::Uuid::new_v4();
        let did = test_did("carol");
        let handle = test_handle("carol");
        let cid = test_cid_link(3);

        ops.create_repo(ms.database(), user_id, &did, &handle, &cid, "rev1")
            .unwrap();
        ops.update_repo_rev(ms.database(), user_id, "rev_updated")
            .unwrap();

        let repo = ops.get_repo(user_id).unwrap().unwrap();
        assert_eq!(repo.repo_root_cid, cid);
        assert_eq!(repo.repo_rev.as_deref(), Some("rev_updated"));
    }

    #[test]
    fn delete_repo_removes_meta_and_handle() {
        let (_dir, ms) = open_fresh();
        let ops = ms.repo_ops();
        let user_id = uuid::Uuid::new_v4();
        let did = test_did("dave");
        let handle = test_handle("dave");
        let cid = test_cid_link(4);

        ops.create_repo(ms.database(), user_id, &did, &handle, &cid, "rev1")
            .unwrap();
        assert!(ops.get_repo(user_id).unwrap().is_some());
        assert!(ops.lookup_handle(&handle).unwrap().is_some());

        ops.delete_repo(ms.database(), user_id).unwrap();
        assert!(ops.get_repo(user_id).unwrap().is_none());
        assert!(ops.lookup_handle(&handle).unwrap().is_none());
    }

    #[test]
    fn delete_repo_clears_user_hash_mapping() {
        let (_dir, ms) = open_fresh();
        let ops = ms.repo_ops();
        let user_id = uuid::Uuid::new_v4();
        let did = test_did("mapped");
        let handle = test_handle("mapped");
        let cid = test_cid_link(4);

        ops.create_repo(ms.database(), user_id, &did, &handle, &cid, "rev1")
            .unwrap();
        assert!(ms.user_hashes().get(&user_id).is_some());

        ops.delete_repo(ms.database(), user_id).unwrap();
        assert!(ms.user_hashes().get(&user_id).is_none());
    }

    #[test]
    fn delete_repo_allows_recreate_with_same_did() {
        let (_dir, ms) = open_fresh();
        let ops = ms.repo_ops();
        let did = test_did("recreate");
        let handle_a = test_handle("recreate_a");
        let handle_b = test_handle("recreate_b");
        let uid_a = uuid::Uuid::new_v4();
        let uid_b = uuid::Uuid::new_v4();
        let cid = test_cid_link(70);

        ops.create_repo(ms.database(), uid_a, &did, &handle_a, &cid, "r1")
            .unwrap();
        ops.delete_repo(ms.database(), uid_a).unwrap();

        ops.create_repo(ms.database(), uid_b, &did, &handle_b, &cid, "r2")
            .unwrap();

        let repo = ops.get_repo(uid_b).unwrap().unwrap();
        assert_eq!(repo.user_id, uid_b);
        assert_eq!(repo.repo_rev.as_deref(), Some("r2"));
        assert!(ops.get_repo(uid_a).unwrap().is_none());
    }

    #[test]
    fn delete_nonexistent_user_returns_error() {
        let (_dir, ms) = open_fresh();
        let ops = ms.repo_ops();
        let result = ops.delete_repo(ms.database(), uuid::Uuid::new_v4());
        assert!(matches!(result, Err(MetastoreError::InvalidInput(_))));
    }

    #[test]
    fn handle_lookup_case_insensitive() {
        let (_dir, ms) = open_fresh();
        let ops = ms.repo_ops();
        let user_id = uuid::Uuid::new_v4();
        let did = test_did("eve");
        let handle = test_handle("eve");
        let cid = test_cid_link(5);

        ops.create_repo(ms.database(), user_id, &did, &handle, &cid, "rev1")
            .unwrap();

        let upper_handle = Handle::from("EVE.TEST.INVALID".to_string());
        let found = ops.lookup_handle(&upper_handle).unwrap();
        assert_eq!(found, Some(user_id));
    }

    #[test]
    fn get_repo_root_by_did() {
        let (_dir, ms) = open_fresh();
        let ops = ms.repo_ops();
        let user_id = uuid::Uuid::new_v4();
        let did = test_did("frank");
        let handle = test_handle("frank");
        let cid = test_cid_link(6);

        ops.create_repo(ms.database(), user_id, &did, &handle, &cid, "rev1")
            .unwrap();

        let root = ops.get_repo_root_by_did(&did).unwrap().unwrap();
        assert_eq!(root, cid);

        let unknown = test_did("nobody");
        assert!(ops.get_repo_root_by_did(&unknown).unwrap().is_none());
    }

    #[test]
    fn get_repo_root_for_update() {
        let (_dir, ms) = open_fresh();
        let ops = ms.repo_ops();
        let user_id = uuid::Uuid::new_v4();
        let did = test_did("grace");
        let handle = test_handle("grace");
        let cid = test_cid_link(7);

        ops.create_repo(ms.database(), user_id, &did, &handle, &cid, "rev1")
            .unwrap();

        let root = ops.get_repo_root_for_update(user_id).unwrap().unwrap();
        assert_eq!(root, cid);
    }

    #[test]
    fn count_repos() {
        let (_dir, ms) = open_fresh();
        let ops = ms.repo_ops();

        assert_eq!(ops.count_repos().unwrap(), 0);

        (0..5u8).for_each(|i| {
            let user_id = uuid::Uuid::new_v4();
            let did = test_did(&format!("user{i}"));
            let handle = test_handle(&format!("user{i}"));
            let cid = test_cid_link(i);
            ops.create_repo(ms.database(), user_id, &did, &handle, &cid, "rev1")
                .unwrap();
        });

        assert_eq!(ops.count_repos().unwrap(), 5);
    }

    #[test]
    fn get_account_with_repo() {
        let (_dir, ms) = open_fresh();
        let ops = ms.repo_ops();
        let user_id = uuid::Uuid::new_v4();
        let did = test_did("henry");
        let handle = test_handle("henry");
        let cid = test_cid_link(8);

        ops.create_repo(ms.database(), user_id, &did, &handle, &cid, "rev1")
            .unwrap();

        let account = ops.get_account_with_repo(&did).unwrap().unwrap();
        assert_eq!(account.user_id, user_id);
        assert_eq!(account.did, did);
        assert_eq!(account.repo_root_cid, Some(cid));
        assert!(account.deactivated_at.is_none());
        assert!(account.takedown_ref.is_none());
    }

    #[test]
    fn list_repos_paginated_all() {
        let (_dir, ms) = open_fresh();
        let ops = ms.repo_ops();

        (0..5u8).for_each(|i| {
            let user_id = uuid::Uuid::new_v4();
            let did = test_did(&format!("page{i}"));
            let handle = test_handle(&format!("page{i}"));
            let cid = test_cid_link(10 + i);
            ops.create_repo(
                ms.database(),
                user_id,
                &did,
                &handle,
                &cid,
                &format!("rev{i}"),
            )
            .unwrap();
        });

        let all = ops.list_repos_paginated(None, 100).unwrap();
        assert_eq!(all.len(), 5);

        all.iter()
            .zip(all.iter().skip(1))
            .for_each(|(a, b)| assert!(a.user_hash.raw() < b.user_hash.raw()));
    }

    #[test]
    fn list_repos_paginated_with_cursor() {
        let (_dir, ms) = open_fresh();
        let ops = ms.repo_ops();

        (0..10u8).for_each(|i| {
            let user_id = uuid::Uuid::new_v4();
            let did = test_did(&format!("cursor{i}"));
            let handle = test_handle(&format!("cursor{i}"));
            let cid = test_cid_link(20 + i);
            ops.create_repo(
                ms.database(),
                user_id,
                &did,
                &handle,
                &cid,
                &format!("rev{i}"),
            )
            .unwrap();
        });

        let page1 = ops.list_repos_paginated(None, 3).unwrap();
        assert_eq!(page1.len(), 3);

        let cursor = page1.last().unwrap().user_hash.raw();
        let page2 = ops.list_repos_paginated(Some(cursor), 3).unwrap();
        assert_eq!(page2.len(), 3);

        assert!(page2.first().unwrap().user_hash.raw() > cursor);

        let page2_cursor = page2.last().unwrap().user_hash.raw();
        let page3 = ops.list_repos_paginated(Some(page2_cursor), 100).unwrap();
        assert_eq!(page3.len(), 4);

        let total = page1.len() + page2.len() + page3.len();
        assert_eq!(total, 10);
    }

    #[test]
    fn data_survives_reopen() {
        let dir = tempfile::TempDir::new().unwrap();
        let user_id = uuid::Uuid::new_v4();
        let did = test_did("persist");
        let handle = test_handle("persist");
        let cid = test_cid_link(99);

        {
            let ms = Metastore::open(dir.path(), test_config()).unwrap();
            let ops = ms.repo_ops();
            ops.create_repo(ms.database(), user_id, &did, &handle, &cid, "rev_persist")
                .unwrap();
            ms.persist().unwrap();
        }

        {
            let ms = Metastore::open(dir.path(), test_config()).unwrap();
            let ops = ms.repo_ops();
            let repo = ops.get_repo(user_id).unwrap().unwrap();
            assert_eq!(repo.repo_root_cid, cid);
            assert_eq!(repo.repo_rev.as_deref(), Some("rev_persist"));

            let found = ops.lookup_handle(&handle).unwrap();
            assert_eq!(found, Some(user_id));
        }
    }

    #[test]
    fn get_repos_without_rev() {
        let (_dir, ms) = open_fresh();
        let ops = ms.repo_ops();

        let uid_with = uuid::Uuid::new_v4();
        let did_with = test_did("with_rev");
        let handle_with = test_handle("with_rev");
        ops.create_repo(
            ms.database(),
            uid_with,
            &did_with,
            &handle_with,
            &test_cid_link(40),
            "some_rev",
        )
        .unwrap();

        let uid_without = uuid::Uuid::new_v4();
        let did_without = test_did("without_rev");
        let handle_without = test_handle("without_rev");
        ops.create_repo(
            ms.database(),
            uid_without,
            &did_without,
            &handle_without,
            &test_cid_link(41),
            "",
        )
        .unwrap();

        let result = ops.get_repos_without_rev(100).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].user_id, uid_without);
    }

    #[test]
    fn get_repo_root_cid_by_user_id() {
        let (_dir, ms) = open_fresh();
        let ops = ms.repo_ops();
        let user_id = uuid::Uuid::new_v4();
        let did = test_did("root_cid");
        let handle = test_handle("root_cid");
        let cid = test_cid_link(50);

        ops.create_repo(ms.database(), user_id, &did, &handle, &cid, "rev1")
            .unwrap();

        let root = ops.get_repo_root_cid_by_user_id(user_id).unwrap().unwrap();
        assert_eq!(root, cid);

        assert!(
            ops.get_repo_root_cid_by_user_id(uuid::Uuid::new_v4())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn delete_only_removes_target_handle() {
        let (_dir, ms) = open_fresh();
        let ops = ms.repo_ops();

        let uid_a = uuid::Uuid::new_v4();
        let did_a = test_did("keep_a");
        let handle_a = test_handle("keep_a");
        ops.create_repo(
            ms.database(),
            uid_a,
            &did_a,
            &handle_a,
            &test_cid_link(60),
            "r",
        )
        .unwrap();

        let uid_b = uuid::Uuid::new_v4();
        let did_b = test_did("delete_b");
        let handle_b = test_handle("delete_b");
        ops.create_repo(
            ms.database(),
            uid_b,
            &did_b,
            &handle_b,
            &test_cid_link(61),
            "r",
        )
        .unwrap();

        ops.delete_repo(ms.database(), uid_b).unwrap();

        assert!(ops.lookup_handle(&handle_a).unwrap().is_some());
        assert!(ops.lookup_handle(&handle_b).unwrap().is_none());
        assert!(ops.get_repo(uid_a).unwrap().is_some());
    }

    #[test]
    fn create_repo_rejects_hash_collision() {
        let (_dir, ms) = open_fresh();
        let ops = ms.repo_ops();

        let uid_a = uuid::Uuid::new_v4();
        let did_a = test_did("collision_a");
        let handle_a = test_handle("collision_a");
        let cid = test_cid_link(80);

        ops.create_repo(ms.database(), uid_a, &did_a, &handle_a, &cid, "r1")
            .unwrap();

        let uid_b = uuid::Uuid::new_v4();
        let handle_b = test_handle("collision_b");

        let result = ops.create_repo(ms.database(), uid_b, &did_a, &handle_b, &cid, "r2");

        match result {
            Ok(()) => {
                let repo = ops.get_repo(uid_a).unwrap().unwrap();
                assert_eq!(repo.repo_root_cid, cid);
            }
            Err(MetastoreError::UserHashCollision { .. }) => {
                let repo = ops.get_repo(uid_a).unwrap().unwrap();
                assert_eq!(repo.repo_root_cid, cid);
                assert_eq!(repo.repo_rev.as_deref(), Some("r1"));
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn get_repo_meta_returns_raw_value() {
        let (_dir, ms) = open_fresh();
        let ops = ms.repo_ops();
        let user_id = uuid::Uuid::new_v4();
        let did = test_did("meta_raw");
        let handle = test_handle("meta_raw");
        let cid = test_cid_link(81);

        ops.create_repo(ms.database(), user_id, &did, &handle, &cid, "rev_meta")
            .unwrap();

        let (user_hash, value) = ops.get_repo_meta(user_id).unwrap().unwrap();
        assert_eq!(user_hash, UserHash::from_did(did.as_str()));
        assert_eq!(value.repo_rev, "rev_meta");
        assert_eq!(value.handle, "meta_raw.test.invalid");
        assert_eq!(value.status, RepoStatus::Active);
    }

    #[test]
    fn get_repo_meta_returns_none_for_unknown() {
        let (_dir, ms) = open_fresh();
        let ops = ms.repo_ops();
        assert!(ops.get_repo_meta(uuid::Uuid::new_v4()).unwrap().is_none());
    }

    #[test]
    fn write_repo_meta_via_batch() {
        let (_dir, ms) = open_fresh();
        let ops = ms.repo_ops();
        let user_id = uuid::Uuid::new_v4();
        let did = test_did("batch_write");
        let handle = test_handle("batch_write");
        let cid1 = test_cid_link(82);
        let cid2 = test_cid_link(83);

        ops.create_repo(ms.database(), user_id, &did, &handle, &cid1, "rev1")
            .unwrap();

        let (user_hash, mut value) = ops.get_repo_meta(user_id).unwrap().unwrap();
        value.repo_root_cid = cid_link_to_bytes(&cid2).unwrap();
        value.repo_rev = "rev2".to_string();

        let mut batch = ms.database().batch();
        ops.write_repo_meta(&mut batch, user_hash, &value);
        batch.commit().unwrap();

        let repo = ops.get_repo(user_id).unwrap().unwrap();
        assert_eq!(repo.repo_root_cid, cid2);
        assert_eq!(repo.repo_rev.as_deref(), Some("rev2"));
    }

    #[test]
    fn update_handle_swaps_lookup() {
        let (_dir, ms) = open_fresh();
        let ops = ms.repo_ops();
        let user_id = uuid::Uuid::new_v4();
        let did = test_did("handle_swap");
        let old_handle = test_handle("old_name");
        let new_handle = test_handle("new_name");
        let cid = test_cid_link(84);

        ops.create_repo(ms.database(), user_id, &did, &old_handle, &cid, "r1")
            .unwrap();
        assert!(ops.lookup_handle(&old_handle).unwrap().is_some());

        ops.update_handle(ms.database(), user_id, &new_handle)
            .unwrap();

        assert!(ops.lookup_handle(&old_handle).unwrap().is_none());
        assert_eq!(ops.lookup_handle(&new_handle).unwrap(), Some(user_id));

        let (_, meta) = ops.get_repo_meta(user_id).unwrap().unwrap();
        assert_eq!(meta.handle, "new_name.test.invalid");
    }

    #[test]
    fn update_handle_case_insensitive() {
        let (_dir, ms) = open_fresh();
        let ops = ms.repo_ops();
        let user_id = uuid::Uuid::new_v4();
        let did = test_did("handle_case");
        let handle = test_handle("original");
        let cid = test_cid_link(85);

        ops.create_repo(ms.database(), user_id, &did, &handle, &cid, "r1")
            .unwrap();

        let mixed_case = Handle::from("UPPER.TEST.INVALID".to_string());
        ops.update_handle(ms.database(), user_id, &mixed_case)
            .unwrap();

        let lower_lookup = Handle::from("upper.test.invalid".to_string());
        assert_eq!(ops.lookup_handle(&lower_lookup).unwrap(), Some(user_id));
        assert!(ops.lookup_handle(&handle).unwrap().is_none());
    }
}
