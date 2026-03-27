use dashmap::DashMap;
use fjall::Keyspace;
use parking_lot::Mutex;
use uuid::Uuid;

use super::MetastoreError;
use super::encoding::KeyBuilder;
use super::keys::{KeyTag, UserHash};

pub struct UserHashMap {
    cache: DashMap<Uuid, UserHash>,
    reverse: DashMap<UserHash, Uuid>,
    repo_data: Keyspace,
    write_guard: Mutex<()>,
}

impl UserHashMap {
    pub fn new(repo_data: Keyspace) -> Self {
        Self {
            cache: DashMap::new(),
            reverse: DashMap::new(),
            repo_data,
            write_guard: Mutex::new(()),
        }
    }

    pub fn load_all(&self) -> Result<usize, MetastoreError> {
        let prefix = [KeyTag::USER_MAP.raw()];
        let mut count = 0usize;

        self.repo_data.prefix(prefix).try_for_each(|guard| {
            let (key_bytes, value_bytes) = guard.into_inner().map_err(MetastoreError::Fjall)?;

            let uuid_bytes: [u8; 16] = key_bytes
                .get(1..17)
                .and_then(|s| <[u8; 16]>::try_from(s).ok())
                .ok_or(MetastoreError::CorruptData(
                    "user_map key too short for UUID",
                ))?;

            let hash_bytes: [u8; 8] = <[u8; 8]>::try_from(value_bytes.as_ref())
                .map_err(|_| MetastoreError::CorruptData("user_map value not 8 bytes"))?;

            let uuid = Uuid::from_bytes(uuid_bytes);
            let user_hash = UserHash::from_raw(u64::from_be_bytes(hash_bytes));

            let existing = self.reverse.get(&user_hash).map(|r| *r);
            if let Some(existing_uuid) = existing
                && existing_uuid != uuid
            {
                tracing::error!(
                    existing_uuid = %existing_uuid,
                    new_uuid = %uuid,
                    user_hash = %user_hash,
                    "user hash collision in persisted data"
                );
                return Err(MetastoreError::UserHashCollision {
                    hash: user_hash,
                    existing_uuid,
                    new_uuid: uuid,
                });
            }

            self.cache.insert(uuid, user_hash);
            self.reverse.insert(user_hash, uuid);
            count = count.saturating_add(1);

            if count.is_multiple_of(100_000) {
                tracing::info!(count, "loading user hash mappings");
            }

            Ok::<_, MetastoreError>(())
        })?;

        Ok(count)
    }

    pub fn stage_insert(
        &self,
        batch: &mut fjall::OwnedWriteBatch,
        uuid: Uuid,
        user_hash: UserHash,
    ) -> Result<(), MetastoreError> {
        let _guard = self.write_guard.lock();

        let existing = self.reverse.get(&user_hash).map(|r| *r);
        if let Some(existing_uuid) = existing
            && existing_uuid != uuid
        {
            tracing::error!(
                existing_uuid = %existing_uuid,
                new_uuid = %uuid,
                user_hash = %user_hash,
                "user hash collision detected"
            );
            return Err(MetastoreError::UserHashCollision {
                hash: user_hash,
                existing_uuid,
                new_uuid: uuid,
            });
        }

        let forward_key = KeyBuilder::new()
            .tag(KeyTag::USER_MAP)
            .fixed(uuid.as_bytes())
            .build();

        let reverse_key = KeyBuilder::new()
            .tag(KeyTag::USER_MAP_REVERSE)
            .u64(user_hash.raw())
            .build();

        batch.insert(
            &self.repo_data,
            forward_key.as_slice(),
            user_hash.raw().to_be_bytes(),
        );
        batch.insert(
            &self.repo_data,
            reverse_key.as_slice(),
            uuid.as_bytes().as_slice(),
        );

        self.cache.insert(uuid, user_hash);
        self.reverse.insert(user_hash, uuid);

        Ok(())
    }

    pub fn rollback_insert(&self, uuid: &Uuid, user_hash: &UserHash) {
        self.cache.remove(uuid);
        self.reverse.remove(user_hash);
    }

    pub fn stage_remove(
        &self,
        batch: &mut fjall::OwnedWriteBatch,
        uuid: &Uuid,
    ) -> Option<UserHash> {
        let _guard = self.write_guard.lock();

        let (_, user_hash) = self.cache.remove(uuid)?;
        self.reverse.remove(&user_hash);

        let forward_key = KeyBuilder::new()
            .tag(KeyTag::USER_MAP)
            .fixed(uuid.as_bytes())
            .build();
        let reverse_key = KeyBuilder::new()
            .tag(KeyTag::USER_MAP_REVERSE)
            .u64(user_hash.raw())
            .build();

        batch.remove(&self.repo_data, forward_key.as_slice());
        batch.remove(&self.repo_data, reverse_key.as_slice());

        Some(user_hash)
    }

    pub fn rollback_remove(&self, uuid: Uuid, user_hash: UserHash) {
        self.cache.insert(uuid, user_hash);
        self.reverse.insert(user_hash, uuid);
    }

    pub fn get(&self, uuid: &Uuid) -> Option<UserHash> {
        self.cache.get(uuid).map(|r| *r)
    }

    pub fn get_uuid(&self, user_hash: &UserHash) -> Option<Uuid> {
        self.reverse.get(user_hash).map(|r| *r)
    }

    pub fn len(&self) -> usize {
        self.cache.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_temp() -> (tempfile::TempDir, fjall::Database, Keyspace) {
        let dir = tempfile::TempDir::new().unwrap();
        let db = fjall::Database::builder(dir.path()).open().unwrap();
        let ks = db
            .keyspace("repo_data", fjall::KeyspaceCreateOptions::default)
            .unwrap();
        (dir, db, ks)
    }

    #[test]
    fn insert_and_lookup() {
        let (_dir, db, ks) = open_temp();
        let map = UserHashMap::new(ks);

        let uuid = Uuid::new_v4();
        let hash = UserHash::from_did("did:plc:test123");

        let mut batch = db.batch();
        map.stage_insert(&mut batch, uuid, hash).unwrap();
        batch.commit().unwrap();

        assert_eq!(map.get(&uuid), Some(hash));
        assert_eq!(map.get_uuid(&hash), Some(uuid));
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn cache_populated_at_stage_time() {
        let (_dir, db, ks) = open_temp();
        let map = UserHashMap::new(ks);

        let uuid = Uuid::new_v4();
        let hash = UserHash::from_did("did:plc:staged_only");

        let mut batch = db.batch();
        map.stage_insert(&mut batch, uuid, hash).unwrap();

        assert_eq!(map.get(&uuid), Some(hash));
        assert_eq!(map.get_uuid(&hash), Some(uuid));
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn rollback_removes_from_cache() {
        let (_dir, db, ks) = open_temp();
        let map = UserHashMap::new(ks);

        let uuid = Uuid::new_v4();
        let hash = UserHash::from_did("did:plc:rollback");

        let mut batch = db.batch();
        map.stage_insert(&mut batch, uuid, hash).unwrap();
        assert_eq!(map.len(), 1);

        map.rollback_insert(&uuid, &hash);
        assert!(map.is_empty());
        assert_eq!(map.get(&uuid), None);
        assert_eq!(map.get_uuid(&hash), None);

        drop(batch);
    }

    #[test]
    fn load_all_after_reopen() {
        let dir = tempfile::TempDir::new().unwrap();
        let uuid = Uuid::new_v4();
        let hash = UserHash::from_did("did:plc:persist");

        {
            let db = fjall::Database::builder(dir.path()).open().unwrap();
            let ks = db
                .keyspace("repo_data", fjall::KeyspaceCreateOptions::default)
                .unwrap();
            let map = UserHashMap::new(ks);
            let mut batch = db.batch();
            map.stage_insert(&mut batch, uuid, hash).unwrap();
            batch.commit().unwrap();
            db.persist(fjall::PersistMode::SyncData).unwrap();
        }

        {
            let db = fjall::Database::builder(dir.path()).open().unwrap();
            let ks = db
                .keyspace("repo_data", fjall::KeyspaceCreateOptions::default)
                .unwrap();
            let map = UserHashMap::new(ks);
            let count = map.load_all().unwrap();
            assert_eq!(count, 1);
            assert_eq!(map.get(&uuid), Some(hash));
            assert_eq!(map.get_uuid(&hash), Some(uuid));
        }
    }

    #[test]
    fn multiple_users() {
        let (_dir, db, ks) = open_temp();
        let map = UserHashMap::new(ks);

        let pairs: Vec<_> = (0..10)
            .map(|i| {
                let uuid = Uuid::new_v4();
                let hash = UserHash::from_did(&format!("did:plc:user{i}"));
                (uuid, hash)
            })
            .collect();

        let mut batch = db.batch();
        pairs.iter().for_each(|(uuid, hash)| {
            map.stage_insert(&mut batch, *uuid, *hash).unwrap();
        });
        batch.commit().unwrap();

        assert_eq!(map.len(), 10);
        pairs.iter().for_each(|(uuid, hash)| {
            assert_eq!(map.get(uuid), Some(*hash));
            assert_eq!(map.get_uuid(hash), Some(*uuid));
        });
    }

    #[test]
    fn stage_insert_idempotent_for_same_uuid() {
        let (_dir, db, ks) = open_temp();
        let map = UserHashMap::new(ks);

        let uuid = Uuid::new_v4();
        let hash = UserHash::from_did("did:plc:same");

        let mut batch = db.batch();
        map.stage_insert(&mut batch, uuid, hash).unwrap();
        batch.commit().unwrap();

        let mut batch2 = db.batch();
        map.stage_insert(&mut batch2, uuid, hash).unwrap();
    }

    #[test]
    fn stage_insert_rejects_collision() {
        let (_dir, db, ks) = open_temp();
        let map = UserHashMap::new(ks);

        let uuid_a = Uuid::new_v4();
        let uuid_b = Uuid::new_v4();
        let same_hash = UserHash::from_raw(0xDEAD_BEEF);

        let mut batch = db.batch();
        map.stage_insert(&mut batch, uuid_a, same_hash).unwrap();
        batch.commit().unwrap();

        let mut batch2 = db.batch();
        let result = map.stage_insert(&mut batch2, uuid_b, same_hash);
        assert!(matches!(
            result,
            Err(MetastoreError::UserHashCollision { .. })
        ));
    }

    #[test]
    fn stage_remove_clears_cache_and_persists() {
        let dir = tempfile::TempDir::new().unwrap();
        let uuid = Uuid::new_v4();
        let hash = UserHash::from_did("did:plc:removable");

        let db = fjall::Database::builder(dir.path()).open().unwrap();
        let ks = db
            .keyspace("repo_data", fjall::KeyspaceCreateOptions::default)
            .unwrap();
        let map = UserHashMap::new(ks);

        let mut batch = db.batch();
        map.stage_insert(&mut batch, uuid, hash).unwrap();
        batch.commit().unwrap();
        assert_eq!(map.len(), 1);

        let mut remove_batch = db.batch();
        let removed = map.stage_remove(&mut remove_batch, &uuid);
        assert_eq!(removed, Some(hash));
        remove_batch.commit().unwrap();

        assert!(map.is_empty());
        assert_eq!(map.get(&uuid), None);
        assert_eq!(map.get_uuid(&hash), None);

        db.persist(fjall::PersistMode::SyncData).unwrap();
        drop(map);
        drop(db);

        let db2 = fjall::Database::builder(dir.path()).open().unwrap();
        let ks2 = db2
            .keyspace("repo_data", fjall::KeyspaceCreateOptions::default)
            .unwrap();
        let map2 = UserHashMap::new(ks2);
        assert_eq!(map2.load_all().unwrap(), 0);
    }

    #[test]
    fn stage_remove_returns_none_for_unknown() {
        let (_dir, db, ks) = open_temp();
        let map = UserHashMap::new(ks);
        let mut batch = db.batch();
        assert_eq!(map.stage_remove(&mut batch, &Uuid::new_v4()), None);
    }

    #[test]
    fn rollback_remove_restores_cache() {
        let (_dir, db, ks) = open_temp();
        let map = UserHashMap::new(ks);

        let uuid = Uuid::new_v4();
        let hash = UserHash::from_did("did:plc:rollback_remove");

        let mut batch = db.batch();
        map.stage_insert(&mut batch, uuid, hash).unwrap();
        batch.commit().unwrap();

        let mut remove_batch = db.batch();
        map.stage_remove(&mut remove_batch, &uuid);
        assert!(map.is_empty());

        map.rollback_remove(uuid, hash);
        assert_eq!(map.get(&uuid), Some(hash));
        assert_eq!(map.get_uuid(&hash), Some(uuid));
        assert_eq!(map.len(), 1);

        drop(remove_batch);
    }

    #[test]
    fn stage_remove_then_reinsert_same_did() {
        let (_dir, db, ks) = open_temp();
        let map = UserHashMap::new(ks);

        let uuid_a = Uuid::new_v4();
        let hash = UserHash::from_did("did:plc:reinsert");

        let mut batch = db.batch();
        map.stage_insert(&mut batch, uuid_a, hash).unwrap();
        batch.commit().unwrap();

        let mut remove_batch = db.batch();
        map.stage_remove(&mut remove_batch, &uuid_a);
        remove_batch.commit().unwrap();

        let uuid_b = Uuid::new_v4();
        let mut batch2 = db.batch();
        map.stage_insert(&mut batch2, uuid_b, hash).unwrap();
        batch2.commit().unwrap();

        assert_eq!(map.get(&uuid_b), Some(hash));
        assert_eq!(map.get_uuid(&hash), Some(uuid_b));
        assert_eq!(map.get(&uuid_a), None);
    }
}
