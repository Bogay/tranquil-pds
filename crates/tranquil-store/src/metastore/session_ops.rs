use std::sync::Arc;

use chrono::{DateTime, Utc};
use fjall::{Database, Keyspace};
use uuid::Uuid;

use super::MetastoreError;
use super::keys::UserHash;
use super::scan::point_lookup;
use super::sessions::{
    AppPasswordValue, SessionIndexValue, SessionTokenValue, deserialize_id_counter_value,
    deserialize_last_reauth_value, deserialize_used_refresh_value, login_type_to_u8,
    privilege_to_u8, serialize_by_did_value, serialize_id_counter_value,
    serialize_last_reauth_value, serialize_used_refresh_value, session_app_password_key,
    session_app_password_prefix, session_by_access_key, session_by_did_key, session_by_did_prefix,
    session_by_refresh_key, session_id_counter_key, session_last_reauth_key, session_primary_key,
    session_used_refresh_key, u8_to_login_type, u8_to_privilege,
};
use super::user_hash::UserHashMap;
use super::users::UserValue;

use tranquil_db_traits::{
    AppPasswordCreate, AppPasswordRecord, LoginType, RefreshSessionResult, SessionForRefresh,
    SessionId, SessionListItem, SessionMfaStatus, SessionRefreshData, SessionToken,
    SessionTokenCreate,
};
use tranquil_types::Did;

pub struct SessionOps {
    db: Database,
    auth: Keyspace,
    users: Keyspace,
    user_hashes: Arc<UserHashMap>,
    counter_lock: Arc<parking_lot::Mutex<()>>,
}

impl SessionOps {
    pub fn new(
        db: Database,
        auth: Keyspace,
        users: Keyspace,
        user_hashes: Arc<UserHashMap>,
        counter_lock: Arc<parking_lot::Mutex<()>>,
    ) -> Self {
        Self {
            db,
            auth,
            users,
            user_hashes,
            counter_lock,
        }
    }

    fn resolve_user_hash_from_did(&self, did: &str) -> UserHash {
        UserHash::from_did(did)
    }

    fn resolve_user_hash_from_uuid(&self, user_id: Uuid) -> Result<UserHash, MetastoreError> {
        self.user_hashes
            .get(&user_id)
            .ok_or(MetastoreError::InvalidInput("unknown user_id"))
    }

    fn next_session_id(&self) -> Result<i32, MetastoreError> {
        let _guard = self.counter_lock.lock();
        let counter_key = session_id_counter_key();
        let current = self
            .auth
            .get(counter_key.as_slice())
            .map_err(MetastoreError::Fjall)?
            .and_then(|raw| deserialize_id_counter_value(&raw))
            .unwrap_or(0);
        let next = current.saturating_add(1);
        self.auth
            .insert(counter_key.as_slice(), serialize_id_counter_value(next))
            .map_err(MetastoreError::Fjall)?;
        Ok(next)
    }

    fn value_to_session_token(
        &self,
        v: &SessionTokenValue,
    ) -> Result<SessionToken, MetastoreError> {
        Ok(SessionToken {
            id: SessionId::new(v.id),
            did: Did::new(v.did.clone())
                .map_err(|_| MetastoreError::CorruptData("invalid session did"))?,
            access_jti: v.access_jti.clone(),
            refresh_jti: v.refresh_jti.clone(),
            access_expires_at: DateTime::from_timestamp_millis(v.access_expires_at_ms)
                .unwrap_or_default(),
            refresh_expires_at: DateTime::from_timestamp_millis(v.refresh_expires_at_ms)
                .unwrap_or_default(),
            login_type: u8_to_login_type(v.login_type).unwrap_or(LoginType::Modern),
            mfa_verified: v.mfa_verified,
            scope: v.scope.clone(),
            controller_did: v
                .controller_did
                .as_ref()
                .and_then(|d| Did::new(d.clone()).ok()),
            app_password_name: v.app_password_name.clone(),
            created_at: DateTime::from_timestamp_millis(v.created_at_ms).unwrap_or_default(),
            updated_at: DateTime::from_timestamp_millis(v.updated_at_ms).unwrap_or_default(),
        })
    }

    fn value_to_app_password(
        &self,
        v: &AppPasswordValue,
    ) -> Result<AppPasswordRecord, MetastoreError> {
        Ok(AppPasswordRecord {
            id: v.id,
            user_id: v.user_id,
            name: v.name.clone(),
            password_hash: v.password_hash.clone(),
            created_at: DateTime::from_timestamp_millis(v.created_at_ms).unwrap_or_default(),
            privilege: u8_to_privilege(v.privilege)
                .unwrap_or(tranquil_db_traits::AppPasswordPrivilege::Standard),
            scopes: v.scopes.clone(),
            created_by_controller_did: v
                .created_by_controller_did
                .as_ref()
                .and_then(|d| Did::new(d.clone()).ok()),
        })
    }

    fn load_session_by_id(
        &self,
        session_id: i32,
    ) -> Result<Option<SessionTokenValue>, MetastoreError> {
        let key = session_primary_key(session_id);
        point_lookup(
            &self.auth,
            key.as_slice(),
            SessionTokenValue::deserialize,
            "corrupt session token",
        )
    }

    fn load_user_value(&self, user_hash: UserHash) -> Result<Option<UserValue>, MetastoreError> {
        let key = super::encoding::KeyBuilder::new()
            .tag(super::keys::KeyTag::USER_PRIMARY)
            .u64(user_hash.raw())
            .build();
        point_lookup(
            &self.users,
            key.as_slice(),
            UserValue::deserialize,
            "corrupt user value",
        )
    }

    fn delete_session_indexes(
        &self,
        batch: &mut fjall::OwnedWriteBatch,
        session: &SessionTokenValue,
    ) {
        let user_hash = self.resolve_user_hash_from_did(&session.did);
        batch.remove(&self.auth, session_primary_key(session.id).as_slice());
        batch.remove(
            &self.auth,
            session_by_access_key(&session.access_jti).as_slice(),
        );
        batch.remove(
            &self.auth,
            session_by_refresh_key(&session.refresh_jti).as_slice(),
        );
        batch.remove(
            &self.auth,
            session_by_did_key(user_hash, session.id).as_slice(),
        );
    }

    fn collect_sessions_for_did(
        &self,
        user_hash: UserHash,
    ) -> Result<Vec<SessionTokenValue>, MetastoreError> {
        let prefix = session_by_did_prefix(user_hash);
        self.auth
            .prefix(prefix.as_slice())
            .try_fold(Vec::new(), |mut acc, guard| {
                let (key_bytes, _) = guard.into_inner().map_err(MetastoreError::Fjall)?;
                let mut reader = super::encoding::KeyReader::new(&key_bytes);
                let _tag = reader.tag();
                let _hash = reader.u64();
                let sid_bytes: [u8; 4] = reader
                    .remaining()
                    .try_into()
                    .map_err(|_| MetastoreError::CorruptData("session_by_did key truncated"))?;
                let sid = i32::from_be_bytes(sid_bytes);
                match self.load_session_by_id(sid)? {
                    Some(session) => {
                        acc.push(session);
                        Ok::<_, MetastoreError>(acc)
                    }
                    None => Ok(acc),
                }
            })
    }

    pub fn create_session(&self, data: &SessionTokenCreate) -> Result<SessionId, MetastoreError> {
        let user_hash = self.resolve_user_hash_from_did(data.did.as_str());
        let session_id = self.next_session_id()?;
        let now_ms = Utc::now().timestamp_millis();

        let value = SessionTokenValue {
            id: session_id,
            did: data.did.to_string(),
            access_jti: data.access_jti.clone(),
            refresh_jti: data.refresh_jti.clone(),
            access_expires_at_ms: data.access_expires_at.timestamp_millis(),
            refresh_expires_at_ms: data.refresh_expires_at.timestamp_millis(),
            login_type: login_type_to_u8(data.login_type),
            mfa_verified: data.mfa_verified,
            scope: data.scope.clone(),
            controller_did: data.controller_did.as_ref().map(|d| d.to_string()),
            app_password_name: data.app_password_name.clone(),
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
        };

        let access_index = SessionIndexValue {
            user_hash: user_hash.raw(),
            session_id,
        };
        let refresh_index = SessionIndexValue {
            user_hash: user_hash.raw(),
            session_id,
        };

        let mut batch = self.db.batch();
        batch.insert(
            &self.auth,
            session_primary_key(session_id).as_slice(),
            value.serialize(),
        );
        batch.insert(
            &self.auth,
            session_by_access_key(&data.access_jti).as_slice(),
            access_index.serialize(value.refresh_expires_at_ms),
        );
        batch.insert(
            &self.auth,
            session_by_refresh_key(&data.refresh_jti).as_slice(),
            refresh_index.serialize(value.refresh_expires_at_ms),
        );
        batch.insert(
            &self.auth,
            session_by_did_key(user_hash, session_id).as_slice(),
            serialize_by_did_value(value.refresh_expires_at_ms),
        );
        batch.commit().map_err(MetastoreError::Fjall)?;

        Ok(SessionId::new(session_id))
    }

    pub fn get_session_by_access_jti(
        &self,
        access_jti: &str,
    ) -> Result<Option<SessionToken>, MetastoreError> {
        let index_key = session_by_access_key(access_jti);
        let index_val: Option<SessionIndexValue> = point_lookup(
            &self.auth,
            index_key.as_slice(),
            SessionIndexValue::deserialize,
            "corrupt session access index",
        )?;

        match index_val {
            Some(idx) => {
                let session = self.load_session_by_id(idx.session_id)?;
                session.map(|v| self.value_to_session_token(&v)).transpose()
            }
            None => Ok(None),
        }
    }

    pub fn get_session_for_refresh(
        &self,
        refresh_jti: &str,
    ) -> Result<Option<SessionForRefresh>, MetastoreError> {
        let index_key = session_by_refresh_key(refresh_jti);
        let index_val: Option<SessionIndexValue> = point_lookup(
            &self.auth,
            index_key.as_slice(),
            SessionIndexValue::deserialize,
            "corrupt session refresh index",
        )?;

        let idx = match index_val {
            Some(idx) => idx,
            None => return Ok(None),
        };

        let session = match self.load_session_by_id(idx.session_id)? {
            Some(s) => s,
            None => return Ok(None),
        };

        let now_ms = Utc::now().timestamp_millis();
        if session.refresh_expires_at_ms <= now_ms {
            return Ok(None);
        }

        let user_hash = self.resolve_user_hash_from_did(&session.did);
        let user_value = self.load_user_value(user_hash)?;

        match user_value {
            Some(user) => Ok(Some(SessionForRefresh {
                id: SessionId::new(session.id),
                did: Did::new(session.did)
                    .map_err(|_| MetastoreError::CorruptData("invalid session did"))?,
                scope: session.scope,
                controller_did: session.controller_did.and_then(|d| Did::new(d).ok()),
                key_bytes: user.key_bytes,
                encryption_version: user.encryption_version,
            })),
            None => Ok(None),
        }
    }

    pub fn update_session_tokens(
        &self,
        session_id: SessionId,
        new_access_jti: &str,
        new_refresh_jti: &str,
        new_access_expires_at: DateTime<Utc>,
        new_refresh_expires_at: DateTime<Utc>,
    ) -> Result<(), MetastoreError> {
        let mut session = self
            .load_session_by_id(session_id.as_i32())?
            .ok_or(MetastoreError::InvalidInput("session not found"))?;

        let user_hash = self.resolve_user_hash_from_did(&session.did);
        let old_access_jti = session.access_jti.clone();
        let old_refresh_jti = session.refresh_jti.clone();

        session.access_jti = new_access_jti.to_owned();
        session.refresh_jti = new_refresh_jti.to_owned();
        session.access_expires_at_ms = new_access_expires_at.timestamp_millis();
        session.refresh_expires_at_ms = new_refresh_expires_at.timestamp_millis();
        session.updated_at_ms = Utc::now().timestamp_millis();

        let new_access_index = SessionIndexValue {
            user_hash: user_hash.raw(),
            session_id: session.id,
        };
        let new_refresh_index = SessionIndexValue {
            user_hash: user_hash.raw(),
            session_id: session.id,
        };

        let mut batch = self.db.batch();
        batch.remove(
            &self.auth,
            session_by_access_key(&old_access_jti).as_slice(),
        );
        batch.remove(
            &self.auth,
            session_by_refresh_key(&old_refresh_jti).as_slice(),
        );
        batch.insert(
            &self.auth,
            session_primary_key(session.id).as_slice(),
            session.serialize(),
        );
        batch.insert(
            &self.auth,
            session_by_access_key(new_access_jti).as_slice(),
            new_access_index.serialize(session.refresh_expires_at_ms),
        );
        batch.insert(
            &self.auth,
            session_by_refresh_key(new_refresh_jti).as_slice(),
            new_refresh_index.serialize(session.refresh_expires_at_ms),
        );
        batch.insert(
            &self.auth,
            session_by_did_key(user_hash, session.id).as_slice(),
            serialize_by_did_value(session.refresh_expires_at_ms),
        );
        batch.commit().map_err(MetastoreError::Fjall)?;

        Ok(())
    }

    pub fn delete_session_by_access_jti(&self, access_jti: &str) -> Result<u64, MetastoreError> {
        let index_key = session_by_access_key(access_jti);
        let index_val: Option<SessionIndexValue> = point_lookup(
            &self.auth,
            index_key.as_slice(),
            SessionIndexValue::deserialize,
            "corrupt session access index",
        )?;

        let idx = match index_val {
            Some(idx) => idx,
            None => return Ok(0),
        };

        let session = match self.load_session_by_id(idx.session_id)? {
            Some(s) => s,
            None => return Ok(0),
        };

        let mut batch = self.db.batch();
        self.delete_session_indexes(&mut batch, &session);
        batch.commit().map_err(MetastoreError::Fjall)?;

        Ok(1)
    }

    pub fn delete_session_by_id(&self, session_id: SessionId) -> Result<u64, MetastoreError> {
        let session = match self.load_session_by_id(session_id.as_i32())? {
            Some(s) => s,
            None => return Ok(0),
        };

        let mut batch = self.db.batch();
        self.delete_session_indexes(&mut batch, &session);
        batch.commit().map_err(MetastoreError::Fjall)?;

        Ok(1)
    }

    pub fn delete_sessions_by_did(&self, did: &Did) -> Result<u64, MetastoreError> {
        let user_hash = self.resolve_user_hash_from_did(did.as_str());
        let sessions = self.collect_sessions_for_did(user_hash)?;

        let count = u64::try_from(sessions.len()).unwrap_or(u64::MAX);
        match count {
            0 => Ok(0),
            _ => {
                let mut batch = self.db.batch();
                sessions.iter().for_each(|session| {
                    self.delete_session_indexes(&mut batch, session);
                });
                batch.commit().map_err(MetastoreError::Fjall)?;
                Ok(count)
            }
        }
    }

    pub fn delete_sessions_by_did_except_jti(
        &self,
        did: &Did,
        except_jti: &str,
    ) -> Result<u64, MetastoreError> {
        let user_hash = self.resolve_user_hash_from_did(did.as_str());
        let sessions = self.collect_sessions_for_did(user_hash)?;

        let to_delete: Vec<_> = sessions
            .iter()
            .filter(|s| s.access_jti != except_jti)
            .collect();

        let count = u64::try_from(to_delete.len()).unwrap_or(u64::MAX);
        match count {
            0 => Ok(0),
            _ => {
                let mut batch = self.db.batch();
                to_delete.iter().for_each(|session| {
                    self.delete_session_indexes(&mut batch, session);
                });
                batch.commit().map_err(MetastoreError::Fjall)?;
                Ok(count)
            }
        }
    }

    pub fn list_sessions_by_did(&self, did: &Did) -> Result<Vec<SessionListItem>, MetastoreError> {
        let user_hash = self.resolve_user_hash_from_did(did.as_str());
        let now_ms = Utc::now().timestamp_millis();
        let mut sessions = self.collect_sessions_for_did(user_hash)?;
        sessions.retain(|s| s.refresh_expires_at_ms > now_ms);
        sessions.sort_by_key(|s| std::cmp::Reverse(s.created_at_ms));

        Ok(sessions
            .iter()
            .map(|s| SessionListItem {
                id: SessionId::new(s.id),
                access_jti: s.access_jti.clone(),
                created_at: DateTime::from_timestamp_millis(s.created_at_ms).unwrap_or_default(),
                refresh_expires_at: DateTime::from_timestamp_millis(s.refresh_expires_at_ms)
                    .unwrap_or_default(),
            })
            .collect())
    }

    pub fn get_session_access_jti_by_id(
        &self,
        session_id: SessionId,
        did: &Did,
    ) -> Result<Option<String>, MetastoreError> {
        self.load_session_by_id(session_id.as_i32())?
            .filter(|s| s.did == did.as_str())
            .map(|s| Ok(s.access_jti))
            .transpose()
    }

    pub fn delete_sessions_by_app_password(
        &self,
        did: &Did,
        app_password_name: &str,
    ) -> Result<u64, MetastoreError> {
        let user_hash = self.resolve_user_hash_from_did(did.as_str());
        let sessions = self.collect_sessions_for_did(user_hash)?;

        let to_delete: Vec<_> = sessions
            .iter()
            .filter(|s| s.app_password_name.as_deref() == Some(app_password_name))
            .collect();

        let count = u64::try_from(to_delete.len()).unwrap_or(u64::MAX);
        match count {
            0 => Ok(0),
            _ => {
                let mut batch = self.db.batch();
                to_delete.iter().for_each(|session| {
                    self.delete_session_indexes(&mut batch, session);
                });
                batch.commit().map_err(MetastoreError::Fjall)?;
                Ok(count)
            }
        }
    }

    pub fn get_session_jtis_by_app_password(
        &self,
        did: &Did,
        app_password_name: &str,
    ) -> Result<Vec<String>, MetastoreError> {
        let user_hash = self.resolve_user_hash_from_did(did.as_str());
        let sessions = self.collect_sessions_for_did(user_hash)?;

        Ok(sessions
            .iter()
            .filter(|s| s.app_password_name.as_deref() == Some(app_password_name))
            .map(|s| s.access_jti.clone())
            .collect())
    }

    pub fn check_refresh_token_used(
        &self,
        refresh_jti: &str,
    ) -> Result<Option<SessionId>, MetastoreError> {
        let key = session_used_refresh_key(refresh_jti);
        match self
            .auth
            .get(key.as_slice())
            .map_err(MetastoreError::Fjall)?
        {
            Some(raw) => Ok(deserialize_used_refresh_value(&raw).map(SessionId::new)),
            None => Ok(None),
        }
    }

    pub fn mark_refresh_token_used(
        &self,
        refresh_jti: &str,
        session_id: SessionId,
    ) -> Result<bool, MetastoreError> {
        let key = session_used_refresh_key(refresh_jti);
        let existing = self
            .auth
            .get(key.as_slice())
            .map_err(MetastoreError::Fjall)?;

        match existing {
            Some(_) => Ok(false),
            None => {
                let session = self.load_session_by_id(session_id.as_i32())?;
                let expires_at_ms = session
                    .map(|s| s.refresh_expires_at_ms)
                    .unwrap_or(Utc::now().timestamp_millis().saturating_add(86_400_000));

                self.auth
                    .insert(
                        key.as_slice(),
                        serialize_used_refresh_value(expires_at_ms, session_id.as_i32()),
                    )
                    .map_err(MetastoreError::Fjall)?;
                Ok(true)
            }
        }
    }

    pub fn list_app_passwords(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<AppPasswordRecord>, MetastoreError> {
        let user_hash = self.resolve_user_hash_from_uuid(user_id)?;
        let prefix = session_app_password_prefix(user_hash);

        let mut records: Vec<AppPasswordRecord> =
            self.auth
                .prefix(prefix.as_slice())
                .try_fold(Vec::new(), |mut acc, guard| {
                    let (_, val_bytes) = guard.into_inner().map_err(MetastoreError::Fjall)?;
                    let val = AppPasswordValue::deserialize(&val_bytes)
                        .ok_or(MetastoreError::CorruptData("corrupt app password"))?;
                    acc.push(self.value_to_app_password(&val)?);
                    Ok::<_, MetastoreError>(acc)
                })?;

        records.sort_by_key(|r| std::cmp::Reverse(r.created_at));
        Ok(records)
    }

    pub fn get_app_passwords_for_login(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<AppPasswordRecord>, MetastoreError> {
        let mut passwords = self.list_app_passwords(user_id)?;
        passwords.truncate(20);
        Ok(passwords)
    }

    pub fn get_app_password_by_name(
        &self,
        user_id: Uuid,
        name: &str,
    ) -> Result<Option<AppPasswordRecord>, MetastoreError> {
        let user_hash = self.resolve_user_hash_from_uuid(user_id)?;
        let key = session_app_password_key(user_hash, name);

        let val: Option<AppPasswordValue> = point_lookup(
            &self.auth,
            key.as_slice(),
            AppPasswordValue::deserialize,
            "corrupt app password",
        )?;

        val.map(|v| self.value_to_app_password(&v)).transpose()
    }

    pub fn create_app_password(&self, data: &AppPasswordCreate) -> Result<Uuid, MetastoreError> {
        let user_hash = self.resolve_user_hash_from_uuid(data.user_id)?;
        let id = Uuid::new_v4();
        let now_ms = Utc::now().timestamp_millis();

        let value = AppPasswordValue {
            id,
            user_id: data.user_id,
            name: data.name.clone(),
            password_hash: data.password_hash.clone(),
            created_at_ms: now_ms,
            privilege: privilege_to_u8(data.privilege),
            scopes: data.scopes.clone(),
            created_by_controller_did: data
                .created_by_controller_did
                .as_ref()
                .map(|d| d.to_string()),
        };

        let key = session_app_password_key(user_hash, &data.name);
        self.auth
            .insert(key.as_slice(), value.serialize())
            .map_err(MetastoreError::Fjall)?;

        Ok(id)
    }

    pub fn delete_app_password(&self, user_id: Uuid, name: &str) -> Result<u64, MetastoreError> {
        let user_hash = self.resolve_user_hash_from_uuid(user_id)?;
        let key = session_app_password_key(user_hash, name);

        let exists = self
            .auth
            .get(key.as_slice())
            .map_err(MetastoreError::Fjall)?
            .is_some();

        match exists {
            true => {
                self.auth
                    .remove(key.as_slice())
                    .map_err(MetastoreError::Fjall)?;
                Ok(1)
            }
            false => Ok(0),
        }
    }

    pub fn delete_app_passwords_by_controller(
        &self,
        did: &Did,
        controller_did: &Did,
    ) -> Result<u64, MetastoreError> {
        let user_hash = self.resolve_user_hash_from_did(did.as_str());
        let user_uuid = self
            .user_hashes
            .get_uuid(&user_hash)
            .ok_or(MetastoreError::InvalidInput("unknown did"))?;
        let _ = user_uuid;

        let prefix = session_app_password_prefix(user_hash);
        let controller_str = controller_did.to_string();

        let keys_to_remove: Vec<_> = self
            .auth
            .prefix(prefix.as_slice())
            .filter_map(|guard| {
                let (key_bytes, val_bytes) = guard.into_inner().ok()?;
                let val = AppPasswordValue::deserialize(&val_bytes)?;
                match val.created_by_controller_did.as_deref() == Some(controller_str.as_str()) {
                    true => Some(key_bytes.to_vec()),
                    false => None,
                }
            })
            .collect();

        let count = u64::try_from(keys_to_remove.len()).unwrap_or(u64::MAX);
        match count {
            0 => Ok(0),
            _ => {
                let mut batch = self.db.batch();
                keys_to_remove.iter().for_each(|key| {
                    batch.remove(&self.auth, key);
                });
                batch.commit().map_err(MetastoreError::Fjall)?;
                Ok(count)
            }
        }
    }

    pub fn get_last_reauth_at(&self, did: &Did) -> Result<Option<DateTime<Utc>>, MetastoreError> {
        let user_hash = self.resolve_user_hash_from_did(did.as_str());
        let key = session_last_reauth_key(user_hash);

        match self
            .auth
            .get(key.as_slice())
            .map_err(MetastoreError::Fjall)?
        {
            Some(raw) => {
                Ok(deserialize_last_reauth_value(&raw).and_then(DateTime::from_timestamp_millis))
            }
            None => Ok(None),
        }
    }

    pub fn update_last_reauth(&self, did: &Did) -> Result<DateTime<Utc>, MetastoreError> {
        let user_hash = self.resolve_user_hash_from_did(did.as_str());
        let now = Utc::now();
        let key = session_last_reauth_key(user_hash);

        self.auth
            .insert(
                key.as_slice(),
                serialize_last_reauth_value(now.timestamp_millis()),
            )
            .map_err(MetastoreError::Fjall)?;

        Ok(now)
    }

    pub fn get_session_mfa_status(
        &self,
        did: &Did,
    ) -> Result<Option<SessionMfaStatus>, MetastoreError> {
        let user_hash = self.resolve_user_hash_from_did(did.as_str());
        let mut sessions = self.collect_sessions_for_did(user_hash)?;
        sessions.sort_by_key(|s| std::cmp::Reverse(s.created_at_ms));

        let latest = match sessions.first() {
            Some(s) => s,
            None => return Ok(None),
        };

        let last_reauth_at = self.get_last_reauth_at(did)?;

        Ok(Some(SessionMfaStatus {
            login_type: u8_to_login_type(latest.login_type).unwrap_or(LoginType::Modern),
            mfa_verified: latest.mfa_verified,
            last_reauth_at,
        }))
    }

    pub fn update_mfa_verified(&self, did: &Did) -> Result<(), MetastoreError> {
        let user_hash = self.resolve_user_hash_from_did(did.as_str());
        let sessions = self.collect_sessions_for_did(user_hash)?;
        let now = Utc::now();
        let now_ms = now.timestamp_millis();

        let mut batch = self.db.batch();
        sessions.iter().for_each(|session| {
            let mut updated = session.clone();
            updated.mfa_verified = true;
            updated.updated_at_ms = now_ms;
            batch.insert(
                &self.auth,
                session_primary_key(updated.id).as_slice(),
                updated.serialize(),
            );
        });

        let reauth_key = session_last_reauth_key(user_hash);
        batch.insert(
            &self.auth,
            reauth_key.as_slice(),
            serialize_last_reauth_value(now_ms),
        );

        batch.commit().map_err(MetastoreError::Fjall)?;
        Ok(())
    }

    pub fn get_app_password_hashes_by_did(&self, did: &Did) -> Result<Vec<String>, MetastoreError> {
        let user_hash = self.resolve_user_hash_from_did(did.as_str());
        match self.user_hashes.get_uuid(&user_hash) {
            Some(_) => {}
            None => return Ok(Vec::new()),
        };

        let prefix = session_app_password_prefix(user_hash);

        self.auth
            .prefix(prefix.as_slice())
            .try_fold(Vec::new(), |mut acc, guard| {
                let (_, val_bytes) = guard.into_inner().map_err(MetastoreError::Fjall)?;
                let val = AppPasswordValue::deserialize(&val_bytes)
                    .ok_or(MetastoreError::CorruptData("corrupt app password"))?;
                acc.push(val.password_hash);
                Ok::<_, MetastoreError>(acc)
            })
    }

    pub fn refresh_session_atomic(
        &self,
        data: &SessionRefreshData,
    ) -> Result<RefreshSessionResult, MetastoreError> {
        let used_key = session_used_refresh_key(&data.old_refresh_jti);
        let already_used = self
            .auth
            .get(used_key.as_slice())
            .map_err(MetastoreError::Fjall)?;

        if already_used.is_some() {
            let mut batch = self.db.batch();
            let session = self.load_session_by_id(data.session_id.as_i32())?;
            if let Some(s) = session {
                self.delete_session_indexes(&mut batch, &s);
            }
            batch.commit().map_err(MetastoreError::Fjall)?;
            return Ok(RefreshSessionResult::TokenAlreadyUsed);
        }

        let mut session = match self.load_session_by_id(data.session_id.as_i32())? {
            Some(s) => s,
            None => return Ok(RefreshSessionResult::ConcurrentRefresh),
        };

        if session.refresh_jti != data.old_refresh_jti {
            return Ok(RefreshSessionResult::ConcurrentRefresh);
        }

        let user_hash = self.resolve_user_hash_from_did(&session.did);
        let old_access_jti = session.access_jti.clone();
        let old_refresh_jti = session.refresh_jti.clone();

        session.access_jti = data.new_access_jti.clone();
        session.refresh_jti = data.new_refresh_jti.clone();
        session.access_expires_at_ms = data.new_access_expires_at.timestamp_millis();
        session.refresh_expires_at_ms = data.new_refresh_expires_at.timestamp_millis();
        session.updated_at_ms = Utc::now().timestamp_millis();

        let new_access_index = SessionIndexValue {
            user_hash: user_hash.raw(),
            session_id: session.id,
        };
        let new_refresh_index = SessionIndexValue {
            user_hash: user_hash.raw(),
            session_id: session.id,
        };

        let mut batch = self.db.batch();

        batch.insert(
            &self.auth,
            used_key.as_slice(),
            serialize_used_refresh_value(session.refresh_expires_at_ms, session.id),
        );

        batch.remove(
            &self.auth,
            session_by_access_key(&old_access_jti).as_slice(),
        );
        batch.remove(
            &self.auth,
            session_by_refresh_key(&old_refresh_jti).as_slice(),
        );

        batch.insert(
            &self.auth,
            session_primary_key(session.id).as_slice(),
            session.serialize(),
        );
        batch.insert(
            &self.auth,
            session_by_access_key(&data.new_access_jti).as_slice(),
            new_access_index.serialize(session.refresh_expires_at_ms),
        );
        batch.insert(
            &self.auth,
            session_by_refresh_key(&data.new_refresh_jti).as_slice(),
            new_refresh_index.serialize(session.refresh_expires_at_ms),
        );
        batch.insert(
            &self.auth,
            session_by_did_key(user_hash, session.id).as_slice(),
            serialize_by_did_value(session.refresh_expires_at_ms),
        );

        batch.commit().map_err(MetastoreError::Fjall)?;

        Ok(RefreshSessionResult::Success)
    }
}
