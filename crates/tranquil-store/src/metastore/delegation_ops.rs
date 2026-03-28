use std::sync::Arc;

use chrono::{DateTime, Utc};
use fjall::{Database, Keyspace};
use uuid::Uuid;

use super::MetastoreError;
use super::delegations::{
    AuditLogValue, DelegationGrantValue, action_type_to_u8, audit_log_key, audit_log_prefix,
    by_controller_key, by_controller_prefix, grant_key, grant_prefix, u8_to_action_type,
};
use super::keys::UserHash;
use super::scan::{count_prefix, point_lookup};
use super::user_hash::UserHashMap;

use tranquil_db_traits::DbScope;
use tranquil_db_traits::{
    AuditLogEntry, ControllerInfo, DelegatedAccountInfo, DelegationActionType, DelegationGrant,
};
use tranquil_types::{Did, Handle};

pub struct DelegationOps {
    db: Database,
    indexes: Keyspace,
    users: Keyspace,
    user_hashes: Arc<UserHashMap>,
}

impl DelegationOps {
    pub fn new(
        db: Database,
        indexes: Keyspace,
        users: Keyspace,
        user_hashes: Arc<UserHashMap>,
    ) -> Self {
        Self {
            db,
            indexes,
            users,
            user_hashes,
        }
    }

    fn resolve_handle_for_did(&self, did_str: &str) -> Option<Handle> {
        let user_hash = UserHash::from_did(did_str);
        let key = super::encoding::KeyBuilder::new()
            .tag(super::keys::KeyTag::USER_PRIMARY)
            .u64(user_hash.raw())
            .build();
        self.users
            .get(key.as_slice())
            .ok()
            .flatten()
            .and_then(|raw| super::users::UserValue::deserialize(&raw))
            .and_then(|u| Handle::new(u.handle).ok())
    }

    fn value_to_grant(&self, v: &DelegationGrantValue) -> Result<DelegationGrant, MetastoreError> {
        Ok(DelegationGrant {
            id: v.id,
            delegated_did: Did::new(v.delegated_did.clone())
                .map_err(|_| MetastoreError::CorruptData("invalid delegated_did"))?,
            controller_did: Did::new(v.controller_did.clone())
                .map_err(|_| MetastoreError::CorruptData("invalid controller_did"))?,
            granted_scopes: DbScope::new(&v.granted_scopes).unwrap_or_else(|_| DbScope::empty()),
            granted_at: DateTime::from_timestamp_millis(v.granted_at_ms).unwrap_or_default(),
            granted_by: Did::new(v.granted_by.clone())
                .map_err(|_| MetastoreError::CorruptData("invalid granted_by"))?,
            revoked_at: v.revoked_at_ms.and_then(DateTime::from_timestamp_millis),
            revoked_by: v.revoked_by.as_ref().and_then(|d| Did::new(d.clone()).ok()),
        })
    }

    pub fn is_delegated_account(&self, did: &Did) -> Result<bool, MetastoreError> {
        let delegated_hash = UserHash::from_did(did.as_str());
        let prefix = grant_prefix(delegated_hash);
        let found = self
            .indexes
            .prefix(prefix.as_slice())
            .map(|guard| {
                let (_, val_bytes) = guard.into_inner().map_err(MetastoreError::Fjall)?;
                DelegationGrantValue::deserialize(&val_bytes)
                    .ok_or(MetastoreError::CorruptData("corrupt delegation grant"))
                    .map(|val| val.revoked_at_ms.is_none())
            })
            .find(|result| !matches!(result, Ok(false)));
        match found {
            Some(Ok(true)) => Ok(true),
            Some(Err(e)) => Err(e),
            _ => Ok(false),
        }
    }

    pub fn create_delegation(
        &self,
        delegated_did: &Did,
        controller_did: &Did,
        granted_scopes: &DbScope,
        granted_by: &Did,
    ) -> Result<Uuid, MetastoreError> {
        let delegated_hash = UserHash::from_did(delegated_did.as_str());
        let controller_hash = UserHash::from_did(controller_did.as_str());
        let id = Uuid::new_v4();
        let now_ms = Utc::now().timestamp_millis();

        let value = DelegationGrantValue {
            id,
            delegated_did: delegated_did.to_string(),
            controller_did: controller_did.to_string(),
            granted_scopes: granted_scopes.as_str().to_owned(),
            granted_at_ms: now_ms,
            granted_by: granted_by.to_string(),
            revoked_at_ms: None,
            revoked_by: None,
        };

        let primary = grant_key(delegated_hash, controller_hash);
        let reverse = by_controller_key(controller_hash, delegated_hash);

        let mut batch = self.db.batch();
        batch.insert(&self.indexes, primary.as_slice(), value.serialize());
        batch.insert(&self.indexes, reverse.as_slice(), []);
        batch.commit().map_err(MetastoreError::Fjall)?;

        Ok(id)
    }

    pub fn revoke_delegation(
        &self,
        delegated_did: &Did,
        controller_did: &Did,
        revoked_by: &Did,
    ) -> Result<bool, MetastoreError> {
        let delegated_hash = UserHash::from_did(delegated_did.as_str());
        let controller_hash = UserHash::from_did(controller_did.as_str());
        let primary = grant_key(delegated_hash, controller_hash);

        let existing: Option<DelegationGrantValue> = point_lookup(
            &self.indexes,
            primary.as_slice(),
            DelegationGrantValue::deserialize,
            "corrupt delegation grant",
        )?;

        match existing {
            Some(mut val) if val.revoked_at_ms.is_none() => {
                val.revoked_at_ms = Some(Utc::now().timestamp_millis());
                val.revoked_by = Some(revoked_by.to_string());

                let reverse = by_controller_key(controller_hash, delegated_hash);
                let mut batch = self.db.batch();
                batch.insert(&self.indexes, primary.as_slice(), val.serialize());
                batch.remove(&self.indexes, reverse.as_slice());
                batch.commit().map_err(MetastoreError::Fjall)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    pub fn update_delegation_scopes(
        &self,
        delegated_did: &Did,
        controller_did: &Did,
        new_scopes: &DbScope,
    ) -> Result<bool, MetastoreError> {
        let delegated_hash = UserHash::from_did(delegated_did.as_str());
        let controller_hash = UserHash::from_did(controller_did.as_str());
        let primary = grant_key(delegated_hash, controller_hash);

        let existing: Option<DelegationGrantValue> = point_lookup(
            &self.indexes,
            primary.as_slice(),
            DelegationGrantValue::deserialize,
            "corrupt delegation grant",
        )?;

        match existing {
            Some(mut val) if val.revoked_at_ms.is_none() => {
                val.granted_scopes = new_scopes.as_str().to_owned();
                self.indexes
                    .insert(primary.as_slice(), val.serialize())
                    .map_err(MetastoreError::Fjall)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    pub fn get_delegation(
        &self,
        delegated_did: &Did,
        controller_did: &Did,
    ) -> Result<Option<DelegationGrant>, MetastoreError> {
        let delegated_hash = UserHash::from_did(delegated_did.as_str());
        let controller_hash = UserHash::from_did(controller_did.as_str());
        let primary = grant_key(delegated_hash, controller_hash);

        let val: Option<DelegationGrantValue> = point_lookup(
            &self.indexes,
            primary.as_slice(),
            DelegationGrantValue::deserialize,
            "corrupt delegation grant",
        )?;

        val.map(|v| self.value_to_grant(&v)).transpose()
    }

    pub fn get_delegations_for_account(
        &self,
        delegated_did: &Did,
    ) -> Result<Vec<ControllerInfo>, MetastoreError> {
        let delegated_hash = UserHash::from_did(delegated_did.as_str());
        let prefix = grant_prefix(delegated_hash);

        self.indexes
            .prefix(prefix.as_slice())
            .try_fold(Vec::new(), |mut acc, guard| {
                let (_, val_bytes) = guard.into_inner().map_err(MetastoreError::Fjall)?;
                let val = DelegationGrantValue::deserialize(&val_bytes)
                    .ok_or(MetastoreError::CorruptData("corrupt delegation grant"))?;
                let is_active = val.revoked_at_ms.is_none();
                let controller_did_parsed = Did::new(val.controller_did.clone())
                    .map_err(|_| MetastoreError::CorruptData("invalid controller_did"))?;
                let handle = self.resolve_handle_for_did(&val.controller_did);
                let is_local = self
                    .user_hashes
                    .get_uuid(&UserHash::from_did(&val.controller_did))
                    .is_some();

                acc.push(ControllerInfo {
                    did: controller_did_parsed,
                    handle,
                    granted_scopes: DbScope::new(&val.granted_scopes)
                        .unwrap_or_else(|_| DbScope::empty()),
                    granted_at: DateTime::from_timestamp_millis(val.granted_at_ms)
                        .unwrap_or_default(),
                    is_active,
                    is_local,
                });
                Ok::<_, MetastoreError>(acc)
            })
    }

    pub fn get_accounts_controlled_by(
        &self,
        controller_did: &Did,
    ) -> Result<Vec<DelegatedAccountInfo>, MetastoreError> {
        let controller_hash = UserHash::from_did(controller_did.as_str());
        let prefix = by_controller_prefix(controller_hash);

        self.indexes
            .prefix(prefix.as_slice())
            .try_fold(Vec::new(), |mut acc, guard| {
                let (key_bytes, _) = guard.into_inner().map_err(MetastoreError::Fjall)?;
                let mut reader = super::encoding::KeyReader::new(&key_bytes);
                let _tag = reader.tag();
                let _ctrl_hash = reader.u64();
                let deleg_hash_raw = reader
                    .u64()
                    .ok_or(MetastoreError::CorruptData("corrupt by_controller key"))?;
                let deleg_hash = UserHash::from_raw(deleg_hash_raw);

                let grant_pfx = grant_key(deleg_hash, controller_hash);
                let grant_val: Option<DelegationGrantValue> = point_lookup(
                    &self.indexes,
                    grant_pfx.as_slice(),
                    DelegationGrantValue::deserialize,
                    "corrupt delegation grant",
                )?;

                if let Some(val) = grant_val.filter(|v| v.revoked_at_ms.is_none()) {
                    let delegated_did = Did::new(val.delegated_did.clone())
                        .map_err(|_| MetastoreError::CorruptData("invalid delegated_did"))?;
                    let handle = self
                        .resolve_handle_for_did(&val.delegated_did)
                        .unwrap_or_else(|| Handle::new("unknown.invalid").unwrap());
                    acc.push(DelegatedAccountInfo {
                        did: delegated_did,
                        handle,
                        granted_scopes: DbScope::new(&val.granted_scopes)
                            .unwrap_or_else(|_| DbScope::empty()),
                        granted_at: DateTime::from_timestamp_millis(val.granted_at_ms)
                            .unwrap_or_default(),
                    });
                }

                Ok::<_, MetastoreError>(acc)
            })
    }

    pub fn count_active_controllers(&self, delegated_did: &Did) -> Result<i64, MetastoreError> {
        let delegated_hash = UserHash::from_did(delegated_did.as_str());
        let prefix = grant_prefix(delegated_hash);

        self.indexes
            .prefix(prefix.as_slice())
            .try_fold(0i64, |acc, guard| {
                let (_, val_bytes) = guard.into_inner().map_err(MetastoreError::Fjall)?;
                let val = DelegationGrantValue::deserialize(&val_bytes)
                    .ok_or(MetastoreError::CorruptData("corrupt delegation grant"))?;
                Ok::<_, MetastoreError>(match val.revoked_at_ms.is_none() {
                    true => acc.saturating_add(1),
                    false => acc,
                })
            })
    }

    pub fn controls_any_accounts(&self, did: &Did) -> Result<bool, MetastoreError> {
        let controller_hash = UserHash::from_did(did.as_str());
        let prefix = by_controller_prefix(controller_hash);
        match self.indexes.prefix(prefix.as_slice()).next() {
            Some(guard) => {
                guard.into_inner().map_err(MetastoreError::Fjall)?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn log_delegation_action(
        &self,
        delegated_did: &Did,
        actor_did: &Did,
        controller_did: Option<&Did>,
        action_type: DelegationActionType,
        action_details: Option<serde_json::Value>,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<Uuid, MetastoreError> {
        let delegated_hash = UserHash::from_did(delegated_did.as_str());
        let id = Uuid::new_v4();
        let now_ms = Utc::now().timestamp_millis();

        let value = AuditLogValue {
            id,
            delegated_did: delegated_did.to_string(),
            actor_did: actor_did.to_string(),
            controller_did: controller_did.map(|d| d.to_string()),
            action_type: action_type_to_u8(action_type),
            action_details: action_details.map(|v| serde_json::to_vec(&v).unwrap_or_default()),
            ip_address: ip_address.map(str::to_owned),
            user_agent: user_agent.map(str::to_owned),
            created_at_ms: now_ms,
        };

        let key = audit_log_key(delegated_hash, now_ms, id);
        self.indexes
            .insert(key.as_slice(), value.serialize())
            .map_err(MetastoreError::Fjall)?;

        Ok(id)
    }

    pub fn get_audit_log_for_account(
        &self,
        delegated_did: &Did,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AuditLogEntry>, MetastoreError> {
        let delegated_hash = UserHash::from_did(delegated_did.as_str());
        let prefix = audit_log_prefix(delegated_hash);

        let limit = usize::try_from(limit).unwrap_or(0);
        let offset = usize::try_from(offset).unwrap_or(0);

        self.indexes
            .prefix(prefix.as_slice())
            .skip(offset)
            .take(limit)
            .try_fold(Vec::new(), |mut acc, guard| {
                let (_, val_bytes) = guard.into_inner().map_err(MetastoreError::Fjall)?;
                let val = AuditLogValue::deserialize(&val_bytes)
                    .ok_or(MetastoreError::CorruptData("corrupt audit log entry"))?;
                acc.push(self.value_to_audit_entry(&val)?);
                Ok::<_, MetastoreError>(acc)
            })
    }

    pub fn count_audit_log_entries(&self, delegated_did: &Did) -> Result<i64, MetastoreError> {
        let delegated_hash = UserHash::from_did(delegated_did.as_str());
        let prefix = audit_log_prefix(delegated_hash);
        count_prefix(&self.indexes, prefix.as_slice())
    }

    fn value_to_audit_entry(&self, v: &AuditLogValue) -> Result<AuditLogEntry, MetastoreError> {
        Ok(AuditLogEntry {
            id: v.id,
            delegated_did: Did::new(v.delegated_did.clone())
                .map_err(|_| MetastoreError::CorruptData("invalid delegated_did"))?,
            actor_did: Did::new(v.actor_did.clone())
                .map_err(|_| MetastoreError::CorruptData("invalid actor_did"))?,
            controller_did: v
                .controller_did
                .as_ref()
                .map(|d| Did::new(d.clone()))
                .transpose()
                .map_err(|_| MetastoreError::CorruptData("invalid controller_did"))?,
            action_type: u8_to_action_type(v.action_type).ok_or(MetastoreError::CorruptData(
                "unknown delegation action type",
            ))?,
            action_details: v
                .action_details
                .as_ref()
                .and_then(|b| serde_json::from_slice(b).ok()),
            ip_address: v.ip_address.clone(),
            user_agent: v.user_agent.clone(),
            created_at: DateTime::from_timestamp_millis(v.created_at_ms).unwrap_or_default(),
        })
    }
}
