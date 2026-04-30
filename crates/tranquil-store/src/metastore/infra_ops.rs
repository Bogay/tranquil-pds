use std::sync::Arc;

use chrono::{DateTime, Utc};
use fjall::{Database, Keyspace};
use smallvec::SmallVec;
use uuid::Uuid;

use super::MetastoreError;
use super::blobs::{BlobMetaValue, blob_by_cid_key, blob_meta_key};
use super::infra_schema::{
    DeletionRequestValue, InviteCodeUseValue, InviteCodeValue, NotificationHistoryValue,
    QueuedCommsValue, ReportValue, SigningKeyValue, account_pref_key, account_pref_prefix,
    channel_to_u8, comms_history_key, comms_history_prefix, comms_queue_key, comms_queue_prefix,
    comms_type_to_u8, deletion_by_did_key, deletion_request_key, invite_by_user_key,
    invite_code_key, invite_code_prefix, invite_code_used_by_key, invite_use_key,
    invite_use_prefix, plc_token_key, plc_token_prefix, report_key, server_config_key,
    signing_key_by_id_key, signing_key_key, status_to_u8, u8_to_channel, u8_to_comms_type,
    u8_to_status,
};
use super::keys::UserHash;
use super::scan::{delete_all_by_prefix, point_lookup};
use super::user_hash::UserHashMap;
use super::users::UserValue;

use tranquil_db_traits::{
    AdminAccountInfo, CommsChannel, CommsStatus, CommsType, DeletionRequest,
    DeletionRequestWithToken, InviteCodeError, InviteCodeInfo, InviteCodeRow, InviteCodeSortOrder,
    InviteCodeState, InviteCodeUse, NotificationHistoryRow, PlcTokenInfo, QueuedComms,
    ReservedSigningKey, ReservedSigningKeyFull, ValidatedInviteCode,
};
use tranquil_types::{CidLink, Did, Handle};

pub struct InfraOps {
    db: Database,
    infra: Keyspace,
    repo_data: Keyspace,
    users: Keyspace,
    user_hashes: Arc<UserHashMap>,
    comms_seq: Arc<std::sync::atomic::AtomicU32>,
}

impl InfraOps {
    pub fn new(
        db: Database,
        infra: Keyspace,
        repo_data: Keyspace,
        users: Keyspace,
        user_hashes: Arc<UserHashMap>,
        comms_seq: Arc<std::sync::atomic::AtomicU32>,
    ) -> Self {
        Self {
            db,
            infra,
            repo_data,
            users,
            user_hashes,
            comms_seq,
        }
    }

    fn resolve_user_value(&self, user_hash: UserHash) -> Option<UserValue> {
        let key = super::encoding::KeyBuilder::new()
            .tag(super::keys::KeyTag::USER_PRIMARY)
            .u64(user_hash.raw())
            .build();
        self.users
            .get(key.as_slice())
            .ok()
            .flatten()
            .and_then(|raw| UserValue::deserialize(&raw))
    }

    fn resolve_did_for_uuid(&self, user_id: Uuid) -> Option<Did> {
        let user_hash = self.user_hashes.get(&user_id)?;
        self.resolve_user_value(user_hash)
            .and_then(|u| Did::new(u.did).ok())
    }

    fn resolve_handle_for_uuid(&self, user_id: Uuid) -> Option<Handle> {
        let user_hash = self.user_hashes.get(&user_id)?;
        self.resolve_user_value(user_hash)
            .and_then(|u| Handle::new(u.handle).ok())
    }

    fn value_to_queued_comms(&self, v: &QueuedCommsValue) -> Result<QueuedComms, MetastoreError> {
        let channel =
            u8_to_channel(v.channel).ok_or(MetastoreError::CorruptData("invalid comms channel"))?;
        let comms_type = u8_to_comms_type(v.comms_type)
            .ok_or(MetastoreError::CorruptData("invalid comms type"))?;
        let status =
            u8_to_status(v.status).ok_or(MetastoreError::CorruptData("invalid comms status"))?;
        Ok(QueuedComms {
            id: v.id,
            user_id: v.user_id,
            channel,
            comms_type,
            status,
            recipient: v.recipient.clone(),
            subject: v.subject.clone(),
            body: v.body.clone(),
            metadata: v
                .metadata
                .as_ref()
                .and_then(|b| serde_json::from_slice(b).ok()),
            attempts: v.attempts,
            max_attempts: v.max_attempts,
            last_error: v.error_message.clone(),
            created_at: DateTime::from_timestamp_millis(v.created_at_ms).unwrap_or_default(),
            updated_at: DateTime::from_timestamp_millis(v.sent_at_ms.unwrap_or(v.created_at_ms))
                .unwrap_or_default(),
            scheduled_for: DateTime::from_timestamp_millis(v.scheduled_for_ms).unwrap_or_default(),
            processed_at: v.sent_at_ms.and_then(DateTime::from_timestamp_millis),
        })
    }

    fn value_to_invite_info(&self, v: &InviteCodeValue) -> Result<InviteCodeInfo, MetastoreError> {
        Ok(InviteCodeInfo {
            code: v.code.clone(),
            available_uses: v.available_uses,
            state: InviteCodeState::from_disabled_flag(v.disabled),
            for_account: v
                .for_account
                .as_ref()
                .and_then(|d| Did::new(d.clone()).ok()),
            created_at: DateTime::from_timestamp_millis(v.created_at_ms).unwrap_or_default(),
            created_by: v.created_by.and_then(|uid| self.resolve_did_for_uuid(uid)),
        })
    }

    fn user_to_admin_info(&self, u: &UserValue) -> Result<AdminAccountInfo, MetastoreError> {
        let did = Did::new(u.did.clone())
            .map_err(|_| MetastoreError::CorruptData("invalid did in user record"))?;
        let handle = Handle::new(u.handle.clone())
            .map_err(|_| MetastoreError::CorruptData("invalid handle in user record"))?;
        Ok(AdminAccountInfo {
            id: u.id,
            did,
            handle,
            email: u.email.clone(),
            created_at: DateTime::from_timestamp_millis(u.created_at_ms).unwrap_or_default(),
            invites_disabled: u.invites_disabled,
            email_verified: u.email_verified,
            deactivated_at: u
                .deactivated_at_ms
                .and_then(DateTime::from_timestamp_millis),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn enqueue_comms(
        &self,
        user_id: Option<Uuid>,
        channel: CommsChannel,
        comms_type: CommsType,
        recipient: &str,
        subject: Option<&str>,
        body: &str,
        metadata: Option<serde_json::Value>,
    ) -> Result<Uuid, MetastoreError> {
        let id = Uuid::new_v4();
        let now_ms = Utc::now().timestamp_millis();

        let value = QueuedCommsValue {
            id,
            user_id,
            channel: channel_to_u8(channel),
            comms_type: comms_type_to_u8(comms_type),
            recipient: recipient.to_owned(),
            subject: subject.map(str::to_owned),
            body: body.to_owned(),
            metadata: metadata.map(|v| serde_json::to_vec(&v).unwrap_or_default()),
            status: status_to_u8(CommsStatus::Pending),
            error_message: None,
            attempts: 0,
            max_attempts: 3,
            created_at_ms: now_ms,
            scheduled_for_ms: now_ms,
            sent_at_ms: None,
        };

        let queue_key = comms_queue_key(id);
        let mut batch = self.db.batch();
        batch.insert(&self.infra, queue_key.as_slice(), value.serialize());

        if let Some(uid) = user_id {
            let history_value = NotificationHistoryValue {
                id,
                channel: channel_to_u8(channel),
                comms_type: comms_type_to_u8(comms_type),
                recipient: recipient.to_owned(),
                subject: subject.map(str::to_owned),
                body: body.to_owned(),
                status: status_to_u8(CommsStatus::Pending),
                created_at_ms: now_ms,
            };
            let seq = self
                .comms_seq
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let history_key = comms_history_key(uid, now_ms, seq, id);
            batch.insert(
                &self.infra,
                history_key.as_slice(),
                history_value.serialize(),
            );
        }

        batch.commit().map_err(MetastoreError::Fjall)?;
        Ok(id)
    }

    pub fn fetch_pending_comms(
        &self,
        now: DateTime<Utc>,
        batch_size: i64,
    ) -> Result<Vec<QueuedComms>, MetastoreError> {
        let now_ms = now.timestamp_millis();
        let limit = usize::try_from(batch_size).unwrap_or(0);
        let prefix = comms_queue_prefix();

        self.infra
            .prefix(prefix.as_slice())
            .map(|guard| -> Result<Option<QueuedComms>, MetastoreError> {
                let (_, val_bytes) = guard.into_inner().map_err(MetastoreError::Fjall)?;
                let val = QueuedCommsValue::deserialize(&val_bytes)
                    .ok_or(MetastoreError::CorruptData("corrupt comms queue entry"))?;
                let is_pending = val.status == status_to_u8(CommsStatus::Pending);
                let is_scheduled = val.scheduled_for_ms <= now_ms;
                match is_pending && is_scheduled {
                    true => Ok(Some(self.value_to_queued_comms(&val)?)),
                    false => Ok(None),
                }
            })
            .filter_map(Result::transpose)
            .take(limit)
            .collect()
    }

    pub fn mark_comms_sent(&self, id: Uuid) -> Result<(), MetastoreError> {
        let key = comms_queue_key(id);
        let mut val: QueuedCommsValue = point_lookup(
            &self.infra,
            key.as_slice(),
            QueuedCommsValue::deserialize,
            "corrupt comms queue entry",
        )?
        .ok_or(MetastoreError::InvalidInput("comms entry not found"))?;

        val.status = status_to_u8(CommsStatus::Sent);
        val.sent_at_ms = Some(Utc::now().timestamp_millis());

        let mut batch = self.db.batch();
        batch.insert(&self.infra, key.as_slice(), val.serialize());

        if let Some((hk, mut hv)) =
            self.find_history_entry(val.user_id.unwrap_or(Uuid::nil()), val.id)?
        {
            hv.status = status_to_u8(CommsStatus::Sent);
            batch.insert(&self.infra, hk.as_slice(), hv.serialize());
        }

        batch.commit().map_err(MetastoreError::Fjall)
    }

    pub fn mark_comms_failed(&self, id: Uuid, error: &str) -> Result<(), MetastoreError> {
        let key = comms_queue_key(id);
        let mut val: QueuedCommsValue = point_lookup(
            &self.infra,
            key.as_slice(),
            QueuedCommsValue::deserialize,
            "corrupt comms queue entry",
        )?
        .ok_or(MetastoreError::InvalidInput("comms entry not found"))?;

        let next_attempts = val.attempts.saturating_add(1);
        let exhausted = next_attempts >= val.max_attempts;
        let next_status = match exhausted {
            true => CommsStatus::Failed,
            false => CommsStatus::Pending,
        };
        let now_ms = Utc::now().timestamp_millis();
        let backoff_ms = i64::from(next_attempts).saturating_mul(60_000);

        val.status = status_to_u8(next_status);
        val.error_message = Some(error.to_owned());
        val.attempts = next_attempts;
        val.scheduled_for_ms = now_ms.saturating_add(backoff_ms);

        let mut batch = self.db.batch();
        batch.insert(&self.infra, key.as_slice(), val.serialize());

        if let Some((hk, mut hv)) =
            self.find_history_entry(val.user_id.unwrap_or(Uuid::nil()), val.id)?
        {
            hv.status = status_to_u8(next_status);
            batch.insert(&self.infra, hk.as_slice(), hv.serialize());
        }

        batch.commit().map_err(MetastoreError::Fjall)
    }

    pub fn mark_comms_failed_permanent(&self, id: Uuid, error: &str) -> Result<(), MetastoreError> {
        let key = comms_queue_key(id);
        let mut val: QueuedCommsValue = point_lookup(
            &self.infra,
            key.as_slice(),
            QueuedCommsValue::deserialize,
            "corrupt comms queue entry",
        )?
        .ok_or(MetastoreError::InvalidInput("comms entry not found"))?;

        val.status = status_to_u8(CommsStatus::Failed);
        val.error_message = Some(error.to_owned());
        val.attempts = val.max_attempts;

        let mut batch = self.db.batch();
        batch.insert(&self.infra, key.as_slice(), val.serialize());

        if let Some((hk, mut hv)) =
            self.find_history_entry(val.user_id.unwrap_or(Uuid::nil()), val.id)?
        {
            hv.status = status_to_u8(CommsStatus::Failed);
            batch.insert(&self.infra, hk.as_slice(), hv.serialize());
        }

        batch.commit().map_err(MetastoreError::Fjall)
    }

    #[allow(clippy::type_complexity)]
    fn find_history_entry(
        &self,
        user_id: Uuid,
        comms_id: Uuid,
    ) -> Result<Option<(SmallVec<[u8; 128]>, NotificationHistoryValue)>, MetastoreError> {
        let prefix = comms_history_prefix(user_id);
        self.infra
            .prefix(prefix.as_slice())
            .find_map(|guard| {
                let (key_bytes, val_bytes) = match guard.into_inner() {
                    Ok(kv) => kv,
                    Err(e) => return Some(Err(MetastoreError::Fjall(e))),
                };
                let val = match NotificationHistoryValue::deserialize(&val_bytes) {
                    Some(v) => v,
                    None => {
                        return Some(Err(MetastoreError::CorruptData(
                            "corrupt notification history",
                        )));
                    }
                };
                match val.id == comms_id {
                    true => Some(Ok((SmallVec::from_slice(&key_bytes), val))),
                    false => None,
                }
            })
            .transpose()
    }

    pub fn create_invite_code(
        &self,
        code: &str,
        use_count: i32,
        for_account: Option<&Did>,
    ) -> Result<bool, MetastoreError> {
        let key = invite_code_key(code);
        let existing = self
            .infra
            .get(key.as_slice())
            .map_err(MetastoreError::Fjall)?;
        if existing.is_some() {
            return Ok(false);
        }

        let value = InviteCodeValue {
            code: code.to_owned(),
            available_uses: use_count,
            disabled: false,
            for_account: for_account.map(|d| d.to_string()),
            created_by: None,
            created_at_ms: Utc::now().timestamp_millis(),
        };

        self.infra
            .insert(key.as_slice(), value.serialize())
            .map_err(MetastoreError::Fjall)?;
        Ok(true)
    }

    pub fn create_invite_codes_batch(
        &self,
        codes: &[String],
        use_count: i32,
        created_by_user: Uuid,
        for_account: Option<&Did>,
    ) -> Result<(), MetastoreError> {
        let now_ms = Utc::now().timestamp_millis();
        let mut batch = self.db.batch();

        codes.iter().try_for_each(|code| {
            let value = InviteCodeValue {
                code: code.clone(),
                available_uses: use_count,
                disabled: false,
                for_account: for_account.map(|d| d.to_string()),
                created_by: Some(created_by_user),
                created_at_ms: now_ms,
            };
            let key = invite_code_key(code);
            batch.insert(&self.infra, key.as_slice(), value.serialize());

            Ok::<(), MetastoreError>(())
        })?;

        batch.commit().map_err(MetastoreError::Fjall)
    }

    pub fn get_invite_code_available_uses(
        &self,
        code: &str,
    ) -> Result<Option<i32>, MetastoreError> {
        let key = invite_code_key(code);
        let val: Option<InviteCodeValue> = point_lookup(
            &self.infra,
            key.as_slice(),
            InviteCodeValue::deserialize,
            "corrupt invite code",
        )?;
        Ok(val.map(|v| v.available_uses))
    }

    pub fn validate_invite_code<'a>(
        &self,
        code: &'a str,
    ) -> Result<ValidatedInviteCode<'a>, InviteCodeError> {
        let key = invite_code_key(code);
        let val: Option<InviteCodeValue> = point_lookup(
            &self.infra,
            key.as_slice(),
            InviteCodeValue::deserialize,
            "corrupt invite code",
        )
        .map_err(|e| {
            InviteCodeError::DatabaseError(tranquil_db_traits::DbError::Query(e.to_string()))
        })?;

        match val {
            None => Err(InviteCodeError::NotFound),
            Some(v) if v.disabled => Err(InviteCodeError::Disabled),
            Some(v) if v.available_uses <= 0 => Err(InviteCodeError::ExhaustedUses),
            Some(_) => Ok(ValidatedInviteCode::new_validated(code)),
        }
    }

    pub fn decrement_invite_code_uses(
        &self,
        code: &ValidatedInviteCode<'_>,
    ) -> Result<(), MetastoreError> {
        let key = invite_code_key(code.code());
        let mut val: InviteCodeValue = point_lookup(
            &self.infra,
            key.as_slice(),
            InviteCodeValue::deserialize,
            "corrupt invite code",
        )?
        .ok_or(MetastoreError::InvalidInput("invite code not found"))?;

        val.available_uses = val.available_uses.saturating_sub(1);
        self.infra
            .insert(key.as_slice(), val.serialize())
            .map_err(MetastoreError::Fjall)
    }

    pub fn record_invite_code_use(
        &self,
        code: &ValidatedInviteCode<'_>,
        used_by_user: Uuid,
    ) -> Result<(), MetastoreError> {
        let now_ms = Utc::now().timestamp_millis();
        let use_value = InviteCodeUseValue {
            used_by: used_by_user,
            used_at_ms: now_ms,
        };

        let use_key = invite_use_key(code.code(), used_by_user);
        let used_by_key = invite_code_used_by_key(used_by_user);

        let mut batch = self.db.batch();
        batch.insert(&self.infra, use_key.as_slice(), use_value.serialize());
        batch.insert(&self.infra, used_by_key.as_slice(), code.code().as_bytes());
        batch.commit().map_err(MetastoreError::Fjall)
    }

    pub fn get_invite_codes_for_account(
        &self,
        for_account: &Did,
    ) -> Result<Vec<InviteCodeInfo>, MetastoreError> {
        let did_str = for_account.to_string();
        let prefix = invite_code_prefix();

        self.infra
            .prefix(prefix.as_slice())
            .try_fold(Vec::new(), |mut acc, guard| {
                let (_, val_bytes) = guard.into_inner().map_err(MetastoreError::Fjall)?;
                let val = InviteCodeValue::deserialize(&val_bytes)
                    .ok_or(MetastoreError::CorruptData("corrupt invite code"))?;
                let matches = val.for_account.as_ref().is_some_and(|d| *d == did_str);
                if matches {
                    acc.push(self.value_to_invite_info(&val)?);
                }
                Ok(acc)
            })
    }

    pub fn get_invite_code_uses(&self, code: &str) -> Result<Vec<InviteCodeUse>, MetastoreError> {
        let prefix = invite_use_prefix(code);

        self.infra
            .prefix(prefix.as_slice())
            .try_fold(Vec::new(), |mut acc, guard| {
                let (_, val_bytes) = guard.into_inner().map_err(MetastoreError::Fjall)?;
                let val = InviteCodeUseValue::deserialize(&val_bytes)
                    .ok_or(MetastoreError::CorruptData("corrupt invite use"))?;
                let used_by_did = self
                    .resolve_did_for_uuid(val.used_by)
                    .unwrap_or_else(|| Did::new("did:plc:unknown".to_owned()).unwrap());
                let used_by_handle = self.resolve_handle_for_uuid(val.used_by);
                acc.push(InviteCodeUse {
                    code: code.to_owned(),
                    used_by_did,
                    used_by_handle,
                    used_at: DateTime::from_timestamp_millis(val.used_at_ms).unwrap_or_default(),
                });
                Ok(acc)
            })
    }

    pub fn disable_invite_codes_by_code(&self, codes: &[String]) -> Result<(), MetastoreError> {
        let mut batch = self.db.batch();

        codes.iter().try_for_each(|code| {
            let key = invite_code_key(code);
            let val: Option<InviteCodeValue> = point_lookup(
                &self.infra,
                key.as_slice(),
                InviteCodeValue::deserialize,
                "corrupt invite code",
            )?;
            if let Some(mut v) = val {
                v.disabled = true;
                batch.insert(&self.infra, key.as_slice(), v.serialize());
            }
            Ok::<(), MetastoreError>(())
        })?;

        batch.commit().map_err(MetastoreError::Fjall)
    }

    pub fn disable_invite_codes_by_account(&self, accounts: &[Did]) -> Result<(), MetastoreError> {
        let account_strs: Vec<String> = accounts.iter().map(|d| d.to_string()).collect();
        let prefix = invite_code_prefix();
        let mut batch = self.db.batch();

        self.infra.prefix(prefix.as_slice()).try_for_each(|guard| {
            let (key_bytes, val_bytes) = guard.into_inner().map_err(MetastoreError::Fjall)?;
            let mut val = InviteCodeValue::deserialize(&val_bytes)
                .ok_or(MetastoreError::CorruptData("corrupt invite code"))?;
            let matches = val
                .for_account
                .as_ref()
                .is_some_and(|d| account_strs.iter().any(|a| a == d));
            if matches {
                val.disabled = true;
                batch.insert(&self.infra, key_bytes.as_ref(), val.serialize());
            }
            Ok::<(), MetastoreError>(())
        })?;

        batch.commit().map_err(MetastoreError::Fjall)
    }

    pub fn list_invite_codes(
        &self,
        cursor: Option<&str>,
        limit: i64,
        sort: InviteCodeSortOrder,
    ) -> Result<Vec<InviteCodeRow>, MetastoreError> {
        let prefix = invite_code_prefix();
        let limit = usize::try_from(limit).unwrap_or(0);

        let mut rows: Vec<InviteCodeRow> =
            self.infra
                .prefix(prefix.as_slice())
                .try_fold(Vec::new(), |mut acc, guard| {
                    let (_, val_bytes) = guard.into_inner().map_err(MetastoreError::Fjall)?;
                    let val = InviteCodeValue::deserialize(&val_bytes)
                        .ok_or(MetastoreError::CorruptData("corrupt invite code"))?;
                    let created_by_user = val.created_by.unwrap_or(Uuid::nil());
                    acc.push(InviteCodeRow {
                        code: val.code,
                        available_uses: val.available_uses,
                        disabled: Some(val.disabled),
                        created_by_user,
                        created_at: DateTime::from_timestamp_millis(val.created_at_ms)
                            .unwrap_or_default(),
                    });
                    Ok::<_, MetastoreError>(acc)
                })?;

        match sort {
            InviteCodeSortOrder::Recent => rows.sort_by_key(|r| std::cmp::Reverse(r.created_at)),
            InviteCodeSortOrder::Usage => rows.sort_by_key(|r| r.available_uses),
        }

        let result = match cursor {
            Some(c) => rows
                .into_iter()
                .skip_while(|r| r.code != c)
                .skip(1)
                .take(limit)
                .collect(),
            None => rows.into_iter().take(limit).collect(),
        };

        Ok(result)
    }

    pub fn get_user_dids_by_ids(
        &self,
        user_ids: &[Uuid],
    ) -> Result<Vec<(Uuid, Did)>, MetastoreError> {
        user_ids
            .iter()
            .filter_map(|&uid| self.resolve_did_for_uuid(uid).map(|did| Ok((uid, did))))
            .collect()
    }

    pub fn get_invite_code_uses_batch(
        &self,
        codes: &[String],
    ) -> Result<Vec<InviteCodeUse>, MetastoreError> {
        codes.iter().try_fold(Vec::new(), |mut acc, code| {
            let uses = self.get_invite_code_uses(code)?;
            acc.extend(uses);
            Ok(acc)
        })
    }

    pub fn get_invites_created_by_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<InviteCodeInfo>, MetastoreError> {
        let prefix = invite_code_prefix();

        self.infra
            .prefix(prefix.as_slice())
            .try_fold(Vec::new(), |mut acc, guard| {
                let (_, val_bytes) = guard.into_inner().map_err(MetastoreError::Fjall)?;
                let val = InviteCodeValue::deserialize(&val_bytes)
                    .ok_or(MetastoreError::CorruptData("corrupt invite code"))?;
                if val.created_by == Some(user_id) {
                    acc.push(self.value_to_invite_info(&val)?);
                }
                Ok(acc)
            })
    }

    pub fn get_invite_code_info(
        &self,
        code: &str,
    ) -> Result<Option<InviteCodeInfo>, MetastoreError> {
        let key = invite_code_key(code);
        let val: Option<InviteCodeValue> = point_lookup(
            &self.infra,
            key.as_slice(),
            InviteCodeValue::deserialize,
            "corrupt invite code",
        )?;
        val.map(|v| self.value_to_invite_info(&v)).transpose()
    }

    pub fn get_invite_codes_by_users(
        &self,
        user_ids: &[Uuid],
    ) -> Result<Vec<(Uuid, InviteCodeInfo)>, MetastoreError> {
        let prefix = invite_code_prefix();

        self.infra
            .prefix(prefix.as_slice())
            .try_fold(Vec::new(), |mut acc, guard| {
                let (_, val_bytes) = guard.into_inner().map_err(MetastoreError::Fjall)?;
                let val = InviteCodeValue::deserialize(&val_bytes)
                    .ok_or(MetastoreError::CorruptData("corrupt invite code"))?;
                if let Some(uid) = val.created_by.filter(|u| user_ids.contains(u)) {
                    acc.push((uid, self.value_to_invite_info(&val)?));
                }
                Ok(acc)
            })
    }

    pub fn get_invite_code_used_by_user(
        &self,
        user_id: Uuid,
    ) -> Result<Option<String>, MetastoreError> {
        let key = invite_code_used_by_key(user_id);
        match self
            .infra
            .get(key.as_slice())
            .map_err(MetastoreError::Fjall)?
        {
            Some(raw) => String::from_utf8(raw.to_vec())
                .map(Some)
                .map_err(|_| MetastoreError::CorruptData("invite code used_by not valid utf8")),
            None => Ok(None),
        }
    }

    pub fn delete_invite_code_uses_by_user(&self, user_id: Uuid) -> Result<(), MetastoreError> {
        let used_by_key = invite_code_used_by_key(user_id);
        let code = match self
            .infra
            .get(used_by_key.as_slice())
            .map_err(MetastoreError::Fjall)?
        {
            Some(raw) => String::from_utf8(raw.to_vec())
                .map_err(|_| MetastoreError::CorruptData("invite code used_by not valid utf8"))?,
            None => return Ok(()),
        };

        let use_key = invite_use_key(&code, user_id);
        let mut batch = self.db.batch();
        batch.remove(&self.infra, use_key.as_slice());
        batch.remove(&self.infra, used_by_key.as_slice());
        batch.commit().map_err(MetastoreError::Fjall)
    }

    pub fn delete_invite_codes_by_user(&self, user_id: Uuid) -> Result<(), MetastoreError> {
        let prefix = invite_code_prefix();
        let mut batch = self.db.batch();

        self.infra.prefix(prefix.as_slice()).try_for_each(|guard| {
            let (key_bytes, val_bytes) = guard.into_inner().map_err(MetastoreError::Fjall)?;
            let val = InviteCodeValue::deserialize(&val_bytes)
                .ok_or(MetastoreError::CorruptData("corrupt invite code"))?;
            if val.created_by == Some(user_id) {
                batch.remove(&self.infra, key_bytes.as_ref());
                let use_pfx = invite_use_prefix(&val.code);
                delete_all_by_prefix(&self.infra, &mut batch, use_pfx.as_slice())?;
            }
            Ok::<(), MetastoreError>(())
        })?;

        let user_key = invite_by_user_key(user_id);
        batch.remove(&self.infra, user_key.as_slice());
        batch.commit().map_err(MetastoreError::Fjall)
    }

    pub fn reserve_signing_key(
        &self,
        did: Option<&Did>,
        public_key_did_key: &str,
        private_key_bytes: &[u8],
        expires_at: DateTime<Utc>,
    ) -> Result<Uuid, MetastoreError> {
        let id = Uuid::new_v4();
        let now_ms = Utc::now().timestamp_millis();

        let value = SigningKeyValue {
            id,
            did: did.map(|d| d.to_string()),
            public_key_did_key: public_key_did_key.to_owned(),
            private_key_bytes: private_key_bytes.to_vec(),
            used: false,
            created_at_ms: now_ms,
            expires_at_ms: expires_at.timestamp_millis(),
            used_at_ms: None,
        };

        let primary_key = signing_key_key(public_key_did_key);
        let id_index_key = signing_key_by_id_key(id);

        let mut batch = self.db.batch();
        batch.insert(&self.infra, primary_key.as_slice(), value.serialize());
        batch.insert(
            &self.infra,
            id_index_key.as_slice(),
            public_key_did_key.as_bytes(),
        );
        batch.commit().map_err(MetastoreError::Fjall)?;

        Ok(id)
    }

    pub fn get_reserved_signing_key(
        &self,
        public_key_did_key: &str,
    ) -> Result<Option<ReservedSigningKey>, MetastoreError> {
        let key = signing_key_key(public_key_did_key);
        let val: Option<SigningKeyValue> = point_lookup(
            &self.infra,
            key.as_slice(),
            SigningKeyValue::deserialize,
            "corrupt signing key",
        )?;
        let now_ms = Utc::now().timestamp_millis();
        Ok(val
            .filter(|v| !v.used && v.expires_at_ms > now_ms)
            .map(|v| ReservedSigningKey {
                id: v.id,
                private_key_bytes: v.private_key_bytes,
            }))
    }

    pub fn mark_signing_key_used(&self, key_id: Uuid) -> Result<(), MetastoreError> {
        let id_key = signing_key_by_id_key(key_id);
        let pub_key_str = match self
            .infra
            .get(id_key.as_slice())
            .map_err(MetastoreError::Fjall)?
        {
            Some(raw) => String::from_utf8(raw.to_vec())
                .map_err(|_| MetastoreError::CorruptData("signing key index not valid utf8"))?,
            None => return Ok(()),
        };

        let primary_key = signing_key_key(&pub_key_str);
        let mut val: SigningKeyValue = point_lookup(
            &self.infra,
            primary_key.as_slice(),
            SigningKeyValue::deserialize,
            "corrupt signing key",
        )?
        .ok_or(MetastoreError::CorruptData(
            "signing key missing from primary",
        ))?;

        val.used = true;
        val.used_at_ms = Some(Utc::now().timestamp_millis());
        self.infra
            .insert(primary_key.as_slice(), val.serialize())
            .map_err(MetastoreError::Fjall)
    }

    pub fn create_deletion_request(
        &self,
        token: &str,
        did: &Did,
        expires_at: DateTime<Utc>,
    ) -> Result<(), MetastoreError> {
        let now_ms = Utc::now().timestamp_millis();
        let value = DeletionRequestValue {
            token: token.to_owned(),
            did: did.to_string(),
            created_at_ms: now_ms,
            expires_at_ms: expires_at.timestamp_millis(),
        };

        let primary_key = deletion_request_key(token);
        let did_key = deletion_by_did_key(did.as_str());

        let mut batch = self.db.batch();
        batch.insert(&self.infra, primary_key.as_slice(), value.serialize());
        batch.insert(&self.infra, did_key.as_slice(), token.as_bytes());
        batch.commit().map_err(MetastoreError::Fjall)
    }

    pub fn get_deletion_request(
        &self,
        token: &str,
    ) -> Result<Option<DeletionRequest>, MetastoreError> {
        let key = deletion_request_key(token);
        let val: Option<DeletionRequestValue> = point_lookup(
            &self.infra,
            key.as_slice(),
            DeletionRequestValue::deserialize,
            "corrupt deletion request",
        )?;
        Ok(val.and_then(|v| {
            Did::new(v.did).ok().map(|did| DeletionRequest {
                did,
                expires_at: DateTime::from_timestamp_millis(v.expires_at_ms).unwrap_or_default(),
            })
        }))
    }

    pub fn delete_deletion_request(&self, token: &str) -> Result<(), MetastoreError> {
        let primary_key = deletion_request_key(token);

        let val: Option<DeletionRequestValue> = point_lookup(
            &self.infra,
            primary_key.as_slice(),
            DeletionRequestValue::deserialize,
            "corrupt deletion request",
        )?;

        let mut batch = self.db.batch();
        batch.remove(&self.infra, primary_key.as_slice());

        if let Some(v) = val {
            let did_key = deletion_by_did_key(&v.did);
            batch.remove(&self.infra, did_key.as_slice());
        }

        batch.commit().map_err(MetastoreError::Fjall)
    }

    pub fn delete_deletion_requests_by_did(&self, did: &Did) -> Result<(), MetastoreError> {
        let did_key = deletion_by_did_key(did.as_str());
        let token = match self
            .infra
            .get(did_key.as_slice())
            .map_err(MetastoreError::Fjall)?
        {
            Some(raw) => String::from_utf8(raw.to_vec())
                .map_err(|_| MetastoreError::CorruptData("deletion by_did not valid utf8"))?,
            None => return Ok(()),
        };

        let primary_key = deletion_request_key(&token);
        let mut batch = self.db.batch();
        batch.remove(&self.infra, primary_key.as_slice());
        batch.remove(&self.infra, did_key.as_slice());
        batch.commit().map_err(MetastoreError::Fjall)
    }

    pub fn upsert_account_preference(
        &self,
        user_id: Uuid,
        name: &str,
        value_json: serde_json::Value,
    ) -> Result<(), MetastoreError> {
        let key = account_pref_key(user_id, name);
        let bytes = serde_json::to_vec(&value_json)
            .map_err(|_| MetastoreError::InvalidInput("invalid json for account preference"))?;
        self.infra
            .insert(key.as_slice(), bytes)
            .map_err(MetastoreError::Fjall)
    }

    pub fn insert_account_preference_if_not_exists(
        &self,
        user_id: Uuid,
        name: &str,
        value_json: serde_json::Value,
    ) -> Result<(), MetastoreError> {
        let key = account_pref_key(user_id, name);
        let existing = self
            .infra
            .get(key.as_slice())
            .map_err(MetastoreError::Fjall)?;
        if existing.is_some() {
            return Ok(());
        }
        let bytes = serde_json::to_vec(&value_json)
            .map_err(|_| MetastoreError::InvalidInput("invalid json for account preference"))?;
        self.infra
            .insert(key.as_slice(), bytes)
            .map_err(MetastoreError::Fjall)
    }

    pub fn get_account_preferences(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<(String, serde_json::Value)>, MetastoreError> {
        let prefix = account_pref_prefix(user_id);

        self.infra
            .prefix(prefix.as_slice())
            .try_fold(Vec::new(), |mut acc, guard| {
                let (key_bytes, val_bytes) = guard.into_inner().map_err(MetastoreError::Fjall)?;
                let mut reader = super::encoding::KeyReader::new(&key_bytes);
                reader.tag();
                reader.bytes();
                let raw_name = reader
                    .string()
                    .ok_or(MetastoreError::CorruptData("corrupt account pref key"))?;
                let name = raw_name
                    .split('\x00')
                    .next()
                    .unwrap_or(&raw_name)
                    .to_owned();
                let value: serde_json::Value = serde_json::from_slice(&val_bytes)
                    .map_err(|_| MetastoreError::CorruptData("corrupt account pref json"))?;
                acc.push((name, value));
                Ok(acc)
            })
    }

    pub fn replace_namespace_preferences(
        &self,
        user_id: Uuid,
        namespace: &str,
        preferences: Vec<(String, serde_json::Value)>,
    ) -> Result<(), MetastoreError> {
        let prefix = account_pref_prefix(user_id);
        let mut batch = self.db.batch();

        self.infra.prefix(prefix.as_slice()).try_for_each(|guard| {
            let (key_bytes, _) = guard.into_inner().map_err(MetastoreError::Fjall)?;
            let mut reader = super::encoding::KeyReader::new(&key_bytes);
            reader.tag();
            reader.bytes();
            let name = reader
                .string()
                .ok_or(MetastoreError::CorruptData("corrupt account pref key"))?;
            if name.starts_with(namespace) {
                batch.remove(&self.infra, key_bytes.as_ref());
            }
            Ok::<(), MetastoreError>(())
        })?;

        let mut counts: std::collections::HashMap<&str, u32> = std::collections::HashMap::new();
        preferences.iter().try_for_each(|(name, value)| {
            let idx = counts.entry(name.as_str()).or_insert(0);
            let indexed_name = match *idx {
                0 => name.clone(),
                n => format!("{}\x00{}", name, n),
            };
            *idx += 1;
            let key = account_pref_key(user_id, &indexed_name);
            let bytes = serde_json::to_vec(value)
                .map_err(|_| MetastoreError::InvalidInput("invalid json for account preference"))?;
            batch.insert(&self.infra, key.as_slice(), bytes);
            Ok::<(), MetastoreError>(())
        })?;

        batch.commit().map_err(MetastoreError::Fjall)
    }

    pub fn get_server_config(&self, key: &str) -> Result<Option<String>, MetastoreError> {
        let k = server_config_key(key);
        match self
            .infra
            .get(k.as_slice())
            .map_err(MetastoreError::Fjall)?
        {
            Some(raw) => String::from_utf8(raw.to_vec())
                .map(Some)
                .map_err(|_| MetastoreError::CorruptData("server config not valid utf8")),
            None => Ok(None),
        }
    }

    pub fn get_server_configs(
        &self,
        keys: &[&str],
    ) -> Result<Vec<(String, String)>, MetastoreError> {
        keys.iter()
            .filter_map(|&key| {
                let k = server_config_key(key);
                match self.infra.get(k.as_slice()) {
                    Ok(Some(raw)) => String::from_utf8(raw.to_vec())
                        .ok()
                        .map(|v| Ok((key.to_owned(), v))),
                    Ok(None) => None,
                    Err(e) => Some(Err(MetastoreError::Fjall(e))),
                }
            })
            .collect()
    }

    pub fn upsert_server_config(&self, key: &str, value: &str) -> Result<(), MetastoreError> {
        let k = server_config_key(key);
        self.infra
            .insert(k.as_slice(), value.as_bytes())
            .map_err(MetastoreError::Fjall)
    }

    pub fn delete_server_config(&self, key: &str) -> Result<(), MetastoreError> {
        let k = server_config_key(key);
        self.infra
            .remove(k.as_slice())
            .map_err(MetastoreError::Fjall)
    }

    pub fn health_check(&self) -> Result<bool, MetastoreError> {
        Ok(true)
    }

    pub fn insert_report(
        &self,
        id: i64,
        reason_type: &str,
        reason: Option<&str>,
        subject_json: serde_json::Value,
        reported_by_did: &Did,
        created_at: DateTime<Utc>,
    ) -> Result<(), MetastoreError> {
        let value = ReportValue {
            id,
            reason_type: reason_type.to_owned(),
            reason: reason.map(str::to_owned),
            subject_json: serde_json::to_vec(&subject_json).unwrap_or_default(),
            reported_by_did: reported_by_did.to_string(),
            created_at_ms: created_at.timestamp_millis(),
        };

        let key = report_key(id);
        self.infra
            .insert(key.as_slice(), value.serialize())
            .map_err(MetastoreError::Fjall)
    }

    pub fn delete_plc_tokens_for_user(&self, user_id: Uuid) -> Result<(), MetastoreError> {
        let prefix = plc_token_prefix(user_id);
        let mut batch = self.db.batch();
        delete_all_by_prefix(&self.infra, &mut batch, prefix.as_slice())?;
        batch.commit().map_err(MetastoreError::Fjall)
    }

    pub fn insert_plc_token(
        &self,
        user_id: Uuid,
        token: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), MetastoreError> {
        let key = plc_token_key(user_id, token);
        let expires_at_ms = expires_at.timestamp_millis();
        self.infra
            .insert(key.as_slice(), expires_at_ms.to_be_bytes())
            .map_err(MetastoreError::Fjall)
    }

    pub fn get_plc_token_expiry(
        &self,
        user_id: Uuid,
        token: &str,
    ) -> Result<Option<DateTime<Utc>>, MetastoreError> {
        let key = plc_token_key(user_id, token);
        match self
            .infra
            .get(key.as_slice())
            .map_err(MetastoreError::Fjall)?
        {
            Some(raw) => {
                let arr: [u8; 8] = raw
                    .as_ref()
                    .try_into()
                    .map_err(|_| MetastoreError::CorruptData("plc token expiry not 8 bytes"))?;
                let ms = i64::from_be_bytes(arr);
                Ok(DateTime::from_timestamp_millis(ms))
            }
            None => Ok(None),
        }
    }

    pub fn delete_plc_token(&self, user_id: Uuid, token: &str) -> Result<(), MetastoreError> {
        let key = plc_token_key(user_id, token);
        self.infra
            .remove(key.as_slice())
            .map_err(MetastoreError::Fjall)
    }

    pub fn get_notification_history(
        &self,
        user_id: Uuid,
        limit: i64,
    ) -> Result<Vec<NotificationHistoryRow>, MetastoreError> {
        let prefix = comms_history_prefix(user_id);
        let limit = usize::try_from(limit).unwrap_or(0);

        self.infra
            .prefix(prefix.as_slice())
            .take(limit)
            .try_fold(Vec::new(), |mut acc, guard| {
                let (_, val_bytes) = guard.into_inner().map_err(MetastoreError::Fjall)?;
                let val = NotificationHistoryValue::deserialize(&val_bytes)
                    .ok_or(MetastoreError::CorruptData("corrupt notification history"))?;
                let channel = u8_to_channel(val.channel)
                    .ok_or(MetastoreError::CorruptData("invalid history channel"))?;
                let comms_type = u8_to_comms_type(val.comms_type)
                    .ok_or(MetastoreError::CorruptData("invalid history comms type"))?;
                let status = u8_to_status(val.status)
                    .ok_or(MetastoreError::CorruptData("invalid history status"))?;
                acc.push(NotificationHistoryRow {
                    created_at: DateTime::from_timestamp_millis(val.created_at_ms)
                        .unwrap_or_default(),
                    channel,
                    comms_type,
                    status,
                    subject: val.subject,
                    body: val.body,
                });
                Ok(acc)
            })
    }

    pub fn get_blob_storage_key_by_cid(
        &self,
        cid: &CidLink,
    ) -> Result<Option<String>, MetastoreError> {
        let cid_str = cid.as_str();
        let cid_index_key = blob_by_cid_key(cid_str);
        let user_hash_raw = match self
            .repo_data
            .get(cid_index_key.as_slice())
            .map_err(MetastoreError::Fjall)?
        {
            Some(raw) => {
                let arr: [u8; 8] = raw
                    .as_ref()
                    .try_into()
                    .map_err(|_| MetastoreError::CorruptData("blob_by_cid value not 8 bytes"))?;
                u64::from_be_bytes(arr)
            }
            None => return Ok(None),
        };
        let user_hash = UserHash::from_raw(user_hash_raw);
        let key = blob_meta_key(user_hash, cid_str);
        let val: Option<BlobMetaValue> = point_lookup(
            &self.repo_data,
            key.as_slice(),
            BlobMetaValue::deserialize,
            "corrupt blob_meta value",
        )?;
        Ok(val.map(|v| v.storage_key))
    }

    pub fn delete_blob_by_cid(&self, cid: &CidLink) -> Result<(), MetastoreError> {
        let cid_str = cid.as_str();
        let cid_index_key = blob_by_cid_key(cid_str);
        let user_hash_raw = match self
            .repo_data
            .get(cid_index_key.as_slice())
            .map_err(MetastoreError::Fjall)?
        {
            Some(raw) => {
                let arr: [u8; 8] = raw
                    .as_ref()
                    .try_into()
                    .map_err(|_| MetastoreError::CorruptData("blob_by_cid value not 8 bytes"))?;
                u64::from_be_bytes(arr)
            }
            None => return Ok(()),
        };
        let user_hash = UserHash::from_raw(user_hash_raw);
        let primary_key = blob_meta_key(user_hash, cid_str);

        let mut batch = self.db.batch();
        batch.remove(&self.repo_data, primary_key.as_slice());
        batch.remove(&self.repo_data, cid_index_key.as_slice());
        batch.commit().map_err(MetastoreError::Fjall)
    }

    pub fn get_admin_account_info_by_did(
        &self,
        did: &Did,
    ) -> Result<Option<AdminAccountInfo>, MetastoreError> {
        let user_hash = UserHash::from_did(did.as_str());
        self.resolve_user_value(user_hash)
            .map(|u| self.user_to_admin_info(&u))
            .transpose()
    }

    pub fn get_admin_account_infos_by_dids(
        &self,
        dids: &[Did],
    ) -> Result<Vec<AdminAccountInfo>, MetastoreError> {
        dids.iter()
            .filter_map(|did| {
                let user_hash = UserHash::from_did(did.as_str());
                self.resolve_user_value(user_hash)
                    .map(|u| self.user_to_admin_info(&u))
            })
            .collect()
    }

    pub fn get_invite_code_uses_by_users(
        &self,
        user_ids: &[Uuid],
    ) -> Result<Vec<(Uuid, String)>, MetastoreError> {
        user_ids
            .iter()
            .filter_map(|&uid| {
                let key = invite_code_used_by_key(uid);
                match self.infra.get(key.as_slice()) {
                    Ok(Some(raw)) => String::from_utf8(raw.to_vec())
                        .ok()
                        .map(|code| Ok((uid, code))),
                    Ok(None) => None,
                    Err(e) => Some(Err(MetastoreError::Fjall(e))),
                }
            })
            .collect()
    }

    pub fn get_deletion_request_by_did(
        &self,
        did: &Did,
    ) -> Result<Option<DeletionRequestWithToken>, MetastoreError> {
        let did_key = deletion_by_did_key(did.as_str());
        let token = match self
            .infra
            .get(did_key.as_slice())
            .map_err(MetastoreError::Fjall)?
        {
            Some(raw) => String::from_utf8(raw.to_vec())
                .map_err(|_| MetastoreError::CorruptData("deletion by_did not valid utf8"))?,
            None => return Ok(None),
        };

        let primary_key = deletion_request_key(&token);
        let val: Option<DeletionRequestValue> = point_lookup(
            &self.infra,
            primary_key.as_slice(),
            DeletionRequestValue::deserialize,
            "corrupt deletion request",
        )?;
        Ok(val.map(|v| DeletionRequestWithToken {
            token,
            did: Did::new(v.did).expect("valid DID in database"),
            expires_at: DateTime::from_timestamp_millis(v.expires_at_ms).unwrap_or_default(),
        }))
    }

    pub fn get_latest_comms_for_user(
        &self,
        user_id: Uuid,
        comms_type: CommsType,
        limit: i64,
    ) -> Result<Vec<QueuedComms>, MetastoreError> {
        let target_type = comms_type_to_u8(comms_type);
        let limit = usize::try_from(limit).unwrap_or(0);
        let prefix = comms_queue_prefix();

        let mut results: Vec<QueuedComms> = self
            .infra
            .prefix(prefix.as_slice())
            .map(|guard| -> Result<Option<QueuedComms>, MetastoreError> {
                let (_, val_bytes) = guard.into_inner().map_err(MetastoreError::Fjall)?;
                let val = QueuedCommsValue::deserialize(&val_bytes)
                    .ok_or(MetastoreError::CorruptData("corrupt comms queue entry"))?;
                let matches_user = val.user_id == Some(user_id);
                let matches_type = val.comms_type == target_type;
                match matches_user && matches_type {
                    true => Ok(Some(self.value_to_queued_comms(&val)?)),
                    false => Ok(None),
                }
            })
            .filter_map(Result::transpose)
            .collect::<Result<Vec<_>, _>>()?;

        results.sort_by_key(|r| std::cmp::Reverse(r.created_at));
        results.truncate(limit);
        Ok(results)
    }

    pub fn count_comms_by_type(
        &self,
        user_id: Uuid,
        comms_type: CommsType,
    ) -> Result<i64, MetastoreError> {
        let target_type = comms_type_to_u8(comms_type);
        let prefix = comms_queue_prefix();

        let count = self
            .infra
            .prefix(prefix.as_slice())
            .try_fold(0i64, |acc, guard| {
                let (_, val_bytes) = guard.into_inner().map_err(MetastoreError::Fjall)?;
                let val = QueuedCommsValue::deserialize(&val_bytes)
                    .ok_or(MetastoreError::CorruptData("corrupt comms queue entry"))?;
                let matches = val.user_id == Some(user_id) && val.comms_type == target_type;
                Ok::<i64, MetastoreError>(acc + i64::from(matches))
            })?;

        Ok(count)
    }

    pub fn delete_comms_by_type_for_user(
        &self,
        user_id: Uuid,
        comms_type: CommsType,
    ) -> Result<u64, MetastoreError> {
        let target_type = comms_type_to_u8(comms_type);
        let prefix = comms_queue_prefix();

        let keys_to_delete: Vec<Vec<u8>> = self
            .infra
            .prefix(prefix.as_slice())
            .map(|guard| -> Result<Option<Vec<u8>>, MetastoreError> {
                let (key_bytes, val_bytes) = guard.into_inner().map_err(MetastoreError::Fjall)?;
                let val = QueuedCommsValue::deserialize(&val_bytes)
                    .ok_or(MetastoreError::CorruptData("corrupt comms queue entry"))?;
                let matches = val.user_id == Some(user_id) && val.comms_type == target_type;
                match matches {
                    true => Ok(Some(key_bytes.to_vec())),
                    false => Ok(None),
                }
            })
            .filter_map(Result::transpose)
            .collect::<Result<Vec<_>, _>>()?;

        let count = u64::try_from(keys_to_delete.len()).unwrap_or(u64::MAX);
        let mut batch = self.db.batch();
        keys_to_delete
            .iter()
            .for_each(|k| batch.remove(&self.infra, k.as_slice()));
        batch.commit().map_err(MetastoreError::Fjall)?;
        Ok(count)
    }

    pub fn expire_deletion_request(&self, token: &str) -> Result<(), MetastoreError> {
        let key = deletion_request_key(token);
        let mut val: DeletionRequestValue = point_lookup(
            &self.infra,
            key.as_slice(),
            DeletionRequestValue::deserialize,
            "corrupt deletion request",
        )?
        .ok_or(MetastoreError::InvalidInput("deletion request not found"))?;

        val.expires_at_ms = Utc::now().timestamp_millis() - 3_600_000;
        self.infra
            .insert(key.as_slice(), val.serialize())
            .map_err(MetastoreError::Fjall)
    }

    pub fn get_reserved_signing_key_full(
        &self,
        public_key_did_key: &str,
    ) -> Result<Option<ReservedSigningKeyFull>, MetastoreError> {
        let key = signing_key_key(public_key_did_key);
        let val: Option<SigningKeyValue> = point_lookup(
            &self.infra,
            key.as_slice(),
            SigningKeyValue::deserialize,
            "corrupt signing key",
        )?;
        Ok(val.map(|v| ReservedSigningKeyFull {
            id: v.id,
            did: v.did.and_then(|d| Did::new(d).ok()),
            public_key_did_key: v.public_key_did_key,
            private_key_bytes: v.private_key_bytes,
            expires_at: DateTime::from_timestamp_millis(v.expires_at_ms).unwrap_or_default(),
            used_at: v.used_at_ms.and_then(DateTime::from_timestamp_millis),
        }))
    }

    pub fn get_plc_tokens_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<PlcTokenInfo>, MetastoreError> {
        let prefix = plc_token_prefix(user_id);
        self.infra
            .prefix(prefix.as_slice())
            .map(|guard| -> Result<PlcTokenInfo, MetastoreError> {
                let (key_bytes, val_bytes) = guard.into_inner().map_err(MetastoreError::Fjall)?;
                let arr: [u8; 8] = val_bytes
                    .as_ref()
                    .try_into()
                    .map_err(|_| MetastoreError::CorruptData("plc token expiry not 8 bytes"))?;
                let expires_at =
                    DateTime::from_timestamp_millis(i64::from_be_bytes(arr)).unwrap_or_default();
                let mut reader = super::encoding::KeyReader::new(&key_bytes);
                let _tag = reader.tag();
                let _user_id = reader.bytes();
                let token = reader
                    .string()
                    .ok_or(MetastoreError::CorruptData("plc token key missing token"))?;
                Ok(PlcTokenInfo { token, expires_at })
            })
            .collect()
    }

    pub fn count_plc_tokens_for_user(&self, user_id: Uuid) -> Result<i64, MetastoreError> {
        let prefix = plc_token_prefix(user_id);
        Ok(self
            .infra
            .prefix(prefix.as_slice())
            .count()
            .try_into()
            .unwrap_or(0))
    }
}
