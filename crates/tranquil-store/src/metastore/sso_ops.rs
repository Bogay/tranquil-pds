use chrono::{DateTime, Utc};
use fjall::{Database, Keyspace};
use uuid::Uuid;

use super::MetastoreError;
use super::keys::UserHash;
use super::scan::point_lookup;
use super::sso_schema::{
    ExternalIdentityValue, PendingRegistrationValue, SsoAuthStateValue, auth_state_key,
    auth_state_prefix, by_id_key, by_provider_key, identity_key, identity_user_prefix,
    pending_reg_key, pending_reg_prefix, provider_to_u8, u8_to_provider,
};

use tranquil_db_traits::{
    ExternalEmail, ExternalIdentity, ExternalUserId, ExternalUsername, SsoAction, SsoAuthState,
    SsoPendingRegistration, SsoProviderType,
};
use tranquil_types::Did;

pub struct SsoOps {
    db: Database,
    indexes: Keyspace,
}

impl SsoOps {
    pub fn new(db: Database, indexes: Keyspace) -> Self {
        Self { db, indexes }
    }

    fn value_to_identity(v: &ExternalIdentityValue) -> Result<ExternalIdentity, MetastoreError> {
        Ok(ExternalIdentity {
            id: v.id,
            did: Did::new(v.did.clone())
                .map_err(|_| MetastoreError::CorruptData("invalid did in sso identity"))?,
            provider: u8_to_provider(v.provider)
                .ok_or(MetastoreError::CorruptData("unknown sso provider"))?,
            provider_user_id: ExternalUserId::new(v.provider_user_id.clone()),
            provider_username: v
                .provider_username
                .as_ref()
                .map(|s| ExternalUsername::new(s.clone())),
            provider_email: v
                .provider_email
                .as_ref()
                .map(|s| ExternalEmail::new(s.clone())),
            created_at: DateTime::from_timestamp_millis(v.created_at_ms).unwrap_or_default(),
            updated_at: DateTime::from_timestamp_millis(v.updated_at_ms).unwrap_or_default(),
            last_login_at: v.last_login_at_ms.and_then(DateTime::from_timestamp_millis),
        })
    }

    fn value_to_auth_state(v: &SsoAuthStateValue) -> Result<SsoAuthState, MetastoreError> {
        Ok(SsoAuthState {
            state: v.state.clone(),
            request_uri: v.request_uri.clone(),
            provider: u8_to_provider(v.provider)
                .ok_or(MetastoreError::CorruptData("unknown sso provider"))?,
            action: SsoAction::parse(&v.action)
                .ok_or(MetastoreError::CorruptData("unknown sso action"))?,
            nonce: v.nonce.clone(),
            code_verifier: v.code_verifier.clone(),
            did: v
                .did
                .as_ref()
                .map(|d| Did::new(d.clone()))
                .transpose()
                .map_err(|_| MetastoreError::CorruptData("invalid did in sso auth state"))?,
            created_at: DateTime::from_timestamp_millis(v.created_at_ms).unwrap_or_default(),
            expires_at: DateTime::from_timestamp_millis(v.expires_at_ms).unwrap_or_default(),
        })
    }

    fn value_to_pending_reg(
        v: &PendingRegistrationValue,
    ) -> Result<SsoPendingRegistration, MetastoreError> {
        Ok(SsoPendingRegistration {
            token: v.token.clone(),
            request_uri: v.request_uri.clone(),
            provider: u8_to_provider(v.provider)
                .ok_or(MetastoreError::CorruptData("unknown sso provider"))?,
            provider_user_id: ExternalUserId::new(v.provider_user_id.clone()),
            provider_username: v
                .provider_username
                .as_ref()
                .map(|s| ExternalUsername::new(s.clone())),
            provider_email: v
                .provider_email
                .as_ref()
                .map(|s| ExternalEmail::new(s.clone())),
            provider_email_verified: v.provider_email_verified,
            created_at: DateTime::from_timestamp_millis(v.created_at_ms).unwrap_or_default(),
            expires_at: DateTime::from_timestamp_millis(v.expires_at_ms).unwrap_or_default(),
        })
    }

    pub fn create_external_identity(
        &self,
        did: &Did,
        provider: SsoProviderType,
        provider_user_id: &str,
        provider_username: Option<&str>,
        provider_email: Option<&str>,
    ) -> Result<Uuid, MetastoreError> {
        let user_hash = UserHash::from_did(did.as_str());
        let prov_u8 = provider_to_u8(provider);
        let id = Uuid::new_v4();
        let now_ms = Utc::now().timestamp_millis();

        let value = ExternalIdentityValue {
            id,
            did: did.to_string(),
            provider: prov_u8,
            provider_user_id: provider_user_id.to_owned(),
            provider_username: provider_username.map(str::to_owned),
            provider_email: provider_email.map(str::to_owned),
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
            last_login_at_ms: None,
        };

        let primary = identity_key(user_hash, prov_u8, provider_user_id);
        let provider_index = by_provider_key(prov_u8, provider_user_id);
        let id_index = by_id_key(id);

        let provider_index_val = {
            let mut buf = Vec::with_capacity(8 + 16);
            buf.extend_from_slice(&user_hash.raw().to_be_bytes());
            buf.extend_from_slice(id.as_bytes());
            buf
        };

        let id_index_val = {
            let puid_bytes = provider_user_id.as_bytes();
            let mut buf = Vec::with_capacity(8 + 1 + puid_bytes.len());
            buf.extend_from_slice(&user_hash.raw().to_be_bytes());
            buf.push(prov_u8);
            buf.extend_from_slice(puid_bytes);
            buf
        };

        let mut batch = self.db.batch();
        batch.insert(&self.indexes, primary.as_slice(), value.serialize());
        batch.insert(&self.indexes, provider_index.as_slice(), provider_index_val);
        batch.insert(&self.indexes, id_index.as_slice(), id_index_val);
        batch.commit().map_err(MetastoreError::Fjall)?;

        Ok(id)
    }

    pub fn get_external_identity_by_provider(
        &self,
        provider: SsoProviderType,
        provider_user_id: &str,
    ) -> Result<Option<ExternalIdentity>, MetastoreError> {
        let prov_u8 = provider_to_u8(provider);
        let index = by_provider_key(prov_u8, provider_user_id);

        let index_val = match self
            .indexes
            .get(index.as_slice())
            .map_err(MetastoreError::Fjall)?
        {
            Some(v) => v,
            None => return Ok(None),
        };

        let (user_hash_raw, _id_bytes) = index_val.as_ref().split_at(8);
        let user_hash =
            UserHash::from_raw(u64::from_be_bytes(user_hash_raw.try_into().map_err(
                |_| MetastoreError::CorruptData("corrupt sso by_provider index"),
            )?));

        let primary = identity_key(user_hash, prov_u8, provider_user_id);
        let val: Option<ExternalIdentityValue> = point_lookup(
            &self.indexes,
            primary.as_slice(),
            ExternalIdentityValue::deserialize,
            "corrupt sso identity",
        )?;

        val.map(|v| Self::value_to_identity(&v)).transpose()
    }

    pub fn get_external_identities_by_did(
        &self,
        did: &Did,
    ) -> Result<Vec<ExternalIdentity>, MetastoreError> {
        let user_hash = UserHash::from_did(did.as_str());
        let prefix = identity_user_prefix(user_hash);

        self.indexes
            .prefix(prefix.as_slice())
            .try_fold(Vec::new(), |mut acc, guard| {
                let (_, val_bytes) = guard.into_inner().map_err(MetastoreError::Fjall)?;
                let val = ExternalIdentityValue::deserialize(&val_bytes)
                    .ok_or(MetastoreError::CorruptData("corrupt sso identity"))?;
                acc.push(Self::value_to_identity(&val)?);
                Ok::<_, MetastoreError>(acc)
            })
    }

    pub fn update_external_identity_login(
        &self,
        id: Uuid,
        provider_username: Option<&str>,
        provider_email: Option<&str>,
    ) -> Result<(), MetastoreError> {
        let id_idx = by_id_key(id);
        let id_val = match self
            .indexes
            .get(id_idx.as_slice())
            .map_err(MetastoreError::Fjall)?
        {
            Some(v) => v,
            None => return Ok(()),
        };

        let raw = id_val.as_ref();
        if raw.len() < 9 {
            return Err(MetastoreError::CorruptData("corrupt sso by_id index"));
        }
        let user_hash = UserHash::from_raw(u64::from_be_bytes(
            raw[..8]
                .try_into()
                .map_err(|_| MetastoreError::CorruptData("corrupt sso by_id index"))?,
        ));
        let provider = raw[8];
        let provider_user_id = std::str::from_utf8(&raw[9..])
            .map_err(|_| MetastoreError::CorruptData("corrupt sso by_id index"))?;

        let primary = identity_key(user_hash, provider, provider_user_id);
        let existing: Option<ExternalIdentityValue> = point_lookup(
            &self.indexes,
            primary.as_slice(),
            ExternalIdentityValue::deserialize,
            "corrupt sso identity",
        )?;

        match existing {
            Some(mut val) => {
                val.provider_username = provider_username.map(str::to_owned);
                val.provider_email = provider_email.map(str::to_owned);
                let now_ms = Utc::now().timestamp_millis();
                val.last_login_at_ms = Some(now_ms);
                val.updated_at_ms = now_ms;
                self.indexes
                    .insert(primary.as_slice(), val.serialize())
                    .map_err(MetastoreError::Fjall)?;
                Ok(())
            }
            None => Ok(()),
        }
    }

    pub fn delete_external_identity(&self, id: Uuid, _did: &Did) -> Result<bool, MetastoreError> {
        let id_idx = by_id_key(id);
        let id_val = match self
            .indexes
            .get(id_idx.as_slice())
            .map_err(MetastoreError::Fjall)?
        {
            Some(v) => v,
            None => return Ok(false),
        };

        let raw = id_val.as_ref();
        if raw.len() < 9 {
            return Err(MetastoreError::CorruptData("corrupt sso by_id index"));
        }
        let user_hash = UserHash::from_raw(u64::from_be_bytes(
            raw[..8]
                .try_into()
                .map_err(|_| MetastoreError::CorruptData("corrupt sso by_id index"))?,
        ));
        let provider = raw[8];
        let provider_user_id = std::str::from_utf8(&raw[9..])
            .map_err(|_| MetastoreError::CorruptData("corrupt sso by_id index"))?;

        let primary = identity_key(user_hash, provider, provider_user_id);
        let provider_idx = by_provider_key(provider, provider_user_id);

        let mut batch = self.db.batch();
        batch.remove(&self.indexes, primary.as_slice());
        batch.remove(&self.indexes, provider_idx.as_slice());
        batch.remove(&self.indexes, id_idx.as_slice());
        batch.commit().map_err(MetastoreError::Fjall)?;

        Ok(true)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_sso_auth_state(
        &self,
        state: &str,
        request_uri: &str,
        provider: SsoProviderType,
        action: SsoAction,
        nonce: Option<&str>,
        code_verifier: Option<&str>,
        did: Option<&Did>,
    ) -> Result<(), MetastoreError> {
        let now_ms = Utc::now().timestamp_millis();
        let expires_at_ms = now_ms.saturating_add(600_000);

        let value = SsoAuthStateValue {
            state: state.to_owned(),
            request_uri: request_uri.to_owned(),
            provider: provider_to_u8(provider),
            action: action.as_str().to_owned(),
            nonce: nonce.map(str::to_owned),
            code_verifier: code_verifier.map(str::to_owned),
            did: did.map(|d| d.to_string()),
            created_at_ms: now_ms,
            expires_at_ms,
        };

        let key = auth_state_key(state);
        self.indexes
            .insert(key.as_slice(), value.serialize())
            .map_err(MetastoreError::Fjall)?;
        Ok(())
    }

    pub fn consume_sso_auth_state(
        &self,
        state: &str,
    ) -> Result<Option<SsoAuthState>, MetastoreError> {
        let key = auth_state_key(state);

        let val: Option<SsoAuthStateValue> = point_lookup(
            &self.indexes,
            key.as_slice(),
            SsoAuthStateValue::deserialize,
            "corrupt sso auth state",
        )?;

        match val {
            Some(v) => {
                self.indexes
                    .remove(key.as_slice())
                    .map_err(MetastoreError::Fjall)?;
                let now_ms = Utc::now().timestamp_millis();
                match v.expires_at_ms < now_ms {
                    true => Ok(None),
                    false => Self::value_to_auth_state(&v).map(Some),
                }
            }
            None => Ok(None),
        }
    }

    pub fn cleanup_expired_sso_auth_states(&self) -> Result<u64, MetastoreError> {
        let prefix = auth_state_prefix();
        let now_ms = Utc::now().timestamp_millis();
        let mut count = 0u64;
        let mut batch = self.db.batch();

        self.indexes
            .prefix(prefix.as_slice())
            .try_for_each(|guard| {
                let (key_bytes, val_bytes) = guard.into_inner().map_err(MetastoreError::Fjall)?;
                let val = SsoAuthStateValue::deserialize(&val_bytes)
                    .ok_or(MetastoreError::CorruptData("corrupt sso auth state"))?;
                if val.expires_at_ms < now_ms {
                    batch.remove(&self.indexes, key_bytes.as_ref());
                    count = count.saturating_add(1);
                }
                Ok::<_, MetastoreError>(())
            })?;

        batch.commit().map_err(MetastoreError::Fjall)?;
        Ok(count)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_pending_registration(
        &self,
        token: &str,
        request_uri: &str,
        provider: SsoProviderType,
        provider_user_id: &str,
        provider_username: Option<&str>,
        provider_email: Option<&str>,
        provider_email_verified: bool,
    ) -> Result<(), MetastoreError> {
        let now_ms = Utc::now().timestamp_millis();
        let expires_at_ms = now_ms.saturating_add(600_000);

        let value = PendingRegistrationValue {
            token: token.to_owned(),
            request_uri: request_uri.to_owned(),
            provider: provider_to_u8(provider),
            provider_user_id: provider_user_id.to_owned(),
            provider_username: provider_username.map(str::to_owned),
            provider_email: provider_email.map(str::to_owned),
            provider_email_verified,
            created_at_ms: now_ms,
            expires_at_ms,
        };

        let key = pending_reg_key(token);
        self.indexes
            .insert(key.as_slice(), value.serialize())
            .map_err(MetastoreError::Fjall)?;
        Ok(())
    }

    pub fn get_pending_registration(
        &self,
        token: &str,
    ) -> Result<Option<SsoPendingRegistration>, MetastoreError> {
        let key = pending_reg_key(token);
        let val: Option<PendingRegistrationValue> = point_lookup(
            &self.indexes,
            key.as_slice(),
            PendingRegistrationValue::deserialize,
            "corrupt sso pending registration",
        )?;

        match val {
            Some(v) => {
                let now_ms = Utc::now().timestamp_millis();
                match v.expires_at_ms < now_ms {
                    true => Ok(None),
                    false => Self::value_to_pending_reg(&v).map(Some),
                }
            }
            None => Ok(None),
        }
    }

    pub fn consume_pending_registration(
        &self,
        token: &str,
    ) -> Result<Option<SsoPendingRegistration>, MetastoreError> {
        let key = pending_reg_key(token);
        let val: Option<PendingRegistrationValue> = point_lookup(
            &self.indexes,
            key.as_slice(),
            PendingRegistrationValue::deserialize,
            "corrupt sso pending registration",
        )?;

        match val {
            Some(v) => {
                self.indexes
                    .remove(key.as_slice())
                    .map_err(MetastoreError::Fjall)?;
                let now_ms = Utc::now().timestamp_millis();
                match v.expires_at_ms < now_ms {
                    true => Ok(None),
                    false => Self::value_to_pending_reg(&v).map(Some),
                }
            }
            None => Ok(None),
        }
    }

    pub fn cleanup_expired_pending_registrations(&self) -> Result<u64, MetastoreError> {
        let prefix = pending_reg_prefix();
        let now_ms = Utc::now().timestamp_millis();
        let mut count = 0u64;
        let mut batch = self.db.batch();

        self.indexes
            .prefix(prefix.as_slice())
            .try_for_each(|guard| {
                let (key_bytes, val_bytes) = guard.into_inner().map_err(MetastoreError::Fjall)?;
                let val = PendingRegistrationValue::deserialize(&val_bytes).ok_or(
                    MetastoreError::CorruptData("corrupt sso pending registration"),
                )?;
                if val.expires_at_ms < now_ms {
                    batch.remove(&self.indexes, key_bytes.as_ref());
                    count = count.saturating_add(1);
                }
                Ok::<_, MetastoreError>(())
            })?;

        batch.commit().map_err(MetastoreError::Fjall)?;
        Ok(count)
    }
}
