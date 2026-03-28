use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use fjall::{Database, Keyspace};
use uuid::Uuid;

use super::MetastoreError;
use super::keys::UserHash;
use super::oauth_schema::{
    AccountDeviceValue, AuthorizedClientValue, DeviceTrustValue, DpopJtiValue, OAuthDeviceValue,
    OAuthRequestValue, OAuthTokenValue, ScopePrefsValue, TokenIndexValue, TwoFactorChallengeValue,
    UsedRefreshValue, deserialize_family_counter, oauth_2fa_by_request_key,
    oauth_2fa_challenge_key, oauth_2fa_challenge_prefix, oauth_account_device_key,
    oauth_auth_by_code_key, oauth_auth_client_key, oauth_auth_request_key,
    oauth_auth_request_prefix, oauth_device_key, oauth_device_trust_key, oauth_device_trust_prefix,
    oauth_dpop_jti_key, oauth_dpop_jti_prefix, oauth_scope_prefs_key, oauth_token_by_family_key,
    oauth_token_by_id_key, oauth_token_by_prev_refresh_key, oauth_token_by_refresh_key,
    oauth_token_family_counter_key, oauth_token_key, oauth_token_user_prefix,
    oauth_used_refresh_key, serialize_family_counter,
};
use super::scan::point_lookup;
use super::users::UserValue;

use tranquil_db_traits::{
    DeviceAccountRow, DeviceTrustInfo, OAuthSessionListItem, ScopePreference, TokenFamilyId,
    TrustedDeviceRow, TwoFactorChallenge,
};
use tranquil_oauth::{AuthorizedClientData, DeviceData, RequestData, TokenData};
use tranquil_types::{
    AuthorizationCode, ClientId, DPoPProofId, DeviceId, Did, Handle, RefreshToken, RequestId,
    TokenId,
};

pub struct OAuthOps {
    db: Database,
    auth: Keyspace,
    users: Keyspace,
    counter_lock: Arc<parking_lot::Mutex<()>>,
}

impl OAuthOps {
    pub fn new(
        db: Database,
        auth: Keyspace,
        users: Keyspace,
        counter_lock: Arc<parking_lot::Mutex<()>>,
    ) -> Self {
        Self {
            db,
            auth,
            users,
            counter_lock,
        }
    }

    fn resolve_user_hash_from_did(&self, did: &str) -> UserHash {
        UserHash::from_did(did)
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

    fn next_family_id(&self) -> Result<i32, MetastoreError> {
        let _guard = self.counter_lock.lock();
        let counter_key = oauth_token_family_counter_key();
        let current = self
            .auth
            .get(counter_key.as_slice())
            .map_err(MetastoreError::Fjall)?
            .and_then(|raw| deserialize_family_counter(&raw))
            .unwrap_or(0);
        let next = current.saturating_add(1);
        self.auth
            .insert(counter_key.as_slice(), serialize_family_counter(next))
            .map_err(MetastoreError::Fjall)?;
        Ok(next)
    }

    fn load_token_by_family_id(
        &self,
        user_hash: UserHash,
        family_id: i32,
    ) -> Result<Option<OAuthTokenValue>, MetastoreError> {
        let key = oauth_token_key(user_hash, family_id);
        point_lookup(
            &self.auth,
            key.as_slice(),
            OAuthTokenValue::deserialize,
            "corrupt oauth token",
        )
    }

    fn token_value_to_data(&self, v: &OAuthTokenValue) -> Result<TokenData, MetastoreError> {
        let did = Did::new(v.did.clone())
            .map_err(|_| MetastoreError::CorruptData("invalid did in oauth token"))?;
        let token_id = tranquil_oauth::TokenId(v.token_id.clone());
        let refresh_token = if v.refresh_token.is_empty() {
            None
        } else {
            Some(tranquil_oauth::RefreshToken(v.refresh_token.clone()))
        };

        Ok(TokenData {
            did,
            token_id,
            created_at: DateTime::from_timestamp_millis(v.created_at_ms).unwrap_or_default(),
            updated_at: DateTime::from_timestamp_millis(v.updated_at_ms).unwrap_or_default(),
            expires_at: DateTime::from_timestamp_millis(v.expires_at_ms).unwrap_or_default(),
            client_id: v.client_id.clone(),
            client_auth: tranquil_oauth::ClientAuth::None,
            device_id: None,
            parameters: serde_json::from_str(&v.parameters_json)
                .unwrap_or_else(|_| default_parameters(&v.client_id)),
            details: None,
            code: None,
            current_refresh_token: refresh_token,
            scope: Some(v.scope.clone()).filter(|s| !s.is_empty()),
            controller_did: v
                .controller_did
                .as_ref()
                .and_then(|d| Did::new(d.clone()).ok()),
        })
    }

    fn delete_token_indexes(
        &self,
        batch: &mut fjall::OwnedWriteBatch,
        token: &OAuthTokenValue,
        user_hash: UserHash,
    ) {
        batch.remove(
            &self.auth,
            oauth_token_key(user_hash, token.family_id).as_slice(),
        );
        batch.remove(
            &self.auth,
            oauth_token_by_id_key(&token.token_id).as_slice(),
        );
        batch.remove(
            &self.auth,
            oauth_token_by_refresh_key(&token.refresh_token).as_slice(),
        );
        if let Some(prev) = &token.previous_refresh_token {
            batch.remove(&self.auth, oauth_token_by_prev_refresh_key(prev).as_slice());
        }
        batch.remove(
            &self.auth,
            oauth_token_by_family_key(token.family_id).as_slice(),
        );
    }

    fn collect_tokens_for_did(
        &self,
        user_hash: UserHash,
    ) -> Result<Vec<OAuthTokenValue>, MetastoreError> {
        let prefix = oauth_token_user_prefix(user_hash);
        self.auth
            .prefix(prefix.as_slice())
            .try_fold(Vec::new(), |mut acc, guard| {
                let (_, val_bytes) = guard.into_inner().map_err(MetastoreError::Fjall)?;
                match OAuthTokenValue::deserialize(&val_bytes) {
                    Some(v) => {
                        acc.push(v);
                        Ok::<_, MetastoreError>(acc)
                    }
                    None => Ok(acc),
                }
            })
    }

    fn request_value_to_data(&self, v: &OAuthRequestValue) -> Result<RequestData, MetastoreError> {
        let parameters = serde_json::from_str(&v.parameters_json)
            .map_err(|_| MetastoreError::CorruptData("corrupt oauth request parameters"))?;
        let client_auth = v
            .client_auth_json
            .as_ref()
            .map(|j| serde_json::from_str(j))
            .transpose()
            .map_err(|_| MetastoreError::CorruptData("corrupt oauth client_auth"))?;

        Ok(RequestData {
            client_id: v.client_id.clone(),
            client_auth,
            parameters,
            expires_at: DateTime::from_timestamp_millis(v.expires_at_ms).unwrap_or_default(),
            did: v
                .did
                .as_ref()
                .map(|d| Did::new(d.clone()))
                .transpose()
                .map_err(|_| MetastoreError::CorruptData("invalid did in oauth request"))?,
            device_id: v
                .device_id
                .as_ref()
                .map(|d| tranquil_oauth::DeviceId(d.clone())),
            code: v.code.as_ref().map(|c| tranquil_oauth::Code(c.clone())),
            controller_did: v
                .controller_did
                .as_ref()
                .map(|d| Did::new(d.clone()))
                .transpose()
                .map_err(|_| {
                    MetastoreError::CorruptData("invalid controller_did in oauth request")
                })?,
        })
    }

    fn data_to_request_value(&self, data: &RequestData) -> OAuthRequestValue {
        OAuthRequestValue {
            client_id: data.client_id.clone(),
            client_auth_json: data
                .client_auth
                .as_ref()
                .map(|ca| serde_json::to_string(ca).unwrap_or_default()),
            parameters_json: serde_json::to_string(&data.parameters).unwrap_or_default(),
            expires_at_ms: data.expires_at.timestamp_millis(),
            did: data.did.as_ref().map(|d| d.to_string()),
            device_id: data.device_id.as_ref().map(|d| d.0.clone()),
            code: data.code.as_ref().map(|c| c.0.clone()),
            controller_did: data.controller_did.as_ref().map(|d| d.to_string()),
        }
    }

    pub fn create_token(&self, data: &TokenData) -> Result<TokenFamilyId, MetastoreError> {
        let user_hash = self.resolve_user_hash_from_did(data.did.as_str());
        let family_id = self.next_family_id()?;
        let now_ms = Utc::now().timestamp_millis();

        let value = OAuthTokenValue {
            family_id,
            did: data.did.to_string(),
            client_id: data.client_id.clone(),
            token_id: data.token_id.0.clone(),
            refresh_token: data
                .current_refresh_token
                .as_ref()
                .map(|r| r.0.clone())
                .unwrap_or_default(),
            previous_refresh_token: None,
            scope: data.scope.clone().unwrap_or_default(),
            expires_at_ms: data.expires_at.timestamp_millis(),
            created_at_ms: data.created_at.timestamp_millis(),
            updated_at_ms: now_ms,
            parameters_json: serde_json::to_string(&data.parameters).unwrap_or_default(),
            controller_did: data.controller_did.as_ref().map(|d| d.to_string()),
        };

        let index = TokenIndexValue {
            user_hash: user_hash.raw(),
            family_id,
        };

        let mut batch = self.db.batch();
        batch.insert(
            &self.auth,
            oauth_token_key(user_hash, family_id).as_slice(),
            value.serialize_with_ttl(),
        );
        batch.insert(
            &self.auth,
            oauth_token_by_id_key(&value.token_id).as_slice(),
            index.serialize_with_ttl(value.expires_at_ms),
        );
        if !value.refresh_token.is_empty() {
            batch.insert(
                &self.auth,
                oauth_token_by_refresh_key(&value.refresh_token).as_slice(),
                index.serialize_with_ttl(value.expires_at_ms),
            );
        }
        batch.insert(
            &self.auth,
            oauth_token_by_family_key(family_id).as_slice(),
            index.serialize_with_ttl(value.expires_at_ms),
        );
        batch.commit().map_err(MetastoreError::Fjall)?;

        Ok(TokenFamilyId::new(family_id))
    }

    pub fn get_token_by_id(&self, token_id: &TokenId) -> Result<Option<TokenData>, MetastoreError> {
        let index_key = oauth_token_by_id_key(token_id.as_str());
        let index: Option<TokenIndexValue> = point_lookup(
            &self.auth,
            index_key.as_slice(),
            TokenIndexValue::deserialize,
            "corrupt oauth token index",
        )?;

        match index {
            Some(idx) => {
                let uh = UserHash::from_raw(idx.user_hash);
                self.load_token_by_family_id(uh, idx.family_id)?
                    .map(|v| self.token_value_to_data(&v))
                    .transpose()
            }
            None => Ok(None),
        }
    }

    pub fn get_token_by_refresh_token(
        &self,
        refresh_token: &RefreshToken,
    ) -> Result<Option<(TokenFamilyId, TokenData)>, MetastoreError> {
        let index_key = oauth_token_by_refresh_key(refresh_token.as_str());
        let index: Option<TokenIndexValue> = point_lookup(
            &self.auth,
            index_key.as_slice(),
            TokenIndexValue::deserialize,
            "corrupt oauth token refresh index",
        )?;

        match index {
            Some(idx) => {
                let uh = UserHash::from_raw(idx.user_hash);
                self.load_token_by_family_id(uh, idx.family_id)?
                    .map(|v| {
                        self.token_value_to_data(&v)
                            .map(|td| (TokenFamilyId::new(idx.family_id), td))
                    })
                    .transpose()
            }
            None => Ok(None),
        }
    }

    pub fn get_token_by_previous_refresh_token(
        &self,
        refresh_token: &RefreshToken,
    ) -> Result<Option<(TokenFamilyId, TokenData)>, MetastoreError> {
        let index_key = oauth_token_by_prev_refresh_key(refresh_token.as_str());
        let index: Option<TokenIndexValue> = point_lookup(
            &self.auth,
            index_key.as_slice(),
            TokenIndexValue::deserialize,
            "corrupt oauth token prev refresh index",
        )?;

        match index {
            Some(idx) => {
                let uh = UserHash::from_raw(idx.user_hash);
                self.load_token_by_family_id(uh, idx.family_id)?
                    .map(|v| {
                        self.token_value_to_data(&v)
                            .map(|td| (TokenFamilyId::new(idx.family_id), td))
                    })
                    .transpose()
            }
            None => Ok(None),
        }
    }

    fn lookup_by_family_id(
        &self,
        family_id: i32,
    ) -> Result<Option<(UserHash, OAuthTokenValue)>, MetastoreError> {
        let index_key = oauth_token_by_family_key(family_id);
        let index: Option<TokenIndexValue> = point_lookup(
            &self.auth,
            index_key.as_slice(),
            TokenIndexValue::deserialize,
            "corrupt oauth token family index",
        )?;
        match index {
            Some(idx) => {
                let uh = UserHash::from_raw(idx.user_hash);
                Ok(self
                    .load_token_by_family_id(uh, idx.family_id)?
                    .map(|v| (uh, v)))
            }
            None => Ok(None),
        }
    }

    pub fn rotate_token(
        &self,
        old_db_id: TokenFamilyId,
        new_refresh_token: &RefreshToken,
        new_expires_at: DateTime<Utc>,
    ) -> Result<(), MetastoreError> {
        let (user_hash, mut token) = self
            .lookup_by_family_id(old_db_id.as_i32())?
            .ok_or(MetastoreError::InvalidInput("token family not found"))?;

        let old_refresh = token.refresh_token.clone();
        let old_prev = token.previous_refresh_token.clone();

        token.previous_refresh_token = Some(old_refresh.clone());
        token.refresh_token = new_refresh_token.as_str().to_owned();
        token.expires_at_ms = new_expires_at.timestamp_millis();
        token.updated_at_ms = Utc::now().timestamp_millis();

        let index = TokenIndexValue {
            user_hash: user_hash.raw(),
            family_id: token.family_id,
        };

        let used_val = UsedRefreshValue {
            family_id: token.family_id,
        };

        let mut batch = self.db.batch();
        batch.remove(
            &self.auth,
            oauth_token_by_refresh_key(&old_refresh).as_slice(),
        );
        if let Some(prev) = &old_prev {
            batch.remove(&self.auth, oauth_token_by_prev_refresh_key(prev).as_slice());
        }

        batch.insert(
            &self.auth,
            oauth_token_key(user_hash, token.family_id).as_slice(),
            token.serialize_with_ttl(),
        );
        batch.insert(
            &self.auth,
            oauth_token_by_refresh_key(new_refresh_token.as_str()).as_slice(),
            index.serialize_with_ttl(token.expires_at_ms),
        );
        batch.insert(
            &self.auth,
            oauth_token_by_prev_refresh_key(&old_refresh).as_slice(),
            index.serialize_with_ttl(token.expires_at_ms),
        );
        batch.insert(
            &self.auth,
            oauth_used_refresh_key(&old_refresh).as_slice(),
            used_val.serialize_with_ttl(token.expires_at_ms),
        );
        batch.insert(
            &self.auth,
            oauth_token_by_id_key(&token.token_id).as_slice(),
            index.serialize_with_ttl(token.expires_at_ms),
        );
        batch.insert(
            &self.auth,
            oauth_token_by_family_key(token.family_id).as_slice(),
            index.serialize_with_ttl(token.expires_at_ms),
        );
        batch.commit().map_err(MetastoreError::Fjall)?;

        Ok(())
    }

    pub fn check_refresh_token_used(
        &self,
        refresh_token: &RefreshToken,
    ) -> Result<Option<TokenFamilyId>, MetastoreError> {
        let key = oauth_used_refresh_key(refresh_token.as_str());
        match self
            .auth
            .get(key.as_slice())
            .map_err(MetastoreError::Fjall)?
        {
            Some(raw) => {
                Ok(UsedRefreshValue::deserialize(&raw).map(|v| TokenFamilyId::new(v.family_id)))
            }
            None => Ok(None),
        }
    }

    pub fn delete_token(&self, token_id: &TokenId) -> Result<(), MetastoreError> {
        let index_key = oauth_token_by_id_key(token_id.as_str());
        let index: Option<TokenIndexValue> = point_lookup(
            &self.auth,
            index_key.as_slice(),
            TokenIndexValue::deserialize,
            "corrupt oauth token index",
        )?;

        let idx = match index {
            Some(idx) => idx,
            None => return Ok(()),
        };

        let uh = UserHash::from_raw(idx.user_hash);
        let token = match self.load_token_by_family_id(uh, idx.family_id)? {
            Some(t) => t,
            None => return Ok(()),
        };

        let mut batch = self.db.batch();
        self.delete_token_indexes(&mut batch, &token, uh);
        batch.commit().map_err(MetastoreError::Fjall)?;
        Ok(())
    }

    pub fn delete_token_family(&self, db_id: TokenFamilyId) -> Result<(), MetastoreError> {
        let (user_hash, token) = match self.lookup_by_family_id(db_id.as_i32())? {
            Some(f) => f,
            None => return Ok(()),
        };

        let used_val = UsedRefreshValue {
            family_id: token.family_id,
        };

        let mut batch = self.db.batch();
        self.delete_token_indexes(&mut batch, &token, user_hash);
        if !token.refresh_token.is_empty() {
            batch.insert(
                &self.auth,
                oauth_used_refresh_key(&token.refresh_token).as_slice(),
                used_val.serialize_with_ttl(token.expires_at_ms),
            );
        }
        batch.commit().map_err(MetastoreError::Fjall)?;
        Ok(())
    }

    pub fn list_tokens_for_user(&self, did: &Did) -> Result<Vec<TokenData>, MetastoreError> {
        let user_hash = self.resolve_user_hash_from_did(did.as_str());
        let tokens = self.collect_tokens_for_did(user_hash)?;
        tokens.iter().map(|v| self.token_value_to_data(v)).collect()
    }

    pub fn count_tokens_for_user(&self, did: &Did) -> Result<i64, MetastoreError> {
        let user_hash = self.resolve_user_hash_from_did(did.as_str());
        let prefix = oauth_token_user_prefix(user_hash);
        super::scan::count_prefix(&self.auth, prefix.as_slice())
    }

    pub fn delete_oldest_tokens_for_user(
        &self,
        did: &Did,
        keep_count: i64,
    ) -> Result<u64, MetastoreError> {
        let user_hash = self.resolve_user_hash_from_did(did.as_str());
        let mut tokens = self.collect_tokens_for_did(user_hash)?;
        tokens.sort_by_key(|t| std::cmp::Reverse(t.created_at_ms));

        let keep = usize::try_from(keep_count).unwrap_or(usize::MAX);
        let to_delete: Vec<_> = tokens.into_iter().skip(keep).collect();
        let count = u64::try_from(to_delete.len()).unwrap_or(u64::MAX);

        match count {
            0 => Ok(0),
            _ => {
                let mut batch = self.db.batch();
                to_delete.iter().for_each(|token| {
                    self.delete_token_indexes(&mut batch, token, user_hash);
                });
                batch.commit().map_err(MetastoreError::Fjall)?;
                Ok(count)
            }
        }
    }

    pub fn revoke_tokens_for_client(
        &self,
        did: &Did,
        client_id: &ClientId,
    ) -> Result<u64, MetastoreError> {
        let user_hash = self.resolve_user_hash_from_did(did.as_str());
        let tokens = self.collect_tokens_for_did(user_hash)?;
        let to_revoke: Vec<_> = tokens
            .into_iter()
            .filter(|t| t.client_id == client_id.as_str())
            .collect();

        let count = u64::try_from(to_revoke.len()).unwrap_or(u64::MAX);
        match count {
            0 => Ok(0),
            _ => {
                let mut batch = self.db.batch();
                to_revoke.iter().for_each(|token| {
                    self.delete_token_indexes(&mut batch, token, user_hash);
                });
                batch.commit().map_err(MetastoreError::Fjall)?;
                Ok(count)
            }
        }
    }

    pub fn revoke_tokens_for_controller(
        &self,
        delegated_did: &Did,
        controller_did: &Did,
    ) -> Result<u64, MetastoreError> {
        let user_hash = self.resolve_user_hash_from_did(delegated_did.as_str());
        let tokens = self.collect_tokens_for_did(user_hash)?;
        let controller_str = controller_did.to_string();
        let to_revoke: Vec<_> = tokens
            .into_iter()
            .filter(|t| t.controller_did.as_deref() == Some(controller_str.as_str()))
            .collect();

        let count = u64::try_from(to_revoke.len()).unwrap_or(u64::MAX);
        match count {
            0 => Ok(0),
            _ => {
                let mut batch = self.db.batch();
                to_revoke.iter().for_each(|token| {
                    self.delete_token_indexes(&mut batch, token, user_hash);
                });
                batch.commit().map_err(MetastoreError::Fjall)?;
                Ok(count)
            }
        }
    }

    pub fn create_authorization_request(
        &self,
        request_id: &RequestId,
        data: &RequestData,
    ) -> Result<(), MetastoreError> {
        let value = self.data_to_request_value(data);
        let key = oauth_auth_request_key(request_id.as_str());
        self.auth
            .insert(key.as_slice(), value.serialize_with_ttl())
            .map_err(MetastoreError::Fjall)
    }

    pub fn get_authorization_request(
        &self,
        request_id: &RequestId,
    ) -> Result<Option<RequestData>, MetastoreError> {
        let key = oauth_auth_request_key(request_id.as_str());
        let val: Option<OAuthRequestValue> = point_lookup(
            &self.auth,
            key.as_slice(),
            OAuthRequestValue::deserialize,
            "corrupt oauth auth request",
        )?;

        val.map(|v| self.request_value_to_data(&v)).transpose()
    }

    pub fn set_authorization_did(
        &self,
        request_id: &RequestId,
        did: &Did,
        device_id: Option<&DeviceId>,
    ) -> Result<(), MetastoreError> {
        let key = oauth_auth_request_key(request_id.as_str());
        let mut value: OAuthRequestValue = point_lookup(
            &self.auth,
            key.as_slice(),
            OAuthRequestValue::deserialize,
            "corrupt oauth auth request",
        )?
        .ok_or(MetastoreError::InvalidInput("auth request not found"))?;

        value.did = Some(did.to_string());
        value.device_id = device_id.map(|d| d.as_str().to_owned());

        self.auth
            .insert(key.as_slice(), value.serialize_with_ttl())
            .map_err(MetastoreError::Fjall)
    }

    pub fn update_authorization_request(
        &self,
        request_id: &RequestId,
        did: &Did,
        device_id: Option<&DeviceId>,
        code: &AuthorizationCode,
    ) -> Result<(), MetastoreError> {
        let key = oauth_auth_request_key(request_id.as_str());
        let mut value: OAuthRequestValue = point_lookup(
            &self.auth,
            key.as_slice(),
            OAuthRequestValue::deserialize,
            "corrupt oauth auth request",
        )?
        .ok_or(MetastoreError::InvalidInput("auth request not found"))?;

        value.did = Some(did.to_string());
        value.device_id = device_id.map(|d| d.as_str().to_owned());
        value.code = Some(code.as_str().to_owned());

        let code_index_key = oauth_auth_by_code_key(code.as_str());

        let mut batch = self.db.batch();
        batch.insert(&self.auth, key.as_slice(), value.serialize_with_ttl());
        batch.insert(
            &self.auth,
            code_index_key.as_slice(),
            request_id.as_str().as_bytes(),
        );
        batch.commit().map_err(MetastoreError::Fjall)
    }

    pub fn consume_authorization_request_by_code(
        &self,
        code: &AuthorizationCode,
    ) -> Result<Option<RequestData>, MetastoreError> {
        let code_key = oauth_auth_by_code_key(code.as_str());
        let request_id_bytes = match self
            .auth
            .get(code_key.as_slice())
            .map_err(MetastoreError::Fjall)?
        {
            Some(bytes) => bytes,
            None => return Ok(None),
        };

        let request_id_str = std::str::from_utf8(&request_id_bytes)
            .map_err(|_| MetastoreError::CorruptData("corrupt code index value"))?;
        let req_key = oauth_auth_request_key(request_id_str);

        let value: Option<OAuthRequestValue> = point_lookup(
            &self.auth,
            req_key.as_slice(),
            OAuthRequestValue::deserialize,
            "corrupt oauth auth request",
        )?;

        let data = match value {
            Some(v) => self.request_value_to_data(&v)?,
            None => return Ok(None),
        };

        let mut batch = self.db.batch();
        batch.remove(&self.auth, req_key.as_slice());
        batch.remove(&self.auth, code_key.as_slice());
        batch.commit().map_err(MetastoreError::Fjall)?;

        Ok(Some(data))
    }

    pub fn delete_authorization_request(
        &self,
        request_id: &RequestId,
    ) -> Result<(), MetastoreError> {
        let key = oauth_auth_request_key(request_id.as_str());
        let value: Option<OAuthRequestValue> = point_lookup(
            &self.auth,
            key.as_slice(),
            OAuthRequestValue::deserialize,
            "corrupt oauth auth request",
        )?;

        let mut batch = self.db.batch();
        batch.remove(&self.auth, key.as_slice());
        if let Some(code) = value.and_then(|v| v.code) {
            batch.remove(&self.auth, oauth_auth_by_code_key(&code).as_slice());
        }
        batch.commit().map_err(MetastoreError::Fjall)
    }

    pub fn delete_expired_authorization_requests(&self) -> Result<u64, MetastoreError> {
        let now_ms = Utc::now().timestamp_millis();
        let prefix = oauth_auth_request_prefix();
        let mut keys_to_remove: Vec<(Vec<u8>, Option<String>)> = Vec::new();

        self.auth.prefix(prefix.as_slice()).try_for_each(|guard| {
            let (key_bytes, val_bytes) = guard.into_inner().map_err(MetastoreError::Fjall)?;
            match OAuthRequestValue::deserialize(&val_bytes) {
                Some(v) if v.expires_at_ms <= now_ms => {
                    keys_to_remove.push((key_bytes.to_vec(), v.code));
                    Ok::<(), MetastoreError>(())
                }
                _ => Ok(()),
            }
        })?;

        let count = u64::try_from(keys_to_remove.len()).unwrap_or(u64::MAX);
        match count {
            0 => Ok(0),
            _ => {
                let mut batch = self.db.batch();
                keys_to_remove.iter().for_each(|(key, code)| {
                    batch.remove(&self.auth, key);
                    if let Some(c) = code {
                        batch.remove(&self.auth, oauth_auth_by_code_key(c).as_slice());
                    }
                });
                batch.commit().map_err(MetastoreError::Fjall)?;
                Ok(count)
            }
        }
    }

    pub fn extend_authorization_request_expiry(
        &self,
        request_id: &RequestId,
        new_expires_at: DateTime<Utc>,
    ) -> Result<bool, MetastoreError> {
        let key = oauth_auth_request_key(request_id.as_str());
        let value: Option<OAuthRequestValue> = point_lookup(
            &self.auth,
            key.as_slice(),
            OAuthRequestValue::deserialize,
            "corrupt oauth auth request",
        )?;

        match value {
            Some(mut v) => {
                v.expires_at_ms = new_expires_at.timestamp_millis();
                self.auth
                    .insert(key.as_slice(), v.serialize_with_ttl())
                    .map_err(MetastoreError::Fjall)?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    pub fn mark_request_authenticated(
        &self,
        request_id: &RequestId,
        did: &Did,
        device_id: Option<&DeviceId>,
    ) -> Result<(), MetastoreError> {
        self.set_authorization_did(request_id, did, device_id)
    }

    pub fn update_request_scope(
        &self,
        request_id: &RequestId,
        scope: &str,
    ) -> Result<(), MetastoreError> {
        let key = oauth_auth_request_key(request_id.as_str());
        let mut value: OAuthRequestValue = point_lookup(
            &self.auth,
            key.as_slice(),
            OAuthRequestValue::deserialize,
            "corrupt oauth auth request",
        )?
        .ok_or(MetastoreError::InvalidInput("auth request not found"))?;

        let mut params: serde_json::Value = serde_json::from_str(&value.parameters_json)
            .map_err(|_| MetastoreError::CorruptData("corrupt parameters json"))?;
        params["scope"] = serde_json::Value::String(scope.to_owned());
        value.parameters_json = serde_json::to_string(&params)
            .map_err(|_| MetastoreError::CorruptData("json serialize fail"))?;

        self.auth
            .insert(key.as_slice(), value.serialize_with_ttl())
            .map_err(MetastoreError::Fjall)
    }

    pub fn set_controller_did(
        &self,
        request_id: &RequestId,
        controller_did: &Did,
    ) -> Result<(), MetastoreError> {
        let key = oauth_auth_request_key(request_id.as_str());
        let mut value: OAuthRequestValue = point_lookup(
            &self.auth,
            key.as_slice(),
            OAuthRequestValue::deserialize,
            "corrupt oauth auth request",
        )?
        .ok_or(MetastoreError::InvalidInput("auth request not found"))?;

        value.controller_did = Some(controller_did.to_string());

        self.auth
            .insert(key.as_slice(), value.serialize_with_ttl())
            .map_err(MetastoreError::Fjall)
    }

    pub fn set_request_did(&self, request_id: &RequestId, did: &Did) -> Result<(), MetastoreError> {
        self.set_authorization_did(request_id, did, None)
    }

    pub fn create_device(
        &self,
        device_id: &DeviceId,
        data: &DeviceData,
    ) -> Result<(), MetastoreError> {
        let now_ms = Utc::now().timestamp_millis();
        let value = OAuthDeviceValue {
            session_id: data.session_id.0.clone(),
            user_agent: data.user_agent.clone(),
            ip_address: data.ip_address.clone(),
            last_seen_at_ms: data.last_seen_at.timestamp_millis(),
            created_at_ms: now_ms,
        };

        let key = oauth_device_key(device_id.as_str());
        self.auth
            .insert(key.as_slice(), value.serialize())
            .map_err(MetastoreError::Fjall)
    }

    pub fn get_device(&self, device_id: &DeviceId) -> Result<Option<DeviceData>, MetastoreError> {
        let key = oauth_device_key(device_id.as_str());
        let val: Option<OAuthDeviceValue> = point_lookup(
            &self.auth,
            key.as_slice(),
            OAuthDeviceValue::deserialize,
            "corrupt oauth device",
        )?;

        Ok(val.map(|v| DeviceData {
            session_id: tranquil_oauth::SessionId(v.session_id),
            user_agent: v.user_agent,
            ip_address: v.ip_address,
            last_seen_at: DateTime::from_timestamp_millis(v.last_seen_at_ms).unwrap_or_default(),
        }))
    }

    pub fn update_device_last_seen(&self, device_id: &DeviceId) -> Result<(), MetastoreError> {
        let key = oauth_device_key(device_id.as_str());
        let mut value: OAuthDeviceValue = point_lookup(
            &self.auth,
            key.as_slice(),
            OAuthDeviceValue::deserialize,
            "corrupt oauth device",
        )?
        .ok_or(MetastoreError::InvalidInput("device not found"))?;

        value.last_seen_at_ms = Utc::now().timestamp_millis();

        self.auth
            .insert(key.as_slice(), value.serialize())
            .map_err(MetastoreError::Fjall)
    }

    pub fn delete_device(&self, device_id: &DeviceId) -> Result<(), MetastoreError> {
        let key = oauth_device_key(device_id.as_str());
        self.auth
            .remove(key.as_slice())
            .map_err(MetastoreError::Fjall)
    }

    pub fn upsert_account_device(
        &self,
        did: &Did,
        device_id: &DeviceId,
    ) -> Result<(), MetastoreError> {
        let user_hash = self.resolve_user_hash_from_did(did.as_str());
        let key = oauth_account_device_key(user_hash, device_id.as_str());
        let now_ms = Utc::now().timestamp_millis();

        let value = AccountDeviceValue {
            last_used_at_ms: now_ms,
        };

        self.auth
            .insert(key.as_slice(), value.serialize_with_ttl())
            .map_err(MetastoreError::Fjall)
    }

    pub fn get_device_accounts(
        &self,
        device_id: &DeviceId,
    ) -> Result<Vec<DeviceAccountRow>, MetastoreError> {
        let tag_prefix = [super::keys::KeyTag::OAUTH_ACCOUNT_DEVICE.raw()];
        let device_id_str = device_id.as_str();

        self.auth
            .prefix(tag_prefix)
            .try_fold(Vec::new(), |mut acc, guard| {
                let (key_bytes, val_bytes) = guard.into_inner().map_err(MetastoreError::Fjall)?;
                let val = match AccountDeviceValue::deserialize(&val_bytes) {
                    Some(v) => v,
                    None => return Ok(acc),
                };

                let mut reader = super::encoding::KeyReader::new(&key_bytes[1..]);
                let user_hash_raw = reader
                    .u64()
                    .ok_or(MetastoreError::CorruptData("corrupt account device key"))?;
                let stored_device_id = reader
                    .string()
                    .ok_or(MetastoreError::CorruptData("corrupt account device key"))?;

                if stored_device_id != device_id_str {
                    return Ok(acc);
                }

                let uh = UserHash::from_raw(user_hash_raw);
                if let Some(user) = self.load_user_value(uh)? {
                    let did = Did::new(user.did.clone())
                        .map_err(|_| MetastoreError::CorruptData("invalid did in user"))?;
                    let handle = Handle::new(user.handle.clone())
                        .map_err(|_| MetastoreError::CorruptData("invalid handle in user"))?;
                    acc.push(DeviceAccountRow {
                        did,
                        handle,
                        email: user.email,
                        last_used_at: DateTime::from_timestamp_millis(val.last_used_at_ms)
                            .unwrap_or_default(),
                    });
                }
                Ok(acc)
            })
    }

    pub fn verify_account_on_device(
        &self,
        device_id: &DeviceId,
        did: &Did,
    ) -> Result<bool, MetastoreError> {
        let user_hash = self.resolve_user_hash_from_did(did.as_str());
        let key = oauth_account_device_key(user_hash, device_id.as_str());
        Ok(self
            .auth
            .get(key.as_slice())
            .map_err(MetastoreError::Fjall)?
            .is_some())
    }

    pub fn check_and_record_dpop_jti(&self, jti: &DPoPProofId) -> Result<bool, MetastoreError> {
        let key = oauth_dpop_jti_key(jti.as_str());
        let existing = self
            .auth
            .get(key.as_slice())
            .map_err(MetastoreError::Fjall)?;

        match existing {
            Some(_) => Ok(false),
            None => {
                let value = DpopJtiValue {
                    recorded_at_ms: Utc::now().timestamp_millis(),
                };
                self.auth
                    .insert(key.as_slice(), value.serialize_with_ttl())
                    .map_err(MetastoreError::Fjall)?;
                Ok(true)
            }
        }
    }

    pub fn cleanup_expired_dpop_jtis(&self, max_age_secs: i64) -> Result<u64, MetastoreError> {
        let cutoff_ms = Utc::now()
            .timestamp_millis()
            .saturating_sub(max_age_secs.saturating_mul(1000));
        let prefix = oauth_dpop_jti_prefix();
        let mut keys_to_remove: Vec<Vec<u8>> = Vec::new();

        self.auth.prefix(prefix.as_slice()).try_for_each(|guard| {
            let (key_bytes, val_bytes) = guard.into_inner().map_err(MetastoreError::Fjall)?;
            match DpopJtiValue::ttl_ms(&val_bytes) {
                Some(recorded_ms) if (recorded_ms as i64) < cutoff_ms => {
                    keys_to_remove.push(key_bytes.to_vec());
                }
                _ => {}
            }
            Ok::<(), MetastoreError>(())
        })?;

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

    pub fn create_2fa_challenge(
        &self,
        did: &Did,
        request_uri: &RequestId,
    ) -> Result<TwoFactorChallenge, MetastoreError> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        let expires_at = now + Duration::minutes(10);
        let code: String = {
            let entropy = Uuid::new_v4();
            let bytes = entropy.as_bytes();
            (0..6)
                .map(|i| std::char::from_digit(u32::from(bytes[i] % 10), 10).unwrap_or('0'))
                .collect()
        };

        let value = TwoFactorChallengeValue {
            id: *id.as_bytes(),
            did: did.to_string(),
            request_uri: request_uri.as_str().to_owned(),
            code: code.clone(),
            attempts: 0,
            created_at_ms: now.timestamp_millis(),
            expires_at_ms: expires_at.timestamp_millis(),
        };

        let primary_key = oauth_2fa_challenge_key(id.as_bytes());
        let request_index_key = oauth_2fa_by_request_key(request_uri.as_str());

        let mut batch = self.db.batch();
        batch.insert(
            &self.auth,
            primary_key.as_slice(),
            value.serialize_with_ttl(),
        );
        batch.insert(&self.auth, request_index_key.as_slice(), id.as_bytes());
        batch.commit().map_err(MetastoreError::Fjall)?;

        Ok(TwoFactorChallenge {
            id,
            did: did.clone(),
            request_uri: request_uri.as_str().to_owned(),
            code,
            attempts: 0,
            created_at: now,
            expires_at,
        })
    }

    pub fn get_2fa_challenge(
        &self,
        request_uri: &RequestId,
    ) -> Result<Option<TwoFactorChallenge>, MetastoreError> {
        let index_key = oauth_2fa_by_request_key(request_uri.as_str());
        let id_bytes = match self
            .auth
            .get(index_key.as_slice())
            .map_err(MetastoreError::Fjall)?
        {
            Some(bytes) => bytes,
            None => return Ok(None),
        };

        let id_array: [u8; 16] = id_bytes
            .as_ref()
            .try_into()
            .map_err(|_| MetastoreError::CorruptData("corrupt 2fa index"))?;

        let primary_key = oauth_2fa_challenge_key(&id_array);
        let val: Option<TwoFactorChallengeValue> = point_lookup(
            &self.auth,
            primary_key.as_slice(),
            TwoFactorChallengeValue::deserialize,
            "corrupt 2fa challenge",
        )?;

        val.map(|v| {
            Ok(TwoFactorChallenge {
                id: Uuid::from_bytes(v.id),
                did: Did::new(v.did)
                    .map_err(|_| MetastoreError::CorruptData("invalid did in 2fa challenge"))?,
                request_uri: v.request_uri,
                code: v.code,
                attempts: v.attempts,
                created_at: DateTime::from_timestamp_millis(v.created_at_ms).unwrap_or_default(),
                expires_at: DateTime::from_timestamp_millis(v.expires_at_ms).unwrap_or_default(),
            })
        })
        .transpose()
    }

    pub fn increment_2fa_attempts(&self, id: Uuid) -> Result<i32, MetastoreError> {
        let primary_key = oauth_2fa_challenge_key(id.as_bytes());
        let mut value: TwoFactorChallengeValue = point_lookup(
            &self.auth,
            primary_key.as_slice(),
            TwoFactorChallengeValue::deserialize,
            "corrupt 2fa challenge",
        )?
        .ok_or(MetastoreError::InvalidInput("2fa challenge not found"))?;

        value.attempts = value.attempts.saturating_add(1);

        self.auth
            .insert(primary_key.as_slice(), value.serialize_with_ttl())
            .map_err(MetastoreError::Fjall)?;

        Ok(value.attempts)
    }

    pub fn delete_2fa_challenge(&self, id: Uuid) -> Result<(), MetastoreError> {
        let primary_key = oauth_2fa_challenge_key(id.as_bytes());
        let value: Option<TwoFactorChallengeValue> = point_lookup(
            &self.auth,
            primary_key.as_slice(),
            TwoFactorChallengeValue::deserialize,
            "corrupt 2fa challenge",
        )?;

        let mut batch = self.db.batch();
        batch.remove(&self.auth, primary_key.as_slice());
        if let Some(v) = value {
            batch.remove(
                &self.auth,
                oauth_2fa_by_request_key(&v.request_uri).as_slice(),
            );
        }
        batch.commit().map_err(MetastoreError::Fjall)
    }

    pub fn delete_2fa_challenge_by_request_uri(
        &self,
        request_uri: &RequestId,
    ) -> Result<(), MetastoreError> {
        let index_key = oauth_2fa_by_request_key(request_uri.as_str());
        let id_bytes = match self
            .auth
            .get(index_key.as_slice())
            .map_err(MetastoreError::Fjall)?
        {
            Some(bytes) => bytes,
            None => return Ok(()),
        };

        let id_array: [u8; 16] = match id_bytes.as_ref().try_into() {
            Ok(arr) => arr,
            Err(_) => return Ok(()),
        };

        let primary_key = oauth_2fa_challenge_key(&id_array);
        let mut batch = self.db.batch();
        batch.remove(&self.auth, primary_key.as_slice());
        batch.remove(&self.auth, index_key.as_slice());
        batch.commit().map_err(MetastoreError::Fjall)
    }

    pub fn cleanup_expired_2fa_challenges(&self) -> Result<u64, MetastoreError> {
        let now_ms = Utc::now().timestamp_millis();
        let prefix = oauth_2fa_challenge_prefix();
        let mut to_remove: Vec<(Vec<u8>, String)> = Vec::new();

        self.auth.prefix(prefix.as_slice()).try_for_each(|guard| {
            let (key_bytes, val_bytes) = guard.into_inner().map_err(MetastoreError::Fjall)?;
            match TwoFactorChallengeValue::ttl_ms(&val_bytes) {
                Some(expires_ms) if (expires_ms as i64) <= now_ms => {
                    let v = TwoFactorChallengeValue::deserialize(&val_bytes);
                    let request_uri = v.map(|v| v.request_uri).unwrap_or_default();
                    to_remove.push((key_bytes.to_vec(), request_uri));
                }
                _ => {}
            }
            Ok::<(), MetastoreError>(())
        })?;

        let count = u64::try_from(to_remove.len()).unwrap_or(u64::MAX);
        match count {
            0 => Ok(0),
            _ => {
                let mut batch = self.db.batch();
                to_remove.iter().for_each(|(key, request_uri)| {
                    batch.remove(&self.auth, key);
                    if !request_uri.is_empty() {
                        batch.remove(&self.auth, oauth_2fa_by_request_key(request_uri).as_slice());
                    }
                });
                batch.commit().map_err(MetastoreError::Fjall)?;
                Ok(count)
            }
        }
    }

    pub fn check_user_2fa_enabled(&self, did: &Did) -> Result<bool, MetastoreError> {
        let user_hash = self.resolve_user_hash_from_did(did.as_str());
        let user = self.load_user_value(user_hash)?;
        Ok(user
            .map(|u| u.two_factor_enabled || u.totp_enabled || u.email_2fa_enabled)
            .unwrap_or(false))
    }

    pub fn get_scope_preferences(
        &self,
        did: &Did,
        client_id: &ClientId,
    ) -> Result<Vec<ScopePreference>, MetastoreError> {
        let user_hash = self.resolve_user_hash_from_did(did.as_str());
        let key = oauth_scope_prefs_key(user_hash, client_id.as_str());
        let val: Option<ScopePrefsValue> = point_lookup(
            &self.auth,
            key.as_slice(),
            ScopePrefsValue::deserialize,
            "corrupt scope preferences",
        )?;

        match val {
            Some(v) => serde_json::from_str(&v.prefs_json)
                .map_err(|_| MetastoreError::CorruptData("corrupt scope prefs json")),
            None => Ok(Vec::new()),
        }
    }

    pub fn upsert_scope_preferences(
        &self,
        did: &Did,
        client_id: &ClientId,
        prefs: &[ScopePreference],
    ) -> Result<(), MetastoreError> {
        let user_hash = self.resolve_user_hash_from_did(did.as_str());
        let key = oauth_scope_prefs_key(user_hash, client_id.as_str());
        let prefs_json = serde_json::to_string(prefs)
            .map_err(|_| MetastoreError::CorruptData("scope prefs serialize fail"))?;

        let value = ScopePrefsValue { prefs_json };
        self.auth
            .insert(key.as_slice(), value.serialize())
            .map_err(MetastoreError::Fjall)
    }

    pub fn delete_scope_preferences(
        &self,
        did: &Did,
        client_id: &ClientId,
    ) -> Result<(), MetastoreError> {
        let user_hash = self.resolve_user_hash_from_did(did.as_str());
        let key = oauth_scope_prefs_key(user_hash, client_id.as_str());
        self.auth
            .remove(key.as_slice())
            .map_err(MetastoreError::Fjall)
    }

    pub fn upsert_authorized_client(
        &self,
        did: &Did,
        client_id: &ClientId,
        data: &AuthorizedClientData,
    ) -> Result<(), MetastoreError> {
        let user_hash = self.resolve_user_hash_from_did(did.as_str());
        let key = oauth_auth_client_key(user_hash, client_id.as_str());
        let data_json = serde_json::to_string(data)
            .map_err(|_| MetastoreError::CorruptData("authorized client serialize fail"))?;

        let value = AuthorizedClientValue { data_json };
        self.auth
            .insert(key.as_slice(), value.serialize())
            .map_err(MetastoreError::Fjall)
    }

    pub fn get_authorized_client(
        &self,
        did: &Did,
        client_id: &ClientId,
    ) -> Result<Option<AuthorizedClientData>, MetastoreError> {
        let user_hash = self.resolve_user_hash_from_did(did.as_str());
        let key = oauth_auth_client_key(user_hash, client_id.as_str());
        let val: Option<AuthorizedClientValue> = point_lookup(
            &self.auth,
            key.as_slice(),
            AuthorizedClientValue::deserialize,
            "corrupt authorized client",
        )?;

        match val {
            Some(v) => serde_json::from_str(&v.data_json)
                .map_err(|_| MetastoreError::CorruptData("corrupt authorized client json"))
                .map(Some),
            None => Ok(None),
        }
    }

    pub fn list_trusted_devices(&self, did: &Did) -> Result<Vec<TrustedDeviceRow>, MetastoreError> {
        let user_hash = self.resolve_user_hash_from_did(did.as_str());
        let prefix = oauth_device_trust_prefix(user_hash);

        self.auth
            .prefix(prefix.as_slice())
            .try_fold(Vec::new(), |mut acc, guard| {
                let (_, val_bytes) = guard.into_inner().map_err(MetastoreError::Fjall)?;
                match DeviceTrustValue::deserialize(&val_bytes) {
                    Some(v) => {
                        acc.push(TrustedDeviceRow {
                            id: v.device_id,
                            user_agent: v.user_agent,
                            friendly_name: v.friendly_name,
                            trusted_at: v.trusted_at_ms.and_then(DateTime::from_timestamp_millis),
                            trusted_until: v
                                .trusted_until_ms
                                .and_then(DateTime::from_timestamp_millis),
                            last_seen_at: DateTime::from_timestamp_millis(v.last_seen_at_ms)
                                .unwrap_or_default(),
                        });
                        Ok(acc)
                    }
                    None => Ok(acc),
                }
            })
    }

    pub fn get_device_trust_info(
        &self,
        device_id: &DeviceId,
        did: &Did,
    ) -> Result<Option<DeviceTrustInfo>, MetastoreError> {
        let user_hash = self.resolve_user_hash_from_did(did.as_str());
        let key = oauth_device_trust_key(user_hash, device_id.as_str());
        let val: Option<DeviceTrustValue> = point_lookup(
            &self.auth,
            key.as_slice(),
            DeviceTrustValue::deserialize,
            "corrupt device trust",
        )?;

        Ok(val.map(|v| DeviceTrustInfo {
            trusted_at: v.trusted_at_ms.and_then(DateTime::from_timestamp_millis),
            trusted_until: v.trusted_until_ms.and_then(DateTime::from_timestamp_millis),
        }))
    }

    pub fn device_belongs_to_user(
        &self,
        device_id: &DeviceId,
        did: &Did,
    ) -> Result<bool, MetastoreError> {
        let user_hash = self.resolve_user_hash_from_did(did.as_str());
        let key = oauth_account_device_key(user_hash, device_id.as_str());
        Ok(self
            .auth
            .get(key.as_slice())
            .map_err(MetastoreError::Fjall)?
            .is_some())
    }

    pub fn revoke_device_trust(
        &self,
        device_id: &DeviceId,
        did: &Did,
    ) -> Result<(), MetastoreError> {
        let user_hash = self.resolve_user_hash_from_did(did.as_str());
        let key = oauth_device_trust_key(user_hash, device_id.as_str());
        let val: Option<DeviceTrustValue> = point_lookup(
            &self.auth,
            key.as_slice(),
            DeviceTrustValue::deserialize,
            "corrupt device trust",
        )?;
        match val {
            Some(mut v) => {
                v.trusted_at_ms = None;
                v.trusted_until_ms = None;
                self.auth
                    .insert(key.as_slice(), v.serialize())
                    .map_err(MetastoreError::Fjall)
            }
            None => Ok(()),
        }
    }

    pub fn update_device_friendly_name(
        &self,
        device_id: &DeviceId,
        did: &Did,
        friendly_name: Option<&str>,
    ) -> Result<(), MetastoreError> {
        let user_hash = self.resolve_user_hash_from_did(did.as_str());
        let key = oauth_device_trust_key(user_hash, device_id.as_str());
        let val: Option<DeviceTrustValue> = point_lookup(
            &self.auth,
            key.as_slice(),
            DeviceTrustValue::deserialize,
            "corrupt device trust",
        )?;
        match val {
            Some(mut v) => {
                v.friendly_name = friendly_name.map(str::to_owned);
                self.auth
                    .insert(key.as_slice(), v.serialize())
                    .map_err(MetastoreError::Fjall)
            }
            None => Ok(()),
        }
    }

    pub fn trust_device(
        &self,
        device_id: &DeviceId,
        did: &Did,
        trusted_at: DateTime<Utc>,
        trusted_until: DateTime<Utc>,
    ) -> Result<(), MetastoreError> {
        let user_hash = self.resolve_user_hash_from_did(did.as_str());
        let key = oauth_device_trust_key(user_hash, device_id.as_str());
        let val: Option<DeviceTrustValue> = point_lookup(
            &self.auth,
            key.as_slice(),
            DeviceTrustValue::deserialize,
            "corrupt device trust",
        )?;
        match val {
            Some(mut v) => {
                v.trusted_at_ms = Some(trusted_at.timestamp_millis());
                v.trusted_until_ms = Some(trusted_until.timestamp_millis());
                self.auth
                    .insert(key.as_slice(), v.serialize())
                    .map_err(MetastoreError::Fjall)
            }
            None => Ok(()),
        }
    }

    pub fn extend_device_trust(
        &self,
        device_id: &DeviceId,
        did: &Did,
        trusted_until: DateTime<Utc>,
    ) -> Result<(), MetastoreError> {
        let user_hash = self.resolve_user_hash_from_did(did.as_str());
        let key = oauth_device_trust_key(user_hash, device_id.as_str());
        let val: Option<DeviceTrustValue> = point_lookup(
            &self.auth,
            key.as_slice(),
            DeviceTrustValue::deserialize,
            "corrupt device trust",
        )?;
        match val {
            Some(mut v) => {
                v.trusted_until_ms = Some(trusted_until.timestamp_millis());
                self.auth
                    .insert(key.as_slice(), v.serialize())
                    .map_err(MetastoreError::Fjall)
            }
            None => Ok(()),
        }
    }

    pub fn list_sessions_by_did(
        &self,
        did: &Did,
    ) -> Result<Vec<OAuthSessionListItem>, MetastoreError> {
        let user_hash = self.resolve_user_hash_from_did(did.as_str());
        let now_ms = Utc::now().timestamp_millis();
        let tokens = self.collect_tokens_for_did(user_hash)?;

        Ok(tokens
            .iter()
            .filter(|t| t.expires_at_ms > now_ms)
            .map(|t| OAuthSessionListItem {
                id: TokenFamilyId::new(t.family_id),
                token_id: TokenId::new(t.token_id.clone()),
                created_at: DateTime::from_timestamp_millis(t.created_at_ms).unwrap_or_default(),
                expires_at: DateTime::from_timestamp_millis(t.expires_at_ms).unwrap_or_default(),
                client_id: ClientId::new(t.client_id.clone()),
            })
            .collect())
    }

    pub fn delete_session_by_id(
        &self,
        session_id: TokenFamilyId,
        did: &Did,
    ) -> Result<u64, MetastoreError> {
        let user_hash = self.resolve_user_hash_from_did(did.as_str());
        let token = match self.load_token_by_family_id(user_hash, session_id.as_i32())? {
            Some(t) => t,
            None => return Ok(0),
        };

        let mut batch = self.db.batch();
        self.delete_token_indexes(&mut batch, &token, user_hash);
        batch.commit().map_err(MetastoreError::Fjall)?;
        Ok(1)
    }

    pub fn delete_sessions_by_did(&self, did: &Did) -> Result<u64, MetastoreError> {
        let user_hash = self.resolve_user_hash_from_did(did.as_str());
        let tokens = self.collect_tokens_for_did(user_hash)?;

        let count = u64::try_from(tokens.len()).unwrap_or(u64::MAX);
        match count {
            0 => Ok(0),
            _ => {
                let mut batch = self.db.batch();
                tokens.iter().for_each(|token| {
                    self.delete_token_indexes(&mut batch, token, user_hash);
                });
                batch.commit().map_err(MetastoreError::Fjall)?;
                Ok(count)
            }
        }
    }

    pub fn delete_sessions_by_did_except(
        &self,
        did: &Did,
        except_token_id: &TokenId,
    ) -> Result<u64, MetastoreError> {
        let user_hash = self.resolve_user_hash_from_did(did.as_str());
        let tokens = self.collect_tokens_for_did(user_hash)?;
        let except_str = except_token_id.as_str();

        let to_delete: Vec<_> = tokens.iter().filter(|t| t.token_id != except_str).collect();

        let count = u64::try_from(to_delete.len()).unwrap_or(u64::MAX);
        match count {
            0 => Ok(0),
            _ => {
                let mut batch = self.db.batch();
                to_delete.iter().for_each(|token| {
                    self.delete_token_indexes(&mut batch, token, user_hash);
                });
                batch.commit().map_err(MetastoreError::Fjall)?;
                Ok(count)
            }
        }
    }

    pub fn get_2fa_challenge_code(
        &self,
        request_uri: &RequestId,
    ) -> Result<Option<String>, MetastoreError> {
        self.get_2fa_challenge(request_uri)
            .map(|opt| opt.map(|c| c.code))
    }
}

fn default_parameters(client_id: &str) -> tranquil_oauth::AuthorizationRequestParameters {
    tranquil_oauth::AuthorizationRequestParameters {
        response_type: tranquil_oauth::ResponseType::Code,
        client_id: client_id.to_owned(),
        redirect_uri: String::new(),
        scope: None,
        state: None,
        code_challenge: String::new(),
        code_challenge_method: tranquil_oauth::CodeChallengeMethod::S256,
        response_mode: None,
        login_hint: None,
        dpop_jkt: None,
        prompt: None,
        extra: None,
    }
}
