use std::sync::Arc;

use chrono::{DateTime, Utc};
use fjall::{Database, Keyspace};
use uuid::Uuid;

use super::MetastoreError;
use super::infra_schema::{channel_to_u8, u8_to_channel};
use super::keys::UserHash;
use super::repo_meta::{RepoMetaValue, RepoStatus, handle_key, repo_meta_key};
use super::repo_ops::cid_link_to_bytes;
use super::scan::{count_prefix, delete_all_by_prefix, point_lookup};
use super::sessions::{SessionIndexValue, session_by_access_key};
use super::user_hash::UserHashMap;
use super::users::{
    BackupCodeValue, DidWebOverridesValue, HandleReservationValue, PasskeyIndexValue, PasskeyValue,
    RecoveryTokenValue, ResetCodeValue, TotpValue, UserValue, WebauthnChallengeValue,
    account_type_to_u8, backup_code_key, backup_code_prefix, challenge_type_to_u8,
    did_web_overrides_key, discord_lookup_key, handle_reservation_key, handle_reservation_prefix,
    passkey_by_cred_key, passkey_key, passkey_prefix, recovery_token_key, reset_code_key,
    telegram_lookup_key, totp_key, u8_to_account_type, user_by_email_key, user_by_handle_key,
    user_primary_key, user_primary_prefix, webauthn_challenge_key,
};

use tranquil_db_traits::{
    AccountSearchResult, AccountType, ChannelVerificationStatus, CommsChannel,
    CompletePasskeySetupInput, CreateAccountError, CreateDelegatedAccountInput,
    CreatePasskeyAccountInput, CreatePasswordAccountInput, CreatePasswordAccountResult,
    CreateSsoAccountInput, DidWebOverrides, MigrationReactivationError, MigrationReactivationInput,
    NotificationPrefs, OAuthTokenWithUser, PasswordResetResult, ReactivatedAccountInfo,
    RecoverPasskeyAccountInput, RecoverPasskeyAccountResult, ScheduledDeletionAccount,
    StoredBackupCode, StoredPasskey, TotpRecord, TotpRecordState, User2faStatus, UserAuthInfo,
    UserCommsPrefs, UserConfirmSignup, UserDidWebInfo, UserEmailInfo, UserForDeletion,
    UserForDidDoc, UserForDidDocBuild, UserForPasskeyRecovery, UserForPasskeySetup,
    UserForRecovery, UserForVerification, UserIdAndHandle, UserIdAndPasswordHash,
    UserIdHandleEmail, UserInfoForAuth, UserKeyInfo, UserKeyWithId, UserLegacyLoginPref,
    UserLoginCheck, UserLoginFull, UserLoginInfo, UserPasswordInfo, UserResendVerification,
    UserResetCodeInfo, UserRow, UserSessionInfo, UserStatus, UserVerificationInfo, UserWithKey,
    WebauthnChallengeType,
};
use tranquil_types::{CidLink, Did, Handle};

pub struct UserOps {
    db: Database,
    users: Keyspace,
    repo_data: Keyspace,
    auth: Keyspace,
    user_hashes: Arc<UserHashMap>,
}

impl UserOps {
    pub fn new(
        db: Database,
        users: Keyspace,
        repo_data: Keyspace,
        auth: Keyspace,
        user_hashes: Arc<UserHashMap>,
    ) -> Self {
        Self {
            db,
            users,
            repo_data,
            auth,
            user_hashes,
        }
    }

    fn resolve_hash(&self, did: &str) -> UserHash {
        UserHash::from_did(did)
    }

    fn resolve_hash_from_uuid(&self, user_id: Uuid) -> Result<UserHash, MetastoreError> {
        self.user_hashes
            .get(&user_id)
            .ok_or(MetastoreError::InvalidInput("unknown user_id"))
    }

    fn load_user(&self, user_hash: UserHash) -> Result<Option<UserValue>, MetastoreError> {
        point_lookup(
            &self.users,
            user_primary_key(user_hash).as_slice(),
            UserValue::deserialize,
            "corrupt user value",
        )
    }

    fn load_user_by_did(&self, did: &str) -> Result<Option<UserValue>, MetastoreError> {
        self.load_user(self.resolve_hash(did))
    }

    fn save_user(&self, user_hash: UserHash, val: &UserValue) -> Result<(), MetastoreError> {
        self.users
            .insert(user_primary_key(user_hash).as_slice(), val.serialize())
            .map_err(MetastoreError::Fjall)
    }

    fn load_by_handle(&self, handle: &str) -> Result<Option<UserValue>, MetastoreError> {
        let idx_key = user_by_handle_key(handle);
        match self
            .users
            .get(idx_key.as_slice())
            .map_err(MetastoreError::Fjall)?
        {
            Some(raw) if raw.len() >= 8 => {
                let hash_raw = u64::from_be_bytes(raw[..8].try_into().unwrap());
                self.load_user(UserHash::from_raw(hash_raw))
            }
            _ => Ok(None),
        }
    }

    fn load_by_email(&self, email: &str) -> Result<Option<UserValue>, MetastoreError> {
        let idx_key = user_by_email_key(email);
        match self
            .users
            .get(idx_key.as_slice())
            .map_err(MetastoreError::Fjall)?
        {
            Some(raw) if raw.len() >= 8 => {
                let hash_raw = u64::from_be_bytes(raw[..8].try_into().unwrap());
                self.load_user(UserHash::from_raw(hash_raw))
            }
            _ => Ok(None),
        }
    }

    fn load_by_identifier(&self, identifier: &str) -> Result<Option<UserValue>, MetastoreError> {
        match identifier.starts_with("did:") {
            true => self.load_user_by_did(identifier),
            false => self.load_by_handle(identifier),
        }
    }

    fn mutate_user<F>(&self, user_hash: UserHash, f: F) -> Result<bool, MetastoreError>
    where
        F: FnOnce(&mut UserValue),
    {
        match self.load_user(user_hash)? {
            Some(mut val) => {
                f(&mut val);
                self.save_user(user_hash, &val)?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    fn mutate_user_by_uuid<F>(&self, user_id: Uuid, f: F) -> Result<bool, MetastoreError>
    where
        F: FnOnce(&mut UserValue),
    {
        let user_hash = self.resolve_hash_from_uuid(user_id)?;
        self.mutate_user(user_hash, f)
    }

    fn channel_verification(val: &UserValue) -> ChannelVerificationStatus {
        ChannelVerificationStatus::from_db_row(
            val.email_verified,
            val.discord_verified,
            val.telegram_verified,
            val.signal_verified,
        )
    }

    fn comms_channel(val: &UserValue) -> CommsChannel {
        val.preferred_comms_channel
            .and_then(u8_to_channel)
            .unwrap_or(CommsChannel::Email)
    }

    fn to_user_row(val: &UserValue) -> Result<UserRow, MetastoreError> {
        Ok(UserRow {
            id: val.id,
            did: Did::new(val.did.clone())
                .map_err(|_| MetastoreError::CorruptData("invalid user did"))?,
            handle: Handle::new(val.handle.clone())
                .map_err(|_| MetastoreError::CorruptData("invalid user handle"))?,
            email: val.email.clone(),
            created_at: DateTime::from_timestamp_millis(val.created_at_ms).unwrap_or_default(),
            deactivated_at: val
                .deactivated_at_ms
                .and_then(DateTime::from_timestamp_millis),
            takedown_ref: val.takedown_ref.clone(),
            is_admin: val.is_admin,
        })
    }

    fn to_stored_passkey(pv: &PasskeyValue) -> Result<StoredPasskey, MetastoreError> {
        Ok(StoredPasskey {
            id: pv.id,
            did: Did::new(pv.did.clone())
                .map_err(|_| MetastoreError::CorruptData("invalid passkey did"))?,
            credential_id: pv.credential_id.clone(),
            public_key: pv.public_key.clone(),
            sign_count: pv.sign_count,
            created_at: DateTime::from_timestamp_millis(pv.created_at_ms).unwrap_or_default(),
            last_used: pv.last_used_at_ms.and_then(DateTime::from_timestamp_millis),
            friendly_name: pv.friendly_name.clone(),
            aaguid: pv.aaguid.clone(),
            transports: pv.transports.clone(),
        })
    }

    fn is_first_account(&self) -> Result<bool, MetastoreError> {
        let prefix = user_primary_prefix();
        match self.users.prefix(prefix.as_slice()).next() {
            Some(guard) => {
                guard.into_inner().map_err(MetastoreError::Fjall)?;
                Ok(false)
            }
            None => Ok(true),
        }
    }

    pub fn get_by_did(&self, did: &Did) -> Result<Option<UserRow>, MetastoreError> {
        self.load_user_by_did(did.as_str())?
            .map(|v| Self::to_user_row(&v))
            .transpose()
    }

    pub fn get_by_handle(&self, handle: &Handle) -> Result<Option<UserRow>, MetastoreError> {
        self.load_by_handle(handle.as_str())?
            .map(|v| Self::to_user_row(&v))
            .transpose()
    }

    pub fn get_with_key_by_did(&self, did: &Did) -> Result<Option<UserWithKey>, MetastoreError> {
        self.load_user_by_did(did.as_str())?
            .map(|v| {
                Ok(UserWithKey {
                    id: v.id,
                    did: Did::new(v.did.clone())
                        .map_err(|_| MetastoreError::CorruptData("invalid user did"))?,
                    handle: Handle::new(v.handle.clone())
                        .map_err(|_| MetastoreError::CorruptData("invalid user handle"))?,
                    email: v.email.clone(),
                    deactivated_at: v
                        .deactivated_at_ms
                        .and_then(DateTime::from_timestamp_millis),
                    takedown_ref: v.takedown_ref.clone(),
                    is_admin: v.is_admin,
                    key_bytes: v.key_bytes.clone(),
                    encryption_version: Some(v.encryption_version),
                })
            })
            .transpose()
    }

    pub fn get_status_by_did(&self, did: &Did) -> Result<Option<UserStatus>, MetastoreError> {
        Ok(self.load_user_by_did(did.as_str())?.map(|v| UserStatus {
            deactivated_at: v
                .deactivated_at_ms
                .and_then(DateTime::from_timestamp_millis),
            takedown_ref: v.takedown_ref.clone(),
            is_admin: v.is_admin,
        }))
    }

    pub fn count_users(&self) -> Result<i64, MetastoreError> {
        count_prefix(&self.users, user_primary_prefix().as_slice())
    }

    pub fn get_session_access_expiry(
        &self,
        did: &Did,
        access_jti: &str,
    ) -> Result<Option<DateTime<Utc>>, MetastoreError> {
        let index_key = session_by_access_key(access_jti);
        let index_val: Option<SessionIndexValue> = point_lookup(
            &self.auth,
            index_key.as_slice(),
            SessionIndexValue::deserialize,
            "corrupt session access index",
        )?;

        match index_val {
            Some(idx) => {
                let session_key = super::sessions::session_primary_key(idx.session_id);
                let session: Option<super::sessions::SessionTokenValue> = point_lookup(
                    &self.auth,
                    session_key.as_slice(),
                    super::sessions::SessionTokenValue::deserialize,
                    "corrupt session token",
                )?;
                match session.filter(|s| s.did == did.as_str()) {
                    Some(s) => Ok(DateTime::from_timestamp_millis(s.access_expires_at_ms)),
                    None => Ok(None),
                }
            }
            None => Ok(None),
        }
    }

    pub fn get_oauth_token_with_user(
        &self,
        token_id: &str,
    ) -> Result<Option<OAuthTokenWithUser>, MetastoreError> {
        let index_key = super::oauth_schema::oauth_token_by_id_key(token_id);
        let index_val: Option<super::oauth_schema::TokenIndexValue> = point_lookup(
            &self.auth,
            index_key.as_slice(),
            super::oauth_schema::TokenIndexValue::deserialize,
            "corrupt oauth token index",
        )?;

        let idx = match index_val {
            Some(idx) => idx,
            None => return Ok(None),
        };

        let uh = UserHash::from_raw(idx.user_hash);
        let token_key = super::oauth_schema::oauth_token_key(uh, idx.family_id);
        let token: Option<super::oauth_schema::OAuthTokenValue> = point_lookup(
            &self.auth,
            token_key.as_slice(),
            super::oauth_schema::OAuthTokenValue::deserialize,
            "corrupt oauth token",
        )?;

        let token = match token {
            Some(t) => t,
            None => return Ok(None),
        };

        let user = self.load_user(uh)?;
        match user {
            Some(u) => Ok(Some(OAuthTokenWithUser {
                did: Did::new(token.did)
                    .map_err(|_| MetastoreError::CorruptData("invalid oauth token did"))?,
                expires_at: DateTime::from_timestamp_millis(token.expires_at_ms)
                    .unwrap_or_default(),
                deactivated_at: u
                    .deactivated_at_ms
                    .and_then(DateTime::from_timestamp_millis),
                takedown_ref: u.takedown_ref.clone(),
                is_admin: u.is_admin,
                key_bytes: Some(u.key_bytes.clone()),
                encryption_version: Some(u.encryption_version),
            })),
            None => Ok(None),
        }
    }

    pub fn get_user_info_by_did(
        &self,
        did: &Did,
    ) -> Result<Option<UserInfoForAuth>, MetastoreError> {
        Ok(self
            .load_user_by_did(did.as_str())?
            .map(|v| UserInfoForAuth {
                deactivated_at: v
                    .deactivated_at_ms
                    .and_then(DateTime::from_timestamp_millis),
                takedown_ref: v.takedown_ref.clone(),
                is_admin: v.is_admin,
                key_bytes: Some(v.key_bytes.clone()),
                encryption_version: Some(v.encryption_version),
            }))
    }

    pub fn get_any_admin_user_id(&self) -> Result<Option<Uuid>, MetastoreError> {
        let prefix = user_primary_prefix();
        self.users
            .prefix(prefix.as_slice())
            .map(|guard| -> Result<Option<Uuid>, MetastoreError> {
                let (_, val_bytes) = guard.into_inner().map_err(MetastoreError::Fjall)?;
                let val = UserValue::deserialize(&val_bytes)
                    .ok_or(MetastoreError::CorruptData("corrupt user value"))?;
                Ok(val.is_admin.then_some(val.id))
            })
            .filter_map(Result::transpose)
            .next()
            .transpose()
    }

    pub fn set_invites_disabled(&self, did: &Did, disabled: bool) -> Result<bool, MetastoreError> {
        let user_hash = self.resolve_hash(did.as_str());
        self.mutate_user(user_hash, |u| {
            u.invites_disabled = disabled;
        })
    }

    pub fn search_accounts(
        &self,
        cursor_did: Option<&Did>,
        email_filter: Option<&str>,
        handle_filter: Option<&str>,
        limit: i64,
    ) -> Result<Vec<AccountSearchResult>, MetastoreError> {
        let prefix = user_primary_prefix();
        let limit = usize::try_from(limit).unwrap_or(0);
        let cursor_hash = cursor_did.map(|d| self.resolve_hash(d.as_str()));

        self.users
            .prefix(prefix.as_slice())
            .map(
                |guard| -> Result<Option<AccountSearchResult>, MetastoreError> {
                    let (_, val_bytes) = guard.into_inner().map_err(MetastoreError::Fjall)?;
                    let val = UserValue::deserialize(&val_bytes)
                        .ok_or(MetastoreError::CorruptData("corrupt user value"))?;

                    let val_hash = UserHash::from_did(&val.did);
                    if cursor_hash.is_some_and(|cursor| val_hash.raw() <= cursor.raw()) {
                        return Ok(None);
                    }

                    let email_match = email_filter
                        .is_none_or(|f| val.email.as_deref().is_some_and(|e| e.contains(f)));
                    let handle_match = handle_filter.is_none_or(|f| val.handle.contains(f));

                    match email_match && handle_match {
                        true => Ok(Some(AccountSearchResult {
                            did: Did::new(val.did.clone())
                                .map_err(|_| MetastoreError::CorruptData("invalid user did"))?,
                            handle: Handle::new(val.handle.clone())
                                .map_err(|_| MetastoreError::CorruptData("invalid user handle"))?,
                            email: val.email.clone(),
                            created_at: DateTime::from_timestamp_millis(val.created_at_ms)
                                .unwrap_or_default(),
                            email_verified: val.email_verified,
                            deactivated_at: val
                                .deactivated_at_ms
                                .and_then(DateTime::from_timestamp_millis),
                            invites_disabled: Some(val.invites_disabled),
                        })),
                        false => Ok(None),
                    }
                },
            )
            .filter_map(Result::transpose)
            .take(limit)
            .collect()
    }

    pub fn get_auth_info_by_did(&self, did: &Did) -> Result<Option<UserAuthInfo>, MetastoreError> {
        self.load_user_by_did(did.as_str())?
            .map(|v| {
                Ok(UserAuthInfo {
                    id: v.id,
                    did: Did::new(v.did.clone())
                        .map_err(|_| MetastoreError::CorruptData("invalid user did"))?,
                    password_hash: v.password_hash.clone(),
                    deactivated_at: v
                        .deactivated_at_ms
                        .and_then(DateTime::from_timestamp_millis),
                    takedown_ref: v.takedown_ref.clone(),
                    channel_verification: Self::channel_verification(&v),
                })
            })
            .transpose()
    }

    pub fn get_by_email(&self, email: &str) -> Result<Option<UserForVerification>, MetastoreError> {
        self.load_by_email(email)?
            .map(|v| {
                Ok(UserForVerification {
                    id: v.id,
                    did: Did::new(v.did.clone())
                        .map_err(|_| MetastoreError::CorruptData("invalid user did"))?,
                    email: v.email.clone(),
                    email_verified: v.email_verified,
                    handle: Handle::new(v.handle.clone())
                        .map_err(|_| MetastoreError::CorruptData("invalid user handle"))?,
                })
            })
            .transpose()
    }

    pub fn get_login_check_by_identifier(
        &self,
        identifier: &str,
    ) -> Result<Option<UserLoginCheck>, MetastoreError> {
        self.load_by_identifier(identifier)?
            .map(|v| {
                Ok(UserLoginCheck {
                    did: Did::new(v.did.clone())
                        .map_err(|_| MetastoreError::CorruptData("invalid user did"))?,
                    password_hash: v.password_hash.clone(),
                })
            })
            .transpose()
    }

    pub fn get_login_info_by_identifier(
        &self,
        identifier: &str,
    ) -> Result<Option<UserLoginInfo>, MetastoreError> {
        self.load_by_identifier(identifier)?
            .map(|v| {
                Ok(UserLoginInfo {
                    id: v.id,
                    did: Did::new(v.did.clone())
                        .map_err(|_| MetastoreError::CorruptData("invalid user did"))?,
                    email: v.email.clone(),
                    password_hash: v.password_hash.clone(),
                    password_required: v.password_required,
                    two_factor_enabled: v.two_factor_enabled,
                    preferred_comms_channel: Self::comms_channel(&v),
                    deactivated_at: v
                        .deactivated_at_ms
                        .and_then(DateTime::from_timestamp_millis),
                    takedown_ref: v.takedown_ref.clone(),
                    channel_verification: Self::channel_verification(&v),
                    account_type: u8_to_account_type(v.account_type)
                        .unwrap_or(AccountType::Personal),
                })
            })
            .transpose()
    }

    pub fn get_2fa_status_by_did(
        &self,
        did: &Did,
    ) -> Result<Option<User2faStatus>, MetastoreError> {
        Ok(self.load_user_by_did(did.as_str())?.map(|v| User2faStatus {
            id: v.id,
            two_factor_enabled: v.two_factor_enabled,
            preferred_comms_channel: Self::comms_channel(&v),
            channel_verification: Self::channel_verification(&v),
        }))
    }

    pub fn get_comms_prefs(&self, user_id: Uuid) -> Result<Option<UserCommsPrefs>, MetastoreError> {
        let user_hash = self.resolve_hash_from_uuid(user_id)?;
        self.load_user(user_hash)?
            .map(|v| {
                Ok(UserCommsPrefs {
                    email: v.email.clone(),
                    handle: Handle::new(v.handle.clone())
                        .map_err(|_| MetastoreError::CorruptData("invalid user handle"))?,
                    preferred_channel: Self::comms_channel(&v),
                    preferred_locale: v.preferred_locale.clone(),
                    telegram_chat_id: v.telegram_chat_id,
                    discord_id: v.discord_id.clone(),
                    signal_username: v.signal_username.clone(),
                })
            })
            .transpose()
    }

    pub fn get_id_by_did(&self, did: &Did) -> Result<Option<Uuid>, MetastoreError> {
        Ok(self.load_user_by_did(did.as_str())?.map(|v| v.id))
    }

    pub fn get_user_key_by_id(&self, user_id: Uuid) -> Result<Option<UserKeyInfo>, MetastoreError> {
        let user_hash = self.resolve_hash_from_uuid(user_id)?;
        Ok(self.load_user(user_hash)?.map(|v| UserKeyInfo {
            key_bytes: v.key_bytes.clone(),
            encryption_version: Some(v.encryption_version),
        }))
    }

    pub fn get_id_and_handle_by_did(
        &self,
        did: &Did,
    ) -> Result<Option<UserIdAndHandle>, MetastoreError> {
        self.load_user_by_did(did.as_str())?
            .map(|v| {
                Ok(UserIdAndHandle {
                    id: v.id,
                    handle: Handle::new(v.handle.clone())
                        .map_err(|_| MetastoreError::CorruptData("invalid user handle"))?,
                })
            })
            .transpose()
    }

    pub fn get_did_web_info_by_handle(
        &self,
        handle: &Handle,
    ) -> Result<Option<UserDidWebInfo>, MetastoreError> {
        self.load_by_handle(handle.as_str())?
            .map(|v| {
                Ok(UserDidWebInfo {
                    id: v.id,
                    did: Did::new(v.did.clone())
                        .map_err(|_| MetastoreError::CorruptData("invalid user did"))?,
                    migrated_to_pds: v.migrated_to_pds.clone(),
                })
            })
            .transpose()
    }

    pub fn get_did_web_overrides(
        &self,
        user_id: Uuid,
    ) -> Result<Option<DidWebOverrides>, MetastoreError> {
        let user_hash = self.resolve_hash_from_uuid(user_id)?;
        let key = did_web_overrides_key(user_hash);
        let val: Option<DidWebOverridesValue> = point_lookup(
            &self.users,
            key.as_slice(),
            DidWebOverridesValue::deserialize,
            "corrupt did_web_overrides",
        )?;

        Ok(val.map(|v| DidWebOverrides {
            verification_methods: v
                .verification_methods_json
                .and_then(|j| serde_json::from_str(&j).ok())
                .unwrap_or(serde_json::Value::Null),
            also_known_as: v.also_known_as.unwrap_or_default(),
        }))
    }

    pub fn get_handle_by_did(&self, did: &Did) -> Result<Option<Handle>, MetastoreError> {
        self.load_user_by_did(did.as_str())?
            .map(|v| {
                Handle::new(v.handle.clone())
                    .map_err(|_| MetastoreError::CorruptData("invalid user handle"))
            })
            .transpose()
    }

    pub fn is_account_active_by_did(&self, did: &Did) -> Result<Option<bool>, MetastoreError> {
        Ok(self.load_user_by_did(did.as_str())?.map(|v| v.is_active()))
    }

    pub fn get_user_for_deletion(
        &self,
        did: &Did,
    ) -> Result<Option<UserForDeletion>, MetastoreError> {
        self.load_user_by_did(did.as_str())?
            .map(|v| {
                Ok(UserForDeletion {
                    id: v.id,
                    password_hash: v.password_hash.clone(),
                    handle: Handle::new(v.handle.clone())
                        .map_err(|_| MetastoreError::CorruptData("invalid user handle"))?,
                })
            })
            .transpose()
    }

    pub fn check_handle_exists(
        &self,
        handle: &Handle,
        exclude_user_id: Uuid,
    ) -> Result<bool, MetastoreError> {
        match self.load_by_handle(handle.as_str())? {
            Some(v) => Ok(v.id != exclude_user_id),
            None => Ok(false),
        }
    }

    pub fn update_handle(&self, user_id: Uuid, handle: &Handle) -> Result<(), MetastoreError> {
        let user_hash = self.resolve_hash_from_uuid(user_id)?;
        let val = self
            .load_user(user_hash)?
            .ok_or(MetastoreError::InvalidInput("user not found"))?;

        let old_handle = val.handle.clone();
        let mut updated = val;
        updated.handle = handle.as_str().to_owned();

        let mut batch = self.db.batch();
        batch.remove(&self.users, user_by_handle_key(&old_handle).as_slice());
        batch.insert(
            &self.users,
            user_by_handle_key(handle.as_str()).as_slice(),
            user_hash.raw().to_be_bytes(),
        );
        batch.insert(
            &self.users,
            user_primary_key(user_hash).as_slice(),
            updated.serialize(),
        );
        batch.commit().map_err(MetastoreError::Fjall)
    }

    pub fn get_user_with_key_by_did(
        &self,
        did: &Did,
    ) -> Result<Option<UserKeyWithId>, MetastoreError> {
        Ok(self.load_user_by_did(did.as_str())?.map(|v| UserKeyWithId {
            id: v.id,
            key_bytes: v.key_bytes.clone(),
            encryption_version: Some(v.encryption_version),
        }))
    }

    pub fn is_account_migrated(&self, did: &Did) -> Result<bool, MetastoreError> {
        Ok(self
            .load_user_by_did(did.as_str())?
            .is_some_and(|v| v.migrated_to_pds.is_some()))
    }

    pub fn has_verified_comms_channel(&self, did: &Did) -> Result<bool, MetastoreError> {
        Ok(self
            .load_user_by_did(did.as_str())?
            .is_some_and(|v| v.channel_verification() != 0))
    }

    pub fn get_id_by_handle(&self, handle: &Handle) -> Result<Option<Uuid>, MetastoreError> {
        Ok(self.load_by_handle(handle.as_str())?.map(|v| v.id))
    }

    pub fn get_email_info_by_did(
        &self,
        did: &Did,
    ) -> Result<Option<UserEmailInfo>, MetastoreError> {
        self.load_user_by_did(did.as_str())?
            .map(|v| {
                Ok(UserEmailInfo {
                    id: v.id,
                    handle: Handle::new(v.handle.clone())
                        .map_err(|_| MetastoreError::CorruptData("invalid user handle"))?,
                    email: v.email.clone(),
                    email_verified: v.email_verified,
                })
            })
            .transpose()
    }

    pub fn check_email_exists(
        &self,
        email: &str,
        exclude_user_id: Uuid,
    ) -> Result<bool, MetastoreError> {
        match self.load_by_email(email)? {
            Some(v) => Ok(v.id != exclude_user_id),
            None => Ok(false),
        }
    }

    pub fn update_email(&self, user_id: Uuid, email: &str) -> Result<(), MetastoreError> {
        let user_hash = self.resolve_hash_from_uuid(user_id)?;
        let val = self
            .load_user(user_hash)?
            .ok_or(MetastoreError::InvalidInput("user not found"))?;

        let mut batch = self.db.batch();

        if let Some(old_email) = &val.email {
            batch.remove(&self.users, user_by_email_key(old_email).as_slice());
        }

        batch.insert(
            &self.users,
            user_by_email_key(email).as_slice(),
            user_hash.raw().to_be_bytes(),
        );

        let mut updated = val;
        updated.email = Some(email.to_owned());
        updated.email_verified = false;

        batch.insert(
            &self.users,
            user_primary_key(user_hash).as_slice(),
            updated.serialize(),
        );
        batch.commit().map_err(MetastoreError::Fjall)
    }

    pub fn set_email_verified(&self, user_id: Uuid, verified: bool) -> Result<(), MetastoreError> {
        self.mutate_user_by_uuid(user_id, |u| {
            u.email_verified = verified;
        })?;
        Ok(())
    }

    pub fn check_email_verified_by_identifier(
        &self,
        identifier: &str,
    ) -> Result<Option<bool>, MetastoreError> {
        Ok(self
            .load_by_identifier(identifier)?
            .map(|v| v.email_verified))
    }

    pub fn check_channel_verified_by_did(
        &self,
        did: &Did,
        channel: CommsChannel,
    ) -> Result<Option<bool>, MetastoreError> {
        Ok(self.load_user_by_did(did.as_str())?.map(|v| match channel {
            CommsChannel::Email => v.email_verified,
            CommsChannel::Discord => v.discord_verified,
            CommsChannel::Telegram => v.telegram_verified,
            CommsChannel::Signal => v.signal_verified,
        }))
    }

    pub fn admin_update_email(&self, did: &Did, email: &str) -> Result<u64, MetastoreError> {
        let user_hash = self.resolve_hash(did.as_str());
        let val = match self.load_user(user_hash)? {
            Some(v) => v,
            None => return Ok(0),
        };

        let mut batch = self.db.batch();

        if let Some(old_email) = &val.email {
            batch.remove(&self.users, user_by_email_key(old_email).as_slice());
        }

        batch.insert(
            &self.users,
            user_by_email_key(email).as_slice(),
            user_hash.raw().to_be_bytes(),
        );

        let mut updated = val;
        updated.email = Some(email.to_owned());

        batch.insert(
            &self.users,
            user_primary_key(user_hash).as_slice(),
            updated.serialize(),
        );
        batch.commit().map_err(MetastoreError::Fjall)?;
        Ok(1)
    }

    pub fn admin_update_handle(&self, did: &Did, handle: &Handle) -> Result<u64, MetastoreError> {
        let user_hash = self.resolve_hash(did.as_str());
        let val = match self.load_user(user_hash)? {
            Some(v) => v,
            None => return Ok(0),
        };

        let old_handle = val.handle.clone();
        let mut updated = val;
        updated.handle = handle.as_str().to_owned();

        let mut batch = self.db.batch();
        batch.remove(&self.users, user_by_handle_key(&old_handle).as_slice());
        batch.insert(
            &self.users,
            user_by_handle_key(handle.as_str()).as_slice(),
            user_hash.raw().to_be_bytes(),
        );
        batch.insert(
            &self.users,
            user_primary_key(user_hash).as_slice(),
            updated.serialize(),
        );
        batch.commit().map_err(MetastoreError::Fjall)?;
        Ok(1)
    }

    pub fn admin_update_password(
        &self,
        did: &Did,
        password_hash: &str,
    ) -> Result<u64, MetastoreError> {
        let user_hash = self.resolve_hash(did.as_str());
        match self.mutate_user(user_hash, |u| {
            u.password_hash = Some(password_hash.to_owned());
        })? {
            true => Ok(1),
            false => Ok(0),
        }
    }

    pub fn set_admin_status(&self, did: &Did, is_admin: bool) -> Result<(), MetastoreError> {
        let user_hash = self.resolve_hash(did.as_str());
        self.mutate_user(user_hash, |u| {
            u.is_admin = is_admin;
        })?;
        Ok(())
    }

    pub fn get_notification_prefs(
        &self,
        did: &Did,
    ) -> Result<Option<NotificationPrefs>, MetastoreError> {
        self.load_user_by_did(did.as_str())?
            .map(|v| {
                Ok(NotificationPrefs {
                    email: v.email.clone().unwrap_or_default(),
                    preferred_channel: Self::comms_channel(&v),
                    discord_id: v.discord_id.clone(),
                    discord_username: v.discord_username.clone(),
                    discord_verified: v.discord_verified,
                    telegram_username: v.telegram_username.clone(),
                    telegram_verified: v.telegram_verified,
                    telegram_chat_id: v.telegram_chat_id,
                    signal_username: v.signal_username.clone(),
                    signal_verified: v.signal_verified,
                })
            })
            .transpose()
    }

    pub fn get_id_handle_email_by_did(
        &self,
        did: &Did,
    ) -> Result<Option<UserIdHandleEmail>, MetastoreError> {
        self.load_user_by_did(did.as_str())?
            .map(|v| {
                Ok(UserIdHandleEmail {
                    id: v.id,
                    handle: Handle::new(v.handle.clone())
                        .map_err(|_| MetastoreError::CorruptData("invalid user handle"))?,
                    email: v.email.clone(),
                })
            })
            .transpose()
    }

    pub fn update_preferred_comms_channel(
        &self,
        did: &Did,
        channel: CommsChannel,
    ) -> Result<(), MetastoreError> {
        let user_hash = self.resolve_hash(did.as_str());
        let channel_u8 = channel_to_u8(channel);
        self.mutate_user(user_hash, |u| {
            u.preferred_comms_channel = Some(channel_u8);
        })?;
        Ok(())
    }

    pub fn clear_discord(&self, user_id: Uuid) -> Result<(), MetastoreError> {
        let user_hash = self.resolve_hash_from_uuid(user_id)?;
        let val = match self.load_user(user_hash)? {
            Some(v) => v,
            None => return Ok(()),
        };

        let mut batch = self.db.batch();

        if let Some(username) = &val.discord_username {
            batch.remove(&self.users, discord_lookup_key(username).as_slice());
        }

        let mut updated = val;
        updated.discord_username = None;
        updated.discord_id = None;
        updated.discord_verified = false;

        batch.insert(
            &self.users,
            user_primary_key(user_hash).as_slice(),
            updated.serialize(),
        );
        batch.commit().map_err(MetastoreError::Fjall)
    }

    pub fn clear_telegram(&self, user_id: Uuid) -> Result<(), MetastoreError> {
        let user_hash = self.resolve_hash_from_uuid(user_id)?;
        let val = match self.load_user(user_hash)? {
            Some(v) => v,
            None => return Ok(()),
        };

        let mut batch = self.db.batch();

        if let Some(username) = &val.telegram_username {
            batch.remove(&self.users, telegram_lookup_key(username).as_slice());
        }

        let mut updated = val;
        updated.telegram_username = None;
        updated.telegram_chat_id = None;
        updated.telegram_verified = false;

        batch.insert(
            &self.users,
            user_primary_key(user_hash).as_slice(),
            updated.serialize(),
        );
        batch.commit().map_err(MetastoreError::Fjall)
    }

    pub fn clear_signal(&self, user_id: Uuid) -> Result<(), MetastoreError> {
        self.mutate_user_by_uuid(user_id, |u| {
            u.signal_username = None;
            u.signal_verified = false;
        })?;
        Ok(())
    }

    pub fn set_unverified_signal(
        &self,
        user_id: Uuid,
        signal_username: &str,
    ) -> Result<(), MetastoreError> {
        self.mutate_user_by_uuid(user_id, |u| {
            u.signal_username = Some(signal_username.to_owned());
            u.signal_verified = false;
        })?;
        Ok(())
    }

    pub fn set_unverified_telegram(
        &self,
        user_id: Uuid,
        telegram_username: &str,
    ) -> Result<(), MetastoreError> {
        let user_hash = self.resolve_hash_from_uuid(user_id)?;
        let val = match self.load_user(user_hash)? {
            Some(v) => v,
            None => return Ok(()),
        };

        let mut batch = self.db.batch();

        if let Some(old_username) = &val.telegram_username {
            batch.remove(&self.users, telegram_lookup_key(old_username).as_slice());
        }

        batch.insert(
            &self.users,
            telegram_lookup_key(telegram_username).as_slice(),
            user_hash.raw().to_be_bytes(),
        );

        let mut updated = val;
        updated.telegram_username = Some(telegram_username.to_owned());
        updated.telegram_verified = false;
        updated.telegram_chat_id = None;

        batch.insert(
            &self.users,
            user_primary_key(user_hash).as_slice(),
            updated.serialize(),
        );
        batch.commit().map_err(MetastoreError::Fjall)
    }

    pub fn store_telegram_chat_id(
        &self,
        telegram_username: &str,
        chat_id: i64,
        handle: Option<&str>,
    ) -> Result<Option<Uuid>, MetastoreError> {
        let idx_key = telegram_lookup_key(telegram_username);
        let raw = match self
            .users
            .get(idx_key.as_slice())
            .map_err(MetastoreError::Fjall)?
        {
            Some(raw) if raw.len() >= 8 => raw,
            _ => match handle {
                Some(h) => {
                    let val = match self.load_by_handle(h)? {
                        Some(v) => v,
                        None => return Ok(None),
                    };
                    let user_hash = UserHash::from_did(&val.did);
                    self.mutate_user(user_hash, |u| {
                        u.telegram_chat_id = Some(chat_id);
                    })?;
                    return Ok(Some(val.id));
                }
                None => return Ok(None),
            },
        };

        let hash_raw = u64::from_be_bytes(raw[..8].try_into().unwrap());
        let user_hash = UserHash::from_raw(hash_raw);
        let val = match self.load_user(user_hash)? {
            Some(v) => v,
            None => return Ok(None),
        };
        let uid = val.id;
        self.mutate_user(user_hash, |u| {
            u.telegram_chat_id = Some(chat_id);
        })?;
        Ok(Some(uid))
    }

    pub fn get_telegram_chat_id(&self, user_id: Uuid) -> Result<Option<i64>, MetastoreError> {
        let user_hash = self.resolve_hash_from_uuid(user_id)?;
        Ok(self.load_user(user_hash)?.and_then(|v| v.telegram_chat_id))
    }

    pub fn set_unverified_discord(
        &self,
        user_id: Uuid,
        discord_username: &str,
    ) -> Result<(), MetastoreError> {
        let user_hash = self.resolve_hash_from_uuid(user_id)?;
        let val = match self.load_user(user_hash)? {
            Some(v) => v,
            None => return Ok(()),
        };

        let mut batch = self.db.batch();

        if let Some(old_username) = &val.discord_username {
            batch.remove(&self.users, discord_lookup_key(old_username).as_slice());
        }

        batch.insert(
            &self.users,
            discord_lookup_key(discord_username).as_slice(),
            user_hash.raw().to_be_bytes(),
        );

        let mut updated = val;
        updated.discord_username = Some(discord_username.to_owned());
        updated.discord_id = None;
        updated.discord_verified = false;

        batch.insert(
            &self.users,
            user_primary_key(user_hash).as_slice(),
            updated.serialize(),
        );
        batch.commit().map_err(MetastoreError::Fjall)
    }

    pub fn store_discord_user_id(
        &self,
        discord_username: &str,
        discord_id: &str,
        handle: Option<&str>,
    ) -> Result<Option<Uuid>, MetastoreError> {
        let idx_key = discord_lookup_key(discord_username);
        let raw = match self
            .users
            .get(idx_key.as_slice())
            .map_err(MetastoreError::Fjall)?
        {
            Some(raw) if raw.len() >= 8 => raw,
            _ => match handle {
                Some(h) => {
                    let val = match self.load_by_handle(h)? {
                        Some(v) => v,
                        None => return Ok(None),
                    };
                    let user_hash = UserHash::from_did(&val.did);
                    self.mutate_user(user_hash, |u| {
                        u.discord_id = Some(discord_id.to_owned());
                    })?;
                    return Ok(Some(val.id));
                }
                None => return Ok(None),
            },
        };

        let hash_raw = u64::from_be_bytes(raw[..8].try_into().unwrap());
        let user_hash = UserHash::from_raw(hash_raw);
        let val = match self.load_user(user_hash)? {
            Some(v) => v,
            None => return Ok(None),
        };
        let uid = val.id;
        self.mutate_user(user_hash, |u| {
            u.discord_id = Some(discord_id.to_owned());
        })?;
        Ok(Some(uid))
    }

    pub fn get_verification_info(
        &self,
        did: &Did,
    ) -> Result<Option<UserVerificationInfo>, MetastoreError> {
        self.load_user_by_did(did.as_str())?
            .map(|v| {
                Ok(UserVerificationInfo {
                    id: v.id,
                    handle: Handle::new(v.handle.clone())
                        .map_err(|_| MetastoreError::CorruptData("invalid user handle"))?,
                    email: v.email.clone(),
                    channel_verification: Self::channel_verification(&v),
                })
            })
            .transpose()
    }

    pub fn verify_email_channel(&self, user_id: Uuid, email: &str) -> Result<bool, MetastoreError> {
        let user_hash = self.resolve_hash_from_uuid(user_id)?;
        match self.load_user(user_hash)? {
            Some(_) => {
                self.mutate_user(user_hash, |u| {
                    u.email = Some(email.to_owned());
                    u.email_verified = true;
                })?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    pub fn verify_discord_channel(
        &self,
        user_id: Uuid,
        discord_id: &str,
    ) -> Result<(), MetastoreError> {
        self.mutate_user_by_uuid(user_id, |u| {
            u.discord_id = Some(discord_id.to_owned());
            u.discord_verified = true;
        })?;
        Ok(())
    }

    pub fn verify_telegram_channel(
        &self,
        user_id: Uuid,
        telegram_username: &str,
    ) -> Result<(), MetastoreError> {
        self.mutate_user_by_uuid(user_id, |u| {
            if u.telegram_username.as_deref() == Some(telegram_username) {
                u.telegram_verified = true;
            }
        })?;
        Ok(())
    }

    pub fn verify_signal_channel(
        &self,
        user_id: Uuid,
        signal_username: &str,
    ) -> Result<(), MetastoreError> {
        self.mutate_user_by_uuid(user_id, |u| {
            if u.signal_username.as_deref() == Some(signal_username) {
                u.signal_verified = true;
            }
        })?;
        Ok(())
    }

    pub fn set_email_verified_flag(&self, user_id: Uuid) -> Result<(), MetastoreError> {
        self.mutate_user_by_uuid(user_id, |u| {
            u.email_verified = true;
        })?;
        Ok(())
    }

    pub fn set_discord_verified_flag(&self, user_id: Uuid) -> Result<(), MetastoreError> {
        self.mutate_user_by_uuid(user_id, |u| {
            u.discord_verified = true;
        })?;
        Ok(())
    }

    pub fn set_telegram_verified_flag(&self, user_id: Uuid) -> Result<(), MetastoreError> {
        self.mutate_user_by_uuid(user_id, |u| {
            u.telegram_verified = true;
        })?;
        Ok(())
    }

    pub fn set_signal_verified_flag(&self, user_id: Uuid) -> Result<(), MetastoreError> {
        self.mutate_user_by_uuid(user_id, |u| {
            u.signal_verified = true;
        })?;
        Ok(())
    }

    pub fn has_totp_enabled(&self, did: &Did) -> Result<bool, MetastoreError> {
        Ok(self
            .load_user_by_did(did.as_str())?
            .is_some_and(|v| v.totp_enabled))
    }

    pub fn has_passkeys(&self, did: &Did) -> Result<bool, MetastoreError> {
        let user_hash = self.resolve_hash(did.as_str());
        let prefix = passkey_prefix(user_hash);
        match self.users.prefix(prefix.as_slice()).next() {
            Some(guard) => {
                guard.into_inner().map_err(MetastoreError::Fjall)?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    pub fn get_password_hash_by_did(&self, did: &Did) -> Result<Option<String>, MetastoreError> {
        Ok(self
            .load_user_by_did(did.as_str())?
            .and_then(|v| v.password_hash.clone()))
    }

    pub fn get_passkeys_for_user(&self, did: &Did) -> Result<Vec<StoredPasskey>, MetastoreError> {
        let user_hash = self.resolve_hash(did.as_str());
        let prefix = passkey_prefix(user_hash);

        self.users
            .prefix(prefix.as_slice())
            .try_fold(Vec::new(), |mut acc, guard| {
                let (_, val_bytes) = guard.into_inner().map_err(MetastoreError::Fjall)?;
                let pv = PasskeyValue::deserialize(&val_bytes)
                    .ok_or(MetastoreError::CorruptData("corrupt passkey value"))?;
                acc.push(Self::to_stored_passkey(&pv)?);
                Ok::<_, MetastoreError>(acc)
            })
    }

    pub fn get_passkey_by_credential_id(
        &self,
        credential_id: &[u8],
    ) -> Result<Option<StoredPasskey>, MetastoreError> {
        let idx_key = passkey_by_cred_key(credential_id);
        let idx: Option<PasskeyIndexValue> = point_lookup(
            &self.users,
            idx_key.as_slice(),
            PasskeyIndexValue::deserialize,
            "corrupt passkey index",
        )?;

        match idx {
            Some(iv) => {
                let pk_key = passkey_key(UserHash::from_raw(iv.user_hash), iv.passkey_id);
                let pv: Option<PasskeyValue> = point_lookup(
                    &self.users,
                    pk_key.as_slice(),
                    PasskeyValue::deserialize,
                    "corrupt passkey value",
                )?;
                pv.map(|v| Self::to_stored_passkey(&v)).transpose()
            }
            None => Ok(None),
        }
    }

    pub fn save_passkey(
        &self,
        did: &Did,
        credential_id: &[u8],
        public_key: &[u8],
        friendly_name: Option<&str>,
    ) -> Result<Uuid, MetastoreError> {
        let user_hash = self.resolve_hash(did.as_str());
        let id = Uuid::new_v4();
        let now_ms = Utc::now().timestamp_millis();

        let value = PasskeyValue {
            id,
            did: did.to_string(),
            credential_id: credential_id.to_vec(),
            public_key: public_key.to_vec(),
            sign_count: 0,
            created_at_ms: now_ms,
            last_used_at_ms: None,
            friendly_name: friendly_name.map(str::to_owned),
            aaguid: None,
            transports: None,
        };

        let index = PasskeyIndexValue {
            user_hash: user_hash.raw(),
            passkey_id: id,
        };

        let mut batch = self.db.batch();
        batch.insert(
            &self.users,
            passkey_key(user_hash, id).as_slice(),
            value.serialize(),
        );
        batch.insert(
            &self.users,
            passkey_by_cred_key(credential_id).as_slice(),
            index.serialize(),
        );
        batch.commit().map_err(MetastoreError::Fjall)?;

        Ok(id)
    }

    pub fn update_passkey_counter(
        &self,
        credential_id: &[u8],
        new_counter: i32,
    ) -> Result<bool, MetastoreError> {
        let idx_key = passkey_by_cred_key(credential_id);
        let idx: Option<PasskeyIndexValue> = point_lookup(
            &self.users,
            idx_key.as_slice(),
            PasskeyIndexValue::deserialize,
            "corrupt passkey index",
        )?;

        let iv = match idx {
            Some(iv) => iv,
            None => return Ok(false),
        };

        let pk_key = passkey_key(UserHash::from_raw(iv.user_hash), iv.passkey_id);
        let pv: Option<PasskeyValue> = point_lookup(
            &self.users,
            pk_key.as_slice(),
            PasskeyValue::deserialize,
            "corrupt passkey value",
        )?;

        match pv {
            Some(mut val) => {
                val.sign_count = new_counter;
                val.last_used_at_ms = Some(Utc::now().timestamp_millis());
                self.users
                    .insert(pk_key.as_slice(), val.serialize())
                    .map_err(MetastoreError::Fjall)?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    pub fn delete_passkey(&self, id: Uuid, did: &Did) -> Result<bool, MetastoreError> {
        let user_hash = self.resolve_hash(did.as_str());
        let pk_key = passkey_key(user_hash, id);

        let pv: Option<PasskeyValue> = point_lookup(
            &self.users,
            pk_key.as_slice(),
            PasskeyValue::deserialize,
            "corrupt passkey value",
        )?;

        match pv {
            Some(val) => {
                let mut batch = self.db.batch();
                batch.remove(&self.users, pk_key.as_slice());
                batch.remove(
                    &self.users,
                    passkey_by_cred_key(&val.credential_id).as_slice(),
                );
                batch.commit().map_err(MetastoreError::Fjall)?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    pub fn update_passkey_name(
        &self,
        id: Uuid,
        did: &Did,
        name: &str,
    ) -> Result<bool, MetastoreError> {
        let user_hash = self.resolve_hash(did.as_str());
        let pk_key = passkey_key(user_hash, id);

        let pv: Option<PasskeyValue> = point_lookup(
            &self.users,
            pk_key.as_slice(),
            PasskeyValue::deserialize,
            "corrupt passkey value",
        )?;

        match pv {
            Some(mut val) => {
                val.friendly_name = Some(name.to_owned());
                self.users
                    .insert(pk_key.as_slice(), val.serialize())
                    .map_err(MetastoreError::Fjall)?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    pub fn save_webauthn_challenge(
        &self,
        did: &Did,
        challenge_type: WebauthnChallengeType,
        state_json: &str,
    ) -> Result<Uuid, MetastoreError> {
        let user_hash = self.resolve_hash(did.as_str());
        let type_u8 = challenge_type_to_u8(challenge_type);
        let id = Uuid::new_v4();
        let now_ms = Utc::now().timestamp_millis();

        let value = WebauthnChallengeValue {
            id,
            challenge_type: type_u8,
            state_json: state_json.to_owned(),
            created_at_ms: now_ms,
        };

        let key = webauthn_challenge_key(user_hash, type_u8);
        self.auth
            .insert(key.as_slice(), value.serialize_with_ttl())
            .map_err(MetastoreError::Fjall)?;

        Ok(id)
    }

    pub fn load_webauthn_challenge(
        &self,
        did: &Did,
        challenge_type: WebauthnChallengeType,
    ) -> Result<Option<String>, MetastoreError> {
        let user_hash = self.resolve_hash(did.as_str());
        let type_u8 = challenge_type_to_u8(challenge_type);
        let key = webauthn_challenge_key(user_hash, type_u8);

        let val: Option<WebauthnChallengeValue> = point_lookup(
            &self.auth,
            key.as_slice(),
            WebauthnChallengeValue::deserialize,
            "corrupt webauthn challenge",
        )?;

        Ok(val.map(|v| v.state_json))
    }

    pub fn delete_webauthn_challenge(
        &self,
        did: &Did,
        challenge_type: WebauthnChallengeType,
    ) -> Result<(), MetastoreError> {
        let user_hash = self.resolve_hash(did.as_str());
        let type_u8 = challenge_type_to_u8(challenge_type);
        let key = webauthn_challenge_key(user_hash, type_u8);
        self.auth
            .remove(key.as_slice())
            .map_err(MetastoreError::Fjall)
    }

    const DISCOVERABLE_CHALLENGE_TYPE: u8 = 2;

    pub fn save_discoverable_challenge(
        &self,
        request_key: &str,
        state_json: &str,
    ) -> Result<Uuid, MetastoreError> {
        let key_hash = UserHash::from_did(request_key);
        let id = Uuid::new_v4();
        let now_ms = Utc::now().timestamp_millis();

        let value = WebauthnChallengeValue {
            id,
            challenge_type: Self::DISCOVERABLE_CHALLENGE_TYPE,
            state_json: state_json.to_owned(),
            created_at_ms: now_ms,
        };

        let key = webauthn_challenge_key(key_hash, Self::DISCOVERABLE_CHALLENGE_TYPE);
        self.auth
            .insert(key.as_slice(), value.serialize_with_ttl())
            .map_err(MetastoreError::Fjall)?;

        Ok(id)
    }

    pub fn load_discoverable_challenge(
        &self,
        request_key: &str,
    ) -> Result<Option<String>, MetastoreError> {
        let key_hash = UserHash::from_did(request_key);
        let key = webauthn_challenge_key(key_hash, Self::DISCOVERABLE_CHALLENGE_TYPE);

        let val: Option<WebauthnChallengeValue> = point_lookup(
            &self.auth,
            key.as_slice(),
            WebauthnChallengeValue::deserialize,
            "corrupt webauthn challenge",
        )?;

        Ok(val.map(|v| v.state_json))
    }

    pub fn delete_discoverable_challenge(&self, request_key: &str) -> Result<(), MetastoreError> {
        let key_hash = UserHash::from_did(request_key);
        let key = webauthn_challenge_key(key_hash, Self::DISCOVERABLE_CHALLENGE_TYPE);
        self.auth
            .remove(key.as_slice())
            .map_err(MetastoreError::Fjall)
    }

    pub fn get_totp_record(&self, did: &Did) -> Result<Option<TotpRecord>, MetastoreError> {
        let user_hash = self.resolve_hash(did.as_str());
        let key = totp_key(user_hash);
        let val: Option<TotpValue> = point_lookup(
            &self.users,
            key.as_slice(),
            TotpValue::deserialize,
            "corrupt totp value",
        )?;

        Ok(val.map(|v| TotpRecord {
            secret_encrypted: v.secret_encrypted,
            encryption_version: v.encryption_version,
            verified: v.verified,
        }))
    }

    pub fn get_totp_record_state(
        &self,
        did: &Did,
    ) -> Result<Option<TotpRecordState>, MetastoreError> {
        self.get_totp_record(did)?
            .map(|r| Ok(TotpRecordState::from(r)))
            .transpose()
    }

    pub fn upsert_totp_secret(
        &self,
        did: &Did,
        secret_encrypted: &[u8],
        encryption_version: i32,
    ) -> Result<(), MetastoreError> {
        let user_hash = self.resolve_hash(did.as_str());
        let key = totp_key(user_hash);

        let value = TotpValue {
            secret_encrypted: secret_encrypted.to_vec(),
            encryption_version,
            verified: false,
            last_used_at_ms: None,
        };

        self.users
            .insert(key.as_slice(), value.serialize())
            .map_err(MetastoreError::Fjall)
    }

    pub fn set_totp_verified(&self, did: &Did) -> Result<(), MetastoreError> {
        let user_hash = self.resolve_hash(did.as_str());
        let key = totp_key(user_hash);

        let mut val = match point_lookup(
            &self.users,
            key.as_slice(),
            TotpValue::deserialize,
            "corrupt totp value",
        )? {
            Some(v) => v,
            None => return Ok(()),
        };

        val.verified = true;

        let mut batch = self.db.batch();
        batch.insert(&self.users, key.as_slice(), val.serialize());

        let mut user = match self.load_user(user_hash)? {
            Some(u) => u,
            None => {
                batch.commit().map_err(MetastoreError::Fjall)?;
                return Ok(());
            }
        };
        user.totp_enabled = true;
        batch.insert(
            &self.users,
            user_primary_key(user_hash).as_slice(),
            user.serialize(),
        );
        batch.commit().map_err(MetastoreError::Fjall)
    }

    pub fn update_totp_last_used(&self, did: &Did) -> Result<(), MetastoreError> {
        let user_hash = self.resolve_hash(did.as_str());
        let key = totp_key(user_hash);
        let mut val: TotpValue = match point_lookup(
            &self.users,
            key.as_slice(),
            TotpValue::deserialize,
            "corrupt totp value",
        )? {
            Some(v) => v,
            None => return Ok(()),
        };

        val.last_used_at_ms = Some(Utc::now().timestamp_millis());
        self.users
            .insert(key.as_slice(), val.serialize())
            .map_err(MetastoreError::Fjall)
    }

    pub fn delete_totp(&self, did: &Did) -> Result<(), MetastoreError> {
        let user_hash = self.resolve_hash(did.as_str());
        let key = totp_key(user_hash);

        let mut batch = self.db.batch();
        batch.remove(&self.users, key.as_slice());

        if let Some(mut user) = self.load_user(user_hash)? {
            user.totp_enabled = false;
            batch.insert(
                &self.users,
                user_primary_key(user_hash).as_slice(),
                user.serialize(),
            );
        }

        batch.commit().map_err(MetastoreError::Fjall)
    }

    pub fn get_unused_backup_codes(
        &self,
        did: &Did,
    ) -> Result<Vec<StoredBackupCode>, MetastoreError> {
        let user_hash = self.resolve_hash(did.as_str());
        let prefix = backup_code_prefix(user_hash);

        self.users
            .prefix(prefix.as_slice())
            .try_fold(Vec::new(), |mut acc, guard| {
                let (_, val_bytes) = guard.into_inner().map_err(MetastoreError::Fjall)?;
                let val = BackupCodeValue::deserialize(&val_bytes)
                    .ok_or(MetastoreError::CorruptData("corrupt backup code"))?;
                match val.used {
                    false => {
                        acc.push(StoredBackupCode {
                            id: val.id,
                            code_hash: val.code_hash,
                        });
                        Ok(acc)
                    }
                    true => Ok(acc),
                }
            })
    }

    pub fn mark_backup_code_used(&self, code_id: Uuid) -> Result<bool, MetastoreError> {
        let prefix = user_primary_prefix();
        let all_user_hashes: Vec<UserHash> = self
            .users
            .prefix(prefix.as_slice())
            .filter_map(|guard| {
                let (key_bytes, _) = guard.into_inner().ok()?;
                (key_bytes.len() >= 9).then(|| {
                    let hash_raw = u64::from_be_bytes(key_bytes[1..9].try_into().unwrap());
                    UserHash::from_raw(hash_raw)
                })
            })
            .collect();

        all_user_hashes
            .iter()
            .try_fold(false, |found, user_hash| match found {
                true => Ok(true),
                false => {
                    let key = backup_code_key(*user_hash, code_id);
                    let val: Option<BackupCodeValue> = point_lookup(
                        &self.users,
                        key.as_slice(),
                        BackupCodeValue::deserialize,
                        "corrupt backup code",
                    )?;
                    match val {
                        Some(mut bc) => {
                            bc.used = true;
                            self.users
                                .insert(key.as_slice(), bc.serialize())
                                .map_err(MetastoreError::Fjall)?;
                            Ok(true)
                        }
                        None => Ok(false),
                    }
                }
            })
    }

    pub fn count_unused_backup_codes(&self, did: &Did) -> Result<i64, MetastoreError> {
        let user_hash = self.resolve_hash(did.as_str());
        let prefix = backup_code_prefix(user_hash);

        self.users
            .prefix(prefix.as_slice())
            .try_fold(0i64, |acc, guard| {
                let (_, val_bytes) = guard.into_inner().map_err(MetastoreError::Fjall)?;
                let val = BackupCodeValue::deserialize(&val_bytes)
                    .ok_or(MetastoreError::CorruptData("corrupt backup code"))?;
                match val.used {
                    false => Ok(acc.saturating_add(1)),
                    true => Ok(acc),
                }
            })
    }

    pub fn delete_backup_codes(&self, did: &Did) -> Result<u64, MetastoreError> {
        let user_hash = self.resolve_hash(did.as_str());
        let prefix = backup_code_prefix(user_hash);

        let keys: Vec<Vec<u8>> = self
            .users
            .prefix(prefix.as_slice())
            .filter_map(|guard| {
                let (key_bytes, _) = guard.into_inner().ok()?;
                Some(key_bytes.to_vec())
            })
            .collect();

        let count = u64::try_from(keys.len()).unwrap_or(u64::MAX);
        match count {
            0 => Ok(0),
            _ => {
                let mut batch = self.db.batch();
                keys.iter().for_each(|key| {
                    batch.remove(&self.users, key);
                });
                batch.commit().map_err(MetastoreError::Fjall)?;
                Ok(count)
            }
        }
    }

    fn insert_backup_codes_batch(
        &self,
        batch: &mut fjall::OwnedWriteBatch,
        user_hash: UserHash,
        code_hashes: &[String],
    ) {
        code_hashes.iter().for_each(|hash| {
            let id = Uuid::new_v4();
            let value = BackupCodeValue {
                id,
                code_hash: hash.clone(),
                used: false,
            };
            batch.insert(
                &self.users,
                backup_code_key(user_hash, id).as_slice(),
                value.serialize(),
            );
        });
    }

    pub fn insert_backup_codes(
        &self,
        did: &Did,
        code_hashes: &[String],
    ) -> Result<(), MetastoreError> {
        let user_hash = self.resolve_hash(did.as_str());
        let mut batch = self.db.batch();
        self.insert_backup_codes_batch(&mut batch, user_hash, code_hashes);
        batch.commit().map_err(MetastoreError::Fjall)
    }

    pub fn enable_totp_with_backup_codes(
        &self,
        did: &Did,
        code_hashes: &[String],
    ) -> Result<(), MetastoreError> {
        let user_hash = self.resolve_hash(did.as_str());
        let mut batch = self.db.batch();

        if let Some(mut user) = self.load_user(user_hash)? {
            user.totp_enabled = true;
            user.two_factor_enabled = true;
            batch.insert(
                &self.users,
                user_primary_key(user_hash).as_slice(),
                user.serialize(),
            );
        }

        self.insert_backup_codes_batch(&mut batch, user_hash, code_hashes);
        batch.commit().map_err(MetastoreError::Fjall)
    }

    pub fn delete_totp_and_backup_codes(&self, did: &Did) -> Result<(), MetastoreError> {
        let user_hash = self.resolve_hash(did.as_str());
        let mut batch = self.db.batch();

        batch.remove(&self.users, totp_key(user_hash).as_slice());
        delete_all_by_prefix(
            &self.users,
            &mut batch,
            backup_code_prefix(user_hash).as_slice(),
        )?;

        if let Some(mut user) = self.load_user(user_hash)? {
            user.totp_enabled = false;
            batch.insert(
                &self.users,
                user_primary_key(user_hash).as_slice(),
                user.serialize(),
            );
        }

        batch.commit().map_err(MetastoreError::Fjall)
    }

    pub fn replace_backup_codes(
        &self,
        did: &Did,
        code_hashes: &[String],
    ) -> Result<(), MetastoreError> {
        let user_hash = self.resolve_hash(did.as_str());
        let mut batch = self.db.batch();
        delete_all_by_prefix(
            &self.users,
            &mut batch,
            backup_code_prefix(user_hash).as_slice(),
        )?;
        self.insert_backup_codes_batch(&mut batch, user_hash, code_hashes);
        batch.commit().map_err(MetastoreError::Fjall)
    }

    pub fn get_session_info_by_did(
        &self,
        did: &Did,
    ) -> Result<Option<UserSessionInfo>, MetastoreError> {
        self.load_user_by_did(did.as_str())?
            .map(|v| {
                Ok(UserSessionInfo {
                    handle: Handle::new(v.handle.clone())
                        .map_err(|_| MetastoreError::CorruptData("invalid user handle"))?,
                    email: v.email.clone(),
                    is_admin: v.is_admin,
                    deactivated_at: v
                        .deactivated_at_ms
                        .and_then(DateTime::from_timestamp_millis),
                    takedown_ref: v.takedown_ref.clone(),
                    preferred_locale: v.preferred_locale.clone(),
                    preferred_comms_channel: Self::comms_channel(&v),
                    channel_verification: Self::channel_verification(&v),
                    migrated_to_pds: v.migrated_to_pds.clone(),
                    migrated_at: v.migrated_at_ms.and_then(DateTime::from_timestamp_millis),
                    totp_enabled: v.totp_enabled,
                    email_2fa_enabled: v.email_2fa_enabled,
                })
            })
            .transpose()
    }

    pub fn get_legacy_login_pref(
        &self,
        did: &Did,
    ) -> Result<Option<UserLegacyLoginPref>, MetastoreError> {
        Ok(self
            .load_user_by_did(did.as_str())?
            .map(|v| UserLegacyLoginPref {
                allow_legacy_login: v.allow_legacy_login,
                has_mfa: v.two_factor_enabled || v.totp_enabled,
            }))
    }

    pub fn update_legacy_login(&self, did: &Did, allow: bool) -> Result<bool, MetastoreError> {
        let user_hash = self.resolve_hash(did.as_str());
        self.mutate_user(user_hash, |u| {
            u.allow_legacy_login = allow;
        })
    }

    pub fn set_email_2fa_enabled(
        &self,
        user_id: Uuid,
        enabled: bool,
    ) -> Result<bool, MetastoreError> {
        let user_hash = self.resolve_hash_from_uuid(user_id)?;
        self.mutate_user(user_hash, |u| {
            u.email_2fa_enabled = enabled;
        })
    }

    pub fn update_locale(&self, did: &Did, locale: &str) -> Result<bool, MetastoreError> {
        let user_hash = self.resolve_hash(did.as_str());
        self.mutate_user(user_hash, |u| {
            u.preferred_locale = Some(locale.to_owned());
        })
    }

    pub fn get_login_full_by_identifier(
        &self,
        identifier: &str,
    ) -> Result<Option<UserLoginFull>, MetastoreError> {
        self.load_by_identifier(identifier)?
            .map(|v| {
                Ok(UserLoginFull {
                    id: v.id,
                    did: Did::new(v.did.clone())
                        .map_err(|_| MetastoreError::CorruptData("invalid user did"))?,
                    handle: Handle::new(v.handle.clone())
                        .map_err(|_| MetastoreError::CorruptData("invalid user handle"))?,
                    password_hash: v.password_hash.clone(),
                    email: v.email.clone(),
                    deactivated_at: v
                        .deactivated_at_ms
                        .and_then(DateTime::from_timestamp_millis),
                    takedown_ref: v.takedown_ref.clone(),
                    channel_verification: Self::channel_verification(&v),
                    allow_legacy_login: v.allow_legacy_login,
                    migrated_to_pds: v.migrated_to_pds.clone(),
                    preferred_comms_channel: Self::comms_channel(&v),
                    key_bytes: v.key_bytes.clone(),
                    encryption_version: Some(v.encryption_version),
                    totp_enabled: v.totp_enabled,
                    email_2fa_enabled: v.email_2fa_enabled,
                })
            })
            .transpose()
    }

    pub fn get_confirm_signup_by_did(
        &self,
        did: &Did,
    ) -> Result<Option<UserConfirmSignup>, MetastoreError> {
        self.load_user_by_did(did.as_str())?
            .map(|v| {
                Ok(UserConfirmSignup {
                    id: v.id,
                    did: Did::new(v.did.clone())
                        .map_err(|_| MetastoreError::CorruptData("invalid user did"))?,
                    handle: Handle::new(v.handle.clone())
                        .map_err(|_| MetastoreError::CorruptData("invalid user handle"))?,
                    email: v.email.clone(),
                    channel: Self::comms_channel(&v),
                    discord_username: v.discord_username.clone(),
                    telegram_username: v.telegram_username.clone(),
                    signal_username: v.signal_username.clone(),
                    key_bytes: v.key_bytes.clone(),
                    encryption_version: Some(v.encryption_version),
                })
            })
            .transpose()
    }

    pub fn get_resend_verification_by_did(
        &self,
        did: &Did,
    ) -> Result<Option<UserResendVerification>, MetastoreError> {
        self.load_user_by_did(did.as_str())?
            .map(|v| {
                Ok(UserResendVerification {
                    id: v.id,
                    handle: Handle::new(v.handle.clone())
                        .map_err(|_| MetastoreError::CorruptData("invalid user handle"))?,
                    email: v.email.clone(),
                    channel: Self::comms_channel(&v),
                    discord_username: v.discord_username.clone(),
                    telegram_username: v.telegram_username.clone(),
                    signal_username: v.signal_username.clone(),
                    channel_verification: Self::channel_verification(&v),
                })
            })
            .transpose()
    }

    pub fn set_channel_verified(
        &self,
        did: &Did,
        channel: CommsChannel,
    ) -> Result<(), MetastoreError> {
        let user_hash = self.resolve_hash(did.as_str());
        self.mutate_user(user_hash, |u| match channel {
            CommsChannel::Email => u.email_verified = true,
            CommsChannel::Discord => u.discord_verified = true,
            CommsChannel::Telegram => u.telegram_verified = true,
            CommsChannel::Signal => u.signal_verified = true,
        })?;
        Ok(())
    }

    pub fn get_id_by_email_or_handle(
        &self,
        email: &str,
        handle: &str,
    ) -> Result<Option<Uuid>, MetastoreError> {
        match self.load_by_email(email)? {
            Some(v) => Ok(Some(v.id)),
            None => Ok(self.load_by_handle(handle)?.map(|v| v.id)),
        }
    }

    pub fn count_accounts_by_email(&self, email: &str) -> Result<i64, MetastoreError> {
        match self.load_by_email(email)? {
            Some(_) => Ok(1),
            None => Ok(0),
        }
    }

    pub fn get_handles_by_email(&self, email: &str) -> Result<Vec<Handle>, MetastoreError> {
        match self.load_by_email(email)? {
            Some(v) => Handle::new(v.handle.clone())
                .map(|h| vec![h])
                .map_err(|_| MetastoreError::CorruptData("invalid user handle")),
            None => Ok(Vec::new()),
        }
    }

    pub fn set_password_reset_code(
        &self,
        user_id: Uuid,
        code: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), MetastoreError> {
        let user_hash = self.resolve_hash_from_uuid(user_id)?;
        let user = self
            .load_user(user_hash)?
            .ok_or(MetastoreError::InvalidInput("user not found"))?;

        let value = ResetCodeValue {
            user_hash: user_hash.raw(),
            user_id,
            preferred_comms_channel: user.preferred_comms_channel,
            code: code.to_owned(),
            expires_at_ms: expires_at.timestamp_millis(),
        };

        let key = reset_code_key(code);
        self.auth
            .insert(key.as_slice(), value.serialize_with_ttl())
            .map_err(MetastoreError::Fjall)
    }

    pub fn get_user_by_reset_code(
        &self,
        code: &str,
    ) -> Result<Option<UserResetCodeInfo>, MetastoreError> {
        let key = reset_code_key(code);
        let val: Option<ResetCodeValue> = point_lookup(
            &self.auth,
            key.as_slice(),
            ResetCodeValue::deserialize,
            "corrupt reset code",
        )?;

        match val {
            Some(rc) => {
                let user_hash = UserHash::from_raw(rc.user_hash);
                match self.load_user(user_hash)? {
                    Some(u) => Ok(Some(UserResetCodeInfo {
                        id: u.id,
                        did: Did::new(u.did.clone())
                            .map_err(|_| MetastoreError::CorruptData("invalid user did"))?,
                        preferred_comms_channel: Self::comms_channel(&u),
                        expires_at: DateTime::from_timestamp_millis(rc.expires_at_ms),
                    })),
                    None => Ok(None),
                }
            }
            None => Ok(None),
        }
    }

    pub fn clear_password_reset_code(&self, user_id: Uuid) -> Result<(), MetastoreError> {
        let user_hash = self.resolve_hash_from_uuid(user_id)?;
        let user = match self.load_user(user_hash)? {
            Some(u) => u,
            None => return Ok(()),
        };
        let _ = user;

        let prefix = [super::keys::KeyTag::USER_RESET_CODE.raw()];
        let keys_to_remove: Vec<Vec<u8>> = self
            .auth
            .prefix(prefix)
            .filter_map(|guard| {
                let (key_bytes, val_bytes) = guard.into_inner().ok()?;
                let rc = ResetCodeValue::deserialize(&val_bytes)?;
                match rc.user_id == user_id {
                    true => Some(key_bytes.to_vec()),
                    false => None,
                }
            })
            .collect();

        match keys_to_remove.is_empty() {
            true => Ok(()),
            false => {
                let mut batch = self.db.batch();
                keys_to_remove.iter().for_each(|key| {
                    batch.remove(&self.auth, key);
                });
                batch.commit().map_err(MetastoreError::Fjall)
            }
        }
    }

    pub fn get_id_and_password_hash_by_did(
        &self,
        did: &Did,
    ) -> Result<Option<UserIdAndPasswordHash>, MetastoreError> {
        self.load_user_by_did(did.as_str())?
            .and_then(|v| v.password_hash.clone().map(|ph| (v.id, ph)))
            .map(|(id, ph)| {
                Ok(UserIdAndPasswordHash {
                    id,
                    password_hash: ph,
                })
            })
            .transpose()
    }

    pub fn update_password_hash(
        &self,
        user_id: Uuid,
        password_hash: &str,
    ) -> Result<(), MetastoreError> {
        self.mutate_user_by_uuid(user_id, |u| {
            u.password_hash = Some(password_hash.to_owned());
        })?;
        Ok(())
    }

    pub fn reset_password_with_sessions(
        &self,
        user_id: Uuid,
        password_hash: &str,
    ) -> Result<PasswordResetResult, MetastoreError> {
        let user_hash = self.resolve_hash_from_uuid(user_id)?;
        let user = self
            .load_user(user_hash)?
            .ok_or(MetastoreError::InvalidInput("user not found"))?;

        let did = Did::new(user.did.clone())
            .map_err(|_| MetastoreError::CorruptData("invalid user did"))?;

        let prefix = super::sessions::session_by_did_prefix(user_hash);
        let sessions: Vec<(Vec<u8>, i32, String)> = self
            .auth
            .prefix(prefix.as_slice())
            .filter_map(|guard| {
                let (key_bytes, _) = guard.into_inner().ok()?;
                let remaining = key_bytes.get(9..13)?;
                let sid = i32::from_be_bytes(remaining.try_into().ok()?);
                let session_key = super::sessions::session_primary_key(sid);
                let jti = self
                    .auth
                    .get(session_key.as_slice())
                    .ok()
                    .flatten()
                    .and_then(|raw| super::sessions::SessionTokenValue::deserialize(&raw))
                    .map(|s| s.access_jti)?;
                Some((key_bytes.to_vec(), sid, jti))
            })
            .collect();

        let session_jtis: Vec<String> = sessions.iter().map(|(_, _, jti)| jti.clone()).collect();

        let mut batch = self.db.batch();

        let mut updated = user;
        updated.password_hash = Some(password_hash.to_owned());
        updated.password_required = true;
        batch.insert(
            &self.users,
            super::encoding::KeyBuilder::new()
                .tag(super::keys::KeyTag::USER_PRIMARY)
                .u64(user_hash.raw())
                .build()
                .as_slice(),
            updated.serialize(),
        );

        for (index_key, sid, _) in &sessions {
            let session_key = super::sessions::session_primary_key(*sid);
            batch.remove(&self.auth, session_key.as_slice());
            batch.remove(&self.auth, index_key.as_slice());
        }

        batch.commit().map_err(MetastoreError::Fjall)?;

        self.clear_password_reset_code(user_id)?;

        Ok(PasswordResetResult { did, session_jtis })
    }

    pub fn activate_account(&self, did: &Did) -> Result<bool, MetastoreError> {
        let user_hash = self.resolve_hash(did.as_str());
        self.mutate_user(user_hash, |u| {
            u.deactivated_at_ms = None;
            u.delete_after_ms = None;
        })
    }

    pub fn deactivate_account(
        &self,
        did: &Did,
        delete_after: Option<DateTime<Utc>>,
    ) -> Result<bool, MetastoreError> {
        let user_hash = self.resolve_hash(did.as_str());
        let now_ms = Utc::now().timestamp_millis();
        self.mutate_user(user_hash, |u| {
            u.deactivated_at_ms = Some(now_ms);
            u.delete_after_ms = delete_after.map(|dt| dt.timestamp_millis());
        })
    }

    pub fn has_password_by_did(&self, did: &Did) -> Result<Option<bool>, MetastoreError> {
        Ok(self
            .load_user_by_did(did.as_str())?
            .map(|v| v.password_hash.is_some()))
    }

    pub fn get_password_info_by_did(
        &self,
        did: &Did,
    ) -> Result<Option<UserPasswordInfo>, MetastoreError> {
        Ok(self
            .load_user_by_did(did.as_str())?
            .map(|v| UserPasswordInfo {
                id: v.id,
                password_hash: v.password_hash.clone(),
            }))
    }

    pub fn remove_user_password(&self, user_id: Uuid) -> Result<(), MetastoreError> {
        self.mutate_user_by_uuid(user_id, |u| {
            u.password_hash = None;
            u.password_required = false;
        })?;
        Ok(())
    }

    pub fn set_new_user_password(
        &self,
        user_id: Uuid,
        password_hash: &str,
    ) -> Result<(), MetastoreError> {
        self.mutate_user_by_uuid(user_id, |u| {
            u.password_hash = Some(password_hash.to_owned());
            u.password_required = true;
        })?;
        Ok(())
    }

    pub fn get_user_key_by_did(&self, did: &Did) -> Result<Option<UserKeyInfo>, MetastoreError> {
        Ok(self.load_user_by_did(did.as_str())?.map(|v| UserKeyInfo {
            key_bytes: v.key_bytes.clone(),
            encryption_version: Some(v.encryption_version),
        }))
    }

    fn delete_user_data(
        &self,
        batch: &mut fjall::OwnedWriteBatch,
        user_hash: UserHash,
        user: &UserValue,
    ) -> Result<(), MetastoreError> {
        batch.remove(&self.users, user_primary_key(user_hash).as_slice());
        batch.remove(&self.users, user_by_handle_key(&user.handle).as_slice());

        if let Some(email) = &user.email {
            batch.remove(&self.users, user_by_email_key(email).as_slice());
        }

        if let Some(tg) = &user.telegram_username {
            batch.remove(&self.users, telegram_lookup_key(tg).as_slice());
        }

        if let Some(dc) = &user.discord_username {
            batch.remove(&self.users, discord_lookup_key(dc).as_slice());
        }

        self.users
            .prefix(passkey_prefix(user_hash).as_slice())
            .try_for_each(|guard| {
                let (key_bytes, val_bytes) = guard.into_inner().map_err(MetastoreError::Fjall)?;
                batch.remove(&self.users, key_bytes.as_ref());
                if let Some(pv) = PasskeyValue::deserialize(&val_bytes) {
                    batch.remove(
                        &self.users,
                        passkey_by_cred_key(&pv.credential_id).as_slice(),
                    );
                }
                Ok::<(), MetastoreError>(())
            })?;

        batch.remove(&self.users, totp_key(user_hash).as_slice());
        delete_all_by_prefix(&self.users, batch, backup_code_prefix(user_hash).as_slice())?;
        batch.remove(&self.users, recovery_token_key(user_hash).as_slice());
        batch.remove(&self.users, did_web_overrides_key(user_hash).as_slice());

        self.delete_auth_data_for_user(batch, user_hash)?;

        Ok(())
    }

    fn delete_auth_data_for_user(
        &self,
        batch: &mut fjall::OwnedWriteBatch,
        user_hash: UserHash,
    ) -> Result<(), MetastoreError> {
        use super::sessions::{
            SessionTokenValue, session_app_password_prefix, session_by_access_key,
            session_by_did_prefix, session_by_refresh_key, session_last_reauth_key,
            session_primary_key,
        };

        let did_prefix = session_by_did_prefix(user_hash);
        self.auth
            .prefix(did_prefix.as_slice())
            .try_for_each(|guard| {
                let (key_bytes, _) = guard.into_inner().map_err(MetastoreError::Fjall)?;
                let mut reader = super::encoding::KeyReader::new(&key_bytes);
                let _tag = reader.tag();
                let _hash = reader.u64();
                let sid_bytes: [u8; 4] = reader
                    .remaining()
                    .try_into()
                    .map_err(|_| MetastoreError::CorruptData("session_by_did key truncated"))?;
                let sid = i32::from_be_bytes(sid_bytes);

                let primary = session_primary_key(sid);
                if let Some(raw) = self
                    .auth
                    .get(primary.as_slice())
                    .map_err(MetastoreError::Fjall)?
                {
                    if let Some(session) = SessionTokenValue::deserialize(&raw) {
                        batch.remove(
                            &self.auth,
                            session_by_access_key(&session.access_jti).as_slice(),
                        );
                        batch.remove(
                            &self.auth,
                            session_by_refresh_key(&session.refresh_jti).as_slice(),
                        );
                    }
                    batch.remove(&self.auth, primary.as_slice());
                }

                batch.remove(&self.auth, key_bytes.as_ref());
                Ok::<(), MetastoreError>(())
            })?;

        delete_all_by_prefix(
            &self.auth,
            batch,
            session_app_password_prefix(user_hash).as_slice(),
        )?;

        batch.remove(&self.auth, session_last_reauth_key(user_hash).as_slice());

        batch.remove(&self.auth, webauthn_challenge_key(user_hash, 0).as_slice());
        batch.remove(&self.auth, webauthn_challenge_key(user_hash, 1).as_slice());

        Ok(())
    }

    pub fn delete_account_complete(&self, user_id: Uuid, did: &Did) -> Result<(), MetastoreError> {
        let user_hash = self.resolve_hash(did.as_str());
        let user = match self.load_user(user_hash)? {
            Some(u) => u,
            None => return Ok(()),
        };

        let mut batch = self.db.batch();
        self.delete_user_data(&mut batch, user_hash, &user)?;
        self.user_hashes.stage_remove(&mut batch, &user_id);
        batch.commit().map_err(MetastoreError::Fjall)
    }

    pub fn set_user_takedown(
        &self,
        did: &Did,
        takedown_ref: Option<&str>,
    ) -> Result<bool, MetastoreError> {
        let user_hash = self.resolve_hash(did.as_str());
        self.mutate_user(user_hash, |u| {
            u.takedown_ref = takedown_ref.map(str::to_owned);
        })
    }

    pub fn admin_delete_account_complete(
        &self,
        user_id: Uuid,
        did: &Did,
    ) -> Result<(), MetastoreError> {
        self.delete_account_complete(user_id, did)
    }

    pub fn get_user_for_did_doc(&self, did: &Did) -> Result<Option<UserForDidDoc>, MetastoreError> {
        self.load_user_by_did(did.as_str())?
            .map(|v| {
                Ok(UserForDidDoc {
                    id: v.id,
                    handle: Handle::new(v.handle.clone())
                        .map_err(|_| MetastoreError::CorruptData("invalid user handle"))?,
                    deactivated_at: v
                        .deactivated_at_ms
                        .and_then(DateTime::from_timestamp_millis),
                })
            })
            .transpose()
    }

    pub fn get_user_for_did_doc_build(
        &self,
        did: &Did,
    ) -> Result<Option<UserForDidDocBuild>, MetastoreError> {
        self.load_user_by_did(did.as_str())?
            .map(|v| {
                Ok(UserForDidDocBuild {
                    id: v.id,
                    handle: Handle::new(v.handle.clone())
                        .map_err(|_| MetastoreError::CorruptData("invalid user handle"))?,
                    migrated_to_pds: v.migrated_to_pds.clone(),
                })
            })
            .transpose()
    }

    pub fn upsert_did_web_overrides(
        &self,
        user_id: Uuid,
        verification_methods: Option<serde_json::Value>,
        also_known_as: Option<Vec<String>>,
    ) -> Result<(), MetastoreError> {
        let user_hash = self.resolve_hash_from_uuid(user_id)?;
        let key = did_web_overrides_key(user_hash);

        let value = DidWebOverridesValue {
            verification_methods_json: verification_methods
                .map(|v| serde_json::to_string(&v).unwrap_or_default()),
            also_known_as,
        };

        self.users
            .insert(key.as_slice(), value.serialize())
            .map_err(MetastoreError::Fjall)
    }

    pub fn update_migrated_to_pds(&self, did: &Did, endpoint: &str) -> Result<(), MetastoreError> {
        let user_hash = self.resolve_hash(did.as_str());
        let now_ms = Utc::now().timestamp_millis();
        self.mutate_user(user_hash, |u| {
            u.migrated_to_pds = Some(endpoint.to_owned());
            u.migrated_at_ms = Some(now_ms);
        })?;
        Ok(())
    }

    pub fn get_user_for_passkey_setup(
        &self,
        did: &Did,
    ) -> Result<Option<UserForPasskeySetup>, MetastoreError> {
        let user_hash = self.resolve_hash(did.as_str());
        let user = match self.load_user(user_hash)? {
            Some(u) => u,
            None => return Ok(None),
        };

        let recovery: Option<RecoveryTokenValue> = point_lookup(
            &self.users,
            recovery_token_key(user_hash).as_slice(),
            RecoveryTokenValue::deserialize,
            "corrupt recovery token",
        )?;

        Ok(Some(UserForPasskeySetup {
            id: user.id,
            handle: Handle::new(user.handle.clone())
                .map_err(|_| MetastoreError::CorruptData("invalid user handle"))?,
            recovery_token: recovery.as_ref().map(|r| r.token_hash.clone()),
            recovery_token_expires_at: recovery
                .as_ref()
                .and_then(|r| DateTime::from_timestamp_millis(r.expires_at_ms)),
            password_required: user.password_required,
        }))
    }

    pub fn get_user_for_passkey_recovery(
        &self,
        identifier: &str,
        normalized_handle: &str,
    ) -> Result<Option<UserForPasskeyRecovery>, MetastoreError> {
        let val = match self.load_by_identifier(identifier)? {
            Some(v) => v,
            None => match self.load_by_handle(normalized_handle)? {
                Some(v) => v,
                None => return Ok(None),
            },
        };

        Ok(Some(UserForPasskeyRecovery {
            id: val.id,
            did: Did::new(val.did.clone())
                .map_err(|_| MetastoreError::CorruptData("invalid user did"))?,
            handle: Handle::new(val.handle.clone())
                .map_err(|_| MetastoreError::CorruptData("invalid user handle"))?,
            password_required: val.password_required,
        }))
    }

    pub fn set_recovery_token(
        &self,
        did: &Did,
        token_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), MetastoreError> {
        let user_hash = self.resolve_hash(did.as_str());
        let key = recovery_token_key(user_hash);

        let value = RecoveryTokenValue {
            token_hash: token_hash.to_owned(),
            expires_at_ms: expires_at.timestamp_millis(),
        };

        self.users
            .insert(key.as_slice(), value.serialize())
            .map_err(MetastoreError::Fjall)
    }

    pub fn get_user_for_recovery(
        &self,
        did: &Did,
    ) -> Result<Option<UserForRecovery>, MetastoreError> {
        let user_hash = self.resolve_hash(did.as_str());
        let user = match self.load_user(user_hash)? {
            Some(u) => u,
            None => return Ok(None),
        };

        let recovery: Option<RecoveryTokenValue> = point_lookup(
            &self.users,
            recovery_token_key(user_hash).as_slice(),
            RecoveryTokenValue::deserialize,
            "corrupt recovery token",
        )?;

        Ok(Some(UserForRecovery {
            id: user.id,
            did: Did::new(user.did.clone())
                .map_err(|_| MetastoreError::CorruptData("invalid user did"))?,
            preferred_comms_channel: Self::comms_channel(&user),
            recovery_token: recovery.as_ref().map(|r| r.token_hash.clone()),
            recovery_token_expires_at: recovery
                .as_ref()
                .and_then(|r| DateTime::from_timestamp_millis(r.expires_at_ms)),
        }))
    }

    pub fn get_accounts_scheduled_for_deletion(
        &self,
        limit: i64,
    ) -> Result<Vec<ScheduledDeletionAccount>, MetastoreError> {
        let prefix = user_primary_prefix();
        let limit = usize::try_from(limit).unwrap_or(0);
        let now_ms = Utc::now().timestamp_millis();

        self.users
            .prefix(prefix.as_slice())
            .map(
                |guard| -> Result<Option<ScheduledDeletionAccount>, MetastoreError> {
                    let (_, val_bytes) = guard.into_inner().map_err(MetastoreError::Fjall)?;
                    let val = UserValue::deserialize(&val_bytes)
                        .ok_or(MetastoreError::CorruptData("corrupt user value"))?;
                    match val.delete_after_ms {
                        Some(delete_at) if delete_at <= now_ms => {
                            Ok(Some(ScheduledDeletionAccount {
                                id: val.id,
                                did: Did::new(val.did.clone())
                                    .map_err(|_| MetastoreError::CorruptData("invalid user did"))?,
                                handle: Handle::new(val.handle.clone()).map_err(|_| {
                                    MetastoreError::CorruptData("invalid user handle")
                                })?,
                            }))
                        }
                        _ => Ok(None),
                    }
                },
            )
            .filter_map(Result::transpose)
            .take(limit)
            .collect()
    }

    #[allow(clippy::too_many_arguments)]
    fn build_user_value(
        &self,
        did: &Did,
        handle: &Handle,
        email: Option<&str>,
        password_hash: Option<&str>,
        preferred_comms_channel: CommsChannel,
        discord_username: Option<&str>,
        telegram_username: Option<&str>,
        signal_username: Option<&str>,
        deactivated_at: Option<DateTime<Utc>>,
        encrypted_key_bytes: &[u8],
        encryption_version: i32,
        account_type: AccountType,
        password_required: bool,
        is_admin: bool,
    ) -> UserValue {
        let now_ms = Utc::now().timestamp_millis();
        UserValue {
            id: Uuid::new_v4(),
            did: did.to_string(),
            handle: handle.as_str().to_owned(),
            email: email.map(str::to_owned),
            email_verified: false,
            password_hash: password_hash.map(str::to_owned),
            created_at_ms: now_ms,
            deactivated_at_ms: deactivated_at.map(|dt| dt.timestamp_millis()),
            takedown_ref: None,
            is_admin,
            preferred_comms_channel: Some(channel_to_u8(preferred_comms_channel)),
            key_bytes: encrypted_key_bytes.to_vec(),
            encryption_version,
            account_type: account_type_to_u8(account_type),
            password_required,
            two_factor_enabled: false,
            email_2fa_enabled: false,
            totp_enabled: false,
            allow_legacy_login: false,
            preferred_locale: None,
            invites_disabled: false,
            migrated_to_pds: None,
            migrated_at_ms: None,
            discord_username: discord_username.map(str::to_owned),
            discord_id: None,
            discord_verified: false,
            telegram_username: telegram_username.map(str::to_owned),
            telegram_chat_id: None,
            telegram_verified: false,
            signal_username: signal_username.map(str::to_owned),
            signal_verified: false,
            delete_after_ms: None,
        }
    }

    fn write_new_account(
        &self,
        user_value: &UserValue,
        commit_cid: &str,
        repo_rev: &str,
    ) -> Result<CreatePasswordAccountResult, CreateAccountError> {
        let user_hash = UserHash::from_did(&user_value.did);
        let user_id = user_value.id;

        let cid_link =
            CidLink::new(commit_cid).map_err(|e| CreateAccountError::Database(e.to_string()))?;
        let cid_bytes = cid_link_to_bytes(&cid_link)
            .map_err(|e| CreateAccountError::Database(e.to_string()))?;

        let handle_lower = user_value.handle.to_ascii_lowercase();

        let repo_meta = RepoMetaValue {
            repo_root_cid: cid_bytes,
            repo_rev: repo_rev.to_string(),
            handle: handle_lower.clone(),
            status: RepoStatus::Active,
            deactivated_at_ms: user_value
                .deactivated_at_ms
                .and_then(|ms| u64::try_from(ms).ok()),
            takedown_ref: None,
            did: Some(user_value.did.clone()),
        };

        let mut batch = self.db.batch();

        self.user_hashes
            .stage_insert(&mut batch, user_id, user_hash)
            .map_err(|e| CreateAccountError::Database(e.to_string()))?;

        batch.insert(
            &self.users,
            user_primary_key(user_hash).as_slice(),
            user_value.serialize(),
        );
        batch.insert(
            &self.users,
            user_by_handle_key(user_value.handle.as_str()).as_slice(),
            user_hash.raw().to_be_bytes(),
        );

        if let Some(email) = &user_value.email {
            batch.insert(
                &self.users,
                user_by_email_key(email).as_slice(),
                user_hash.raw().to_be_bytes(),
            );
        }

        if let Some(tg) = &user_value.telegram_username {
            batch.insert(
                &self.users,
                telegram_lookup_key(tg).as_slice(),
                user_hash.raw().to_be_bytes(),
            );
        }

        if let Some(dc) = &user_value.discord_username {
            batch.insert(
                &self.users,
                discord_lookup_key(dc).as_slice(),
                user_hash.raw().to_be_bytes(),
            );
        }

        batch.insert(
            &self.repo_data,
            repo_meta_key(user_hash).as_slice(),
            repo_meta.serialize(),
        );
        batch.insert(
            &self.repo_data,
            handle_key(&handle_lower).as_slice(),
            user_hash.raw().to_be_bytes(),
        );

        match batch.commit() {
            Ok(()) => Ok(CreatePasswordAccountResult {
                user_id,
                is_admin: user_value.is_admin,
            }),
            Err(e) => {
                self.user_hashes.rollback_insert(&user_id, &user_hash);
                Err(CreateAccountError::Database(e.to_string()))
            }
        }
    }

    fn check_availability(
        &self,
        did: &Did,
        handle: &Handle,
        email: Option<&str>,
    ) -> Result<(), CreateAccountError> {
        match self.load_user_by_did(did.as_str()) {
            Ok(Some(_)) => return Err(CreateAccountError::DidExists),
            Err(e) => return Err(CreateAccountError::Database(e.to_string())),
            Ok(None) => {}
        }

        match self.load_by_handle(handle.as_str()) {
            Ok(Some(_)) => return Err(CreateAccountError::HandleTaken),
            Err(e) => return Err(CreateAccountError::Database(e.to_string())),
            Ok(None) => {}
        }

        if let Some(email) = email {
            match self.load_by_email(email) {
                Ok(Some(_)) => return Err(CreateAccountError::EmailTaken),
                Err(e) => return Err(CreateAccountError::Database(e.to_string())),
                Ok(None) => {}
            }
        }

        Ok(())
    }

    pub fn create_password_account(
        &self,
        input: &CreatePasswordAccountInput,
    ) -> Result<CreatePasswordAccountResult, CreateAccountError> {
        self.check_availability(&input.did, &input.handle, input.email.as_deref())?;

        let is_admin = self
            .is_first_account()
            .map_err(|e| CreateAccountError::Database(e.to_string()))?;

        let user_value = self.build_user_value(
            &input.did,
            &input.handle,
            input.email.as_deref(),
            Some(&input.password_hash),
            input.preferred_comms_channel,
            input.discord_username.as_deref(),
            input.telegram_username.as_deref(),
            input.signal_username.as_deref(),
            input.deactivated_at,
            &input.encrypted_key_bytes,
            input.encryption_version,
            AccountType::Personal,
            true,
            is_admin,
        );

        self.write_new_account(&user_value, &input.commit_cid, &input.repo_rev)
    }

    pub fn create_delegated_account(
        &self,
        input: &CreateDelegatedAccountInput,
    ) -> Result<Uuid, CreateAccountError> {
        self.check_availability(&input.did, &input.handle, input.email.as_deref())?;

        let user_value = self.build_user_value(
            &input.did,
            &input.handle,
            input.email.as_deref(),
            None,
            CommsChannel::Email,
            None,
            None,
            None,
            None,
            &input.encrypted_key_bytes,
            input.encryption_version,
            AccountType::Delegated,
            false,
            false,
        );

        let result = self.write_new_account(&user_value, &input.commit_cid, &input.repo_rev)?;
        Ok(result.user_id)
    }

    pub fn create_passkey_account(
        &self,
        input: &CreatePasskeyAccountInput,
    ) -> Result<CreatePasswordAccountResult, CreateAccountError> {
        self.check_availability(&input.did, &input.handle, Some(&input.email))?;

        let is_admin = self
            .is_first_account()
            .map_err(|e| CreateAccountError::Database(e.to_string()))?;

        let user_value = self.build_user_value(
            &input.did,
            &input.handle,
            Some(&input.email),
            None,
            input.preferred_comms_channel,
            input.discord_username.as_deref(),
            input.telegram_username.as_deref(),
            input.signal_username.as_deref(),
            input.deactivated_at,
            &input.encrypted_key_bytes,
            input.encryption_version,
            AccountType::Personal,
            false,
            is_admin,
        );

        let result = self.write_new_account(&user_value, &input.commit_cid, &input.repo_rev)?;

        let user_hash = UserHash::from_did(input.did.as_str());
        let recovery = RecoveryTokenValue {
            token_hash: input.setup_token_hash.clone(),
            expires_at_ms: input.setup_expires_at.timestamp_millis(),
        };
        self.users
            .insert(
                recovery_token_key(user_hash).as_slice(),
                recovery.serialize(),
            )
            .map_err(|e| CreateAccountError::Database(e.to_string()))?;

        Ok(result)
    }

    pub fn create_sso_account(
        &self,
        input: &CreateSsoAccountInput,
    ) -> Result<CreatePasswordAccountResult, CreateAccountError> {
        self.check_availability(&input.did, &input.handle, input.email.as_deref())?;

        let is_admin = self
            .is_first_account()
            .map_err(|e| CreateAccountError::Database(e.to_string()))?;

        let user_value = self.build_user_value(
            &input.did,
            &input.handle,
            input.email.as_deref(),
            None,
            input.preferred_comms_channel,
            input.discord_username.as_deref(),
            input.telegram_username.as_deref(),
            input.signal_username.as_deref(),
            None,
            &input.encrypted_key_bytes,
            input.encryption_version,
            AccountType::Personal,
            false,
            is_admin,
        );

        self.write_new_account(&user_value, &input.commit_cid, &input.repo_rev)
    }

    pub fn reactivate_migration_account(
        &self,
        input: &MigrationReactivationInput,
    ) -> Result<ReactivatedAccountInfo, MigrationReactivationError> {
        let user_hash = UserHash::from_did(input.did.as_str());
        let user = self
            .load_user(user_hash)
            .map_err(|e| MigrationReactivationError::Database(e.to_string()))?
            .ok_or(MigrationReactivationError::NotFound)?;

        if user.deactivated_at_ms.is_none() {
            return Err(MigrationReactivationError::NotDeactivated);
        }

        let existing_handle = self
            .load_by_handle(input.new_handle.as_str())
            .map_err(|e| MigrationReactivationError::Database(e.to_string()))?;
        match existing_handle {
            Some(other) if other.id != user.id => {
                return Err(MigrationReactivationError::HandleTaken);
            }
            _ => {}
        }

        let old_handle = Handle::new(user.handle.clone())
            .map_err(|_| MigrationReactivationError::Database("invalid handle".to_owned()))?;
        let user_id = user.id;

        let mut batch = self.db.batch();

        batch.remove(&self.users, user_by_handle_key(&user.handle).as_slice());
        batch.insert(
            &self.users,
            user_by_handle_key(input.new_handle.as_str()).as_slice(),
            user_hash.raw().to_be_bytes(),
        );

        if let Some(old_email) = &user.email {
            batch.remove(&self.users, user_by_email_key(old_email).as_slice());
        }
        if let Some(new_email) = &input.new_email {
            batch.insert(
                &self.users,
                user_by_email_key(new_email).as_slice(),
                user_hash.raw().to_be_bytes(),
            );
        }

        let mut updated = user;
        updated.handle = input.new_handle.as_str().to_owned();
        updated.email = input.new_email.clone();
        updated.email_verified = false;
        updated.deactivated_at_ms = None;
        updated.delete_after_ms = None;
        updated.migrated_to_pds = None;
        updated.migrated_at_ms = None;

        batch.insert(
            &self.users,
            user_primary_key(user_hash).as_slice(),
            updated.serialize(),
        );

        batch
            .commit()
            .map_err(|e| MigrationReactivationError::Database(e.to_string()))?;

        Ok(ReactivatedAccountInfo {
            user_id,
            old_handle,
        })
    }

    pub fn check_handle_available_for_new_account(
        &self,
        handle: &Handle,
    ) -> Result<bool, MetastoreError> {
        let existing = self.load_by_handle(handle.as_str())?;
        let reserved_key = handle_reservation_key(handle.as_str());
        let reservation = self
            .auth
            .get(reserved_key.as_slice())
            .map_err(MetastoreError::Fjall)?;

        match (existing, reservation) {
            (None, None) => Ok(true),
            _ => Ok(false),
        }
    }

    pub fn reserve_handle(
        &self,
        handle: &Handle,
        reserved_by: &str,
    ) -> Result<bool, MetastoreError> {
        let available = self.check_handle_available_for_new_account(handle)?;
        match available {
            false => Ok(false),
            true => {
                let now_ms = Utc::now().timestamp_millis();
                let expires_at_ms = now_ms.saturating_add(600_000);
                let value = HandleReservationValue {
                    reserved_by: reserved_by.to_owned(),
                    created_at_ms: now_ms,
                    expires_at_ms,
                };
                let key = handle_reservation_key(handle.as_str());
                self.auth
                    .insert(key.as_slice(), value.serialize_with_ttl())
                    .map_err(MetastoreError::Fjall)?;
                Ok(true)
            }
        }
    }

    pub fn release_handle_reservation(&self, handle: &Handle) -> Result<(), MetastoreError> {
        let key = handle_reservation_key(handle.as_str());
        self.auth
            .remove(key.as_slice())
            .map_err(MetastoreError::Fjall)
    }

    pub fn cleanup_expired_handle_reservations(&self) -> Result<u64, MetastoreError> {
        let prefix = handle_reservation_prefix();
        let now_ms = Utc::now().timestamp_millis();

        let expired_keys: Vec<Vec<u8>> = self
            .auth
            .prefix(prefix.as_slice())
            .filter_map(|guard| {
                let (key_bytes, val_bytes) = guard.into_inner().ok()?;
                let val = HandleReservationValue::deserialize(&val_bytes)?;
                match val.expires_at_ms <= now_ms {
                    true => Some(key_bytes.to_vec()),
                    false => None,
                }
            })
            .collect();

        let count = u64::try_from(expired_keys.len()).unwrap_or(u64::MAX);
        match count {
            0 => Ok(0),
            _ => {
                let mut batch = self.db.batch();
                expired_keys.iter().for_each(|key| {
                    batch.remove(&self.auth, key);
                });
                batch.commit().map_err(MetastoreError::Fjall)?;
                Ok(count)
            }
        }
    }

    pub fn complete_passkey_setup(
        &self,
        input: &CompletePasskeySetupInput,
    ) -> Result<(), MetastoreError> {
        let user_hash = self.resolve_hash(input.did.as_str());

        self.mutate_user(user_hash, |u| {
            u.password_hash = Some(input.app_password_hash.clone());
            u.password_required = false;
        })?;

        Ok(())
    }

    pub fn recover_passkey_account(
        &self,
        input: &RecoverPasskeyAccountInput,
    ) -> Result<RecoverPasskeyAccountResult, MetastoreError> {
        let user_hash = self.resolve_hash(input.did.as_str());

        let passkeys: Vec<(Vec<u8>, PasskeyValue)> = self
            .users
            .prefix(passkey_prefix(user_hash).as_slice())
            .filter_map(|guard| {
                let (key_bytes, val_bytes) = guard.into_inner().ok()?;
                let pv = PasskeyValue::deserialize(&val_bytes)?;
                Some((key_bytes.to_vec(), pv))
            })
            .collect();

        let passkeys_deleted = u64::try_from(passkeys.len()).unwrap_or(u64::MAX);

        let mut batch = self.db.batch();

        passkeys.iter().for_each(|(key, pv)| {
            batch.remove(&self.users, key);
            batch.remove(
                &self.users,
                passkey_by_cred_key(&pv.credential_id).as_slice(),
            );
        });

        batch.remove(&self.users, recovery_token_key(user_hash).as_slice());

        if let Some(mut user) = self.load_user(user_hash)? {
            user.password_hash = Some(input.password_hash.clone());
            user.password_required = true;
            batch.insert(
                &self.users,
                user_primary_key(user_hash).as_slice(),
                user.serialize(),
            );
        }

        batch.commit().map_err(MetastoreError::Fjall)?;

        Ok(RecoverPasskeyAccountResult { passkeys_deleted })
    }

    pub fn get_password_reset_info(
        &self,
        email: &str,
    ) -> Result<Option<tranquil_db_traits::PasswordResetInfo>, MetastoreError> {
        let by_email_key = user_by_email_key(email);
        let user_hash = match self
            .users
            .get(by_email_key.as_slice())
            .map_err(MetastoreError::Fjall)?
        {
            Some(raw) => {
                let arr: [u8; 8] = raw
                    .as_ref()
                    .try_into()
                    .map_err(|_| MetastoreError::CorruptData("email index not 8 bytes"))?;
                UserHash::from_raw(u64::from_be_bytes(arr))
            }
            None => return Ok(None),
        };

        let user = match self.load_user(user_hash)? {
            Some(u) => u,
            None => return Ok(None),
        };

        let prefix = [super::keys::KeyTag::USER_RESET_CODE.raw()];
        let reset_code = self
            .auth
            .prefix(prefix)
            .filter_map(|guard| {
                let (_, val_bytes) = guard.into_inner().ok()?;
                let rc = ResetCodeValue::deserialize(&val_bytes)?;
                match rc.user_id == user.id {
                    true => Some(rc),
                    false => None,
                }
            })
            .next();

        Ok(Some(tranquil_db_traits::PasswordResetInfo {
            code: reset_code.as_ref().map(|rc| rc.code.clone()),
            expires_at: reset_code.and_then(|rc| DateTime::from_timestamp_millis(rc.expires_at_ms)),
        }))
    }

    pub fn enable_totp_verified(
        &self,
        did: &Did,
        encrypted_secret: &[u8],
    ) -> Result<(), MetastoreError> {
        let user_hash = self.resolve_hash(did.as_str());
        let key = totp_key(user_hash);

        let value = TotpValue {
            secret_encrypted: encrypted_secret.to_vec(),
            encryption_version: 1,
            verified: true,
            last_used_at_ms: None,
        };

        let mut batch = self.db.batch();
        batch.insert(&self.users, key.as_slice(), value.serialize());

        if let Some(mut user) = self.load_user(user_hash)? {
            user.totp_enabled = true;
            batch.insert(
                &self.users,
                user_primary_key(user_hash).as_slice(),
                user.serialize(),
            );
        }

        batch.commit().map_err(MetastoreError::Fjall)
    }

    pub fn set_two_factor_enabled(&self, did: &Did, enabled: bool) -> Result<(), MetastoreError> {
        let user_hash = self.resolve_hash(did.as_str());
        let mut user = self
            .load_user(user_hash)?
            .ok_or(MetastoreError::InvalidInput("user not found"))?;

        user.two_factor_enabled = enabled;
        self.users
            .insert(user_primary_key(user_hash).as_slice(), user.serialize())
            .map_err(MetastoreError::Fjall)
    }

    pub fn expire_password_reset_code(&self, email: &str) -> Result<(), MetastoreError> {
        let by_email_key = user_by_email_key(email);
        let user_hash_bytes = match self
            .users
            .get(by_email_key.as_slice())
            .map_err(MetastoreError::Fjall)?
        {
            Some(raw) => raw,
            None => return Ok(()),
        };

        let arr: [u8; 8] = user_hash_bytes
            .as_ref()
            .try_into()
            .map_err(|_| MetastoreError::CorruptData("email index not 8 bytes"))?;
        let user_hash = UserHash::from_raw(u64::from_be_bytes(arr));
        let user = match self.load_user(user_hash)? {
            Some(u) => u,
            None => return Ok(()),
        };

        let past_ms = Utc::now()
            .checked_sub_signed(chrono::Duration::hours(1))
            .unwrap_or_else(Utc::now)
            .timestamp_millis();

        let prefix = [super::keys::KeyTag::USER_RESET_CODE.raw()];
        let entries: Vec<(Vec<u8>, ResetCodeValue)> = self
            .auth
            .prefix(prefix)
            .filter_map(|guard| {
                let (key_bytes, val_bytes) = guard.into_inner().ok()?;
                let rc = ResetCodeValue::deserialize(&val_bytes)?;
                match rc.user_id == user.id {
                    true => Some((key_bytes.to_vec(), rc)),
                    false => None,
                }
            })
            .collect();

        match entries.is_empty() {
            true => Ok(()),
            false => {
                let mut batch = self.db.batch();
                entries.into_iter().for_each(|(key, mut rc)| {
                    rc.expires_at_ms = past_ms;
                    batch.insert(&self.auth, &key, rc.serialize_with_ttl());
                });
                batch.commit().map_err(MetastoreError::Fjall)
            }
        }
    }
}
