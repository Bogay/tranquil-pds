use async_trait::async_trait;
use chrono::{DateTime, Utc};
use tranquil_types::{Did, Handle};
use uuid::Uuid;

use crate::{CommsChannel, DbError};

#[derive(Debug, Clone)]
pub struct UserRow {
    pub id: Uuid,
    pub did: Did,
    pub handle: Handle,
    pub email: Option<String>,
    pub created_at: DateTime<Utc>,
    pub deactivated_at: Option<DateTime<Utc>>,
    pub takedown_ref: Option<String>,
    pub is_admin: bool,
}

#[derive(Debug, Clone)]
pub struct UserWithKey {
    pub id: Uuid,
    pub did: Did,
    pub handle: Handle,
    pub email: Option<String>,
    pub deactivated_at: Option<DateTime<Utc>>,
    pub takedown_ref: Option<String>,
    pub is_admin: bool,
    pub key_bytes: Vec<u8>,
    pub encryption_version: Option<i32>,
}

#[derive(Debug, Clone)]
pub struct UserStatus {
    pub deactivated_at: Option<DateTime<Utc>>,
    pub takedown_ref: Option<String>,
    pub is_admin: bool,
}

#[derive(Debug, Clone)]
pub struct UserEmailInfo {
    pub id: Uuid,
    pub handle: Handle,
    pub email: Option<String>,
    pub email_verified: bool,
}

#[derive(Debug, Clone)]
pub struct UserLoginCheck {
    pub did: Did,
    pub password_hash: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UserLoginInfo {
    pub id: Uuid,
    pub did: Did,
    pub email: Option<String>,
    pub password_hash: Option<String>,
    pub password_required: bool,
    pub two_factor_enabled: bool,
    pub preferred_comms_channel: CommsChannel,
    pub deactivated_at: Option<DateTime<Utc>>,
    pub takedown_ref: Option<String>,
    pub email_verified: bool,
    pub discord_verified: bool,
    pub telegram_verified: bool,
    pub signal_verified: bool,
    pub account_type: String,
}

#[derive(Debug, Clone)]
pub struct User2faStatus {
    pub id: Uuid,
    pub two_factor_enabled: bool,
    pub preferred_comms_channel: CommsChannel,
    pub email_verified: bool,
    pub discord_verified: bool,
    pub telegram_verified: bool,
    pub signal_verified: bool,
}

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn get_by_did(&self, did: &Did) -> Result<Option<UserRow>, DbError>;

    async fn get_by_handle(&self, handle: &Handle) -> Result<Option<UserRow>, DbError>;

    async fn get_with_key_by_did(&self, did: &Did) -> Result<Option<UserWithKey>, DbError>;

    async fn get_status_by_did(&self, did: &Did) -> Result<Option<UserStatus>, DbError>;

    async fn count_users(&self) -> Result<i64, DbError>;

    async fn get_session_access_expiry(
        &self,
        did: &Did,
        access_jti: &str,
    ) -> Result<Option<DateTime<Utc>>, DbError>;

    async fn get_oauth_token_with_user(
        &self,
        token_id: &str,
    ) -> Result<Option<OAuthTokenWithUser>, DbError>;

    async fn get_user_info_by_did(&self, did: &Did) -> Result<Option<UserInfoForAuth>, DbError>;

    async fn get_any_admin_user_id(&self) -> Result<Option<Uuid>, DbError>;

    async fn set_invites_disabled(&self, did: &Did, disabled: bool) -> Result<bool, DbError>;

    async fn search_accounts(
        &self,
        cursor_did: Option<&Did>,
        email_filter: Option<&str>,
        handle_filter: Option<&str>,
        limit: i64,
    ) -> Result<Vec<AccountSearchResult>, DbError>;

    async fn get_auth_info_by_did(&self, did: &Did) -> Result<Option<UserAuthInfo>, DbError>;

    async fn get_by_email(&self, email: &str) -> Result<Option<UserForVerification>, DbError>;

    async fn get_login_check_by_handle_or_email(
        &self,
        identifier: &str,
    ) -> Result<Option<UserLoginCheck>, DbError>;

    async fn get_login_info_by_handle_or_email(
        &self,
        identifier: &str,
    ) -> Result<Option<UserLoginInfo>, DbError>;

    async fn get_2fa_status_by_did(&self, did: &Did) -> Result<Option<User2faStatus>, DbError>;

    async fn get_comms_prefs(&self, user_id: Uuid) -> Result<Option<UserCommsPrefs>, DbError>;

    async fn get_id_by_did(&self, did: &Did) -> Result<Option<Uuid>, DbError>;

    async fn get_user_key_by_id(&self, user_id: Uuid) -> Result<Option<UserKeyInfo>, DbError>;

    async fn get_id_and_handle_by_did(&self, did: &Did) -> Result<Option<UserIdAndHandle>, DbError>;

    async fn get_did_web_info_by_handle(
        &self,
        handle: &Handle,
    ) -> Result<Option<UserDidWebInfo>, DbError>;

    async fn get_did_web_overrides(&self, user_id: Uuid) -> Result<Option<DidWebOverrides>, DbError>;

    async fn get_handle_by_did(&self, did: &Did) -> Result<Option<Handle>, DbError>;

    async fn is_account_active_by_did(&self, did: &Did) -> Result<Option<bool>, DbError>;

    async fn get_user_for_deletion(
        &self,
        did: &Did,
    ) -> Result<Option<UserForDeletion>, DbError>;

    async fn check_handle_exists(&self, handle: &Handle, exclude_user_id: Uuid) -> Result<bool, DbError>;

    async fn update_handle(&self, user_id: Uuid, handle: &Handle) -> Result<(), DbError>;

    async fn get_user_with_key_by_did(
        &self,
        did: &Did,
    ) -> Result<Option<UserKeyWithId>, DbError>;

    async fn is_account_migrated(&self, did: &Did) -> Result<bool, DbError>;

    async fn has_verified_comms_channel(&self, did: &Did) -> Result<bool, DbError>;

    async fn get_id_by_handle(&self, handle: &Handle) -> Result<Option<Uuid>, DbError>;

    async fn get_email_info_by_did(&self, did: &Did) -> Result<Option<UserEmailInfo>, DbError>;

    async fn check_email_exists(&self, email: &str, exclude_user_id: Uuid) -> Result<bool, DbError>;

    async fn update_email(&self, user_id: Uuid, email: &str) -> Result<(), DbError>;

    async fn set_email_verified(&self, user_id: Uuid, verified: bool) -> Result<(), DbError>;

    async fn check_email_verified_by_identifier(
        &self,
        identifier: &str,
    ) -> Result<Option<bool>, DbError>;

    async fn admin_update_email(&self, did: &Did, email: &str) -> Result<u64, DbError>;

    async fn admin_update_handle(&self, did: &Did, handle: &Handle) -> Result<u64, DbError>;

    async fn admin_update_password(&self, did: &Did, password_hash: &str) -> Result<u64, DbError>;

    async fn get_notification_prefs(&self, did: &Did) -> Result<Option<NotificationPrefs>, DbError>;

    async fn get_id_handle_email_by_did(
        &self,
        did: &Did,
    ) -> Result<Option<UserIdHandleEmail>, DbError>;

    async fn update_preferred_comms_channel(&self, did: &Did, channel: &str) -> Result<(), DbError>;

    async fn clear_discord(&self, user_id: Uuid) -> Result<(), DbError>;

    async fn clear_telegram(&self, user_id: Uuid) -> Result<(), DbError>;

    async fn clear_signal(&self, user_id: Uuid) -> Result<(), DbError>;

    async fn get_verification_info(
        &self,
        did: &Did,
    ) -> Result<Option<UserVerificationInfo>, DbError>;

    async fn verify_email_channel(&self, user_id: Uuid, email: &str) -> Result<bool, DbError>;

    async fn verify_discord_channel(&self, user_id: Uuid, discord_id: &str) -> Result<(), DbError>;

    async fn verify_telegram_channel(
        &self,
        user_id: Uuid,
        telegram_username: &str,
    ) -> Result<(), DbError>;

    async fn verify_signal_channel(&self, user_id: Uuid, signal_number: &str)
        -> Result<(), DbError>;

    async fn set_email_verified_flag(&self, user_id: Uuid) -> Result<(), DbError>;

    async fn set_discord_verified_flag(&self, user_id: Uuid) -> Result<(), DbError>;

    async fn set_telegram_verified_flag(&self, user_id: Uuid) -> Result<(), DbError>;

    async fn set_signal_verified_flag(&self, user_id: Uuid) -> Result<(), DbError>;

    async fn has_totp_enabled(&self, did: &Did) -> Result<bool, DbError>;

    async fn has_passkeys(&self, did: &Did) -> Result<bool, DbError>;

    async fn get_password_hash_by_did(&self, did: &Did) -> Result<Option<String>, DbError>;

    async fn get_passkeys_for_user(&self, did: &Did) -> Result<Vec<StoredPasskey>, DbError>;

    async fn get_passkey_by_credential_id(
        &self,
        credential_id: &[u8],
    ) -> Result<Option<StoredPasskey>, DbError>;

    async fn save_passkey(
        &self,
        did: &Did,
        credential_id: &[u8],
        public_key: &[u8],
        friendly_name: Option<&str>,
    ) -> Result<Uuid, DbError>;

    async fn update_passkey_counter(
        &self,
        credential_id: &[u8],
        new_counter: i32,
    ) -> Result<bool, DbError>;

    async fn delete_passkey(&self, id: Uuid, did: &Did) -> Result<bool, DbError>;

    async fn update_passkey_name(&self, id: Uuid, did: &Did, name: &str) -> Result<bool, DbError>;

    async fn save_webauthn_challenge(
        &self,
        did: &Did,
        challenge_type: &str,
        state_json: &str,
    ) -> Result<Uuid, DbError>;

    async fn load_webauthn_challenge(
        &self,
        did: &Did,
        challenge_type: &str,
    ) -> Result<Option<String>, DbError>;

    async fn delete_webauthn_challenge(&self, did: &Did, challenge_type: &str)
        -> Result<(), DbError>;

    async fn get_totp_record(&self, did: &Did) -> Result<Option<TotpRecord>, DbError>;

    async fn upsert_totp_secret(
        &self,
        did: &Did,
        secret_encrypted: &[u8],
        encryption_version: i32,
    ) -> Result<(), DbError>;

    async fn set_totp_verified(&self, did: &Did) -> Result<(), DbError>;

    async fn update_totp_last_used(&self, did: &Did) -> Result<(), DbError>;

    async fn delete_totp(&self, did: &Did) -> Result<(), DbError>;

    async fn get_unused_backup_codes(&self, did: &Did) -> Result<Vec<StoredBackupCode>, DbError>;

    async fn mark_backup_code_used(&self, code_id: Uuid) -> Result<bool, DbError>;

    async fn count_unused_backup_codes(&self, did: &Did) -> Result<i64, DbError>;

    async fn delete_backup_codes(&self, did: &Did) -> Result<u64, DbError>;

    async fn insert_backup_codes(&self, did: &Did, code_hashes: &[String]) -> Result<(), DbError>;

    async fn enable_totp_with_backup_codes(
        &self,
        did: &Did,
        code_hashes: &[String],
    ) -> Result<(), DbError>;

    async fn delete_totp_and_backup_codes(&self, did: &Did) -> Result<(), DbError>;

    async fn replace_backup_codes(&self, did: &Did, code_hashes: &[String]) -> Result<(), DbError>;

    async fn get_session_info_by_did(&self, did: &Did) -> Result<Option<UserSessionInfo>, DbError>;

    async fn get_legacy_login_pref(&self, did: &Did) -> Result<Option<UserLegacyLoginPref>, DbError>;

    async fn update_legacy_login(&self, did: &Did, allow: bool) -> Result<bool, DbError>;

    async fn update_locale(&self, did: &Did, locale: &str) -> Result<bool, DbError>;

    async fn get_login_full_by_identifier(
        &self,
        identifier: &str,
    ) -> Result<Option<UserLoginFull>, DbError>;

    async fn get_confirm_signup_by_did(
        &self,
        did: &Did,
    ) -> Result<Option<UserConfirmSignup>, DbError>;

    async fn get_resend_verification_by_did(
        &self,
        did: &Did,
    ) -> Result<Option<UserResendVerification>, DbError>;

    async fn set_channel_verified(&self, did: &Did, channel: CommsChannel) -> Result<(), DbError>;

    async fn get_id_by_email_or_handle(
        &self,
        email: &str,
        handle: &str,
    ) -> Result<Option<Uuid>, DbError>;

    async fn set_password_reset_code(
        &self,
        user_id: Uuid,
        code: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), DbError>;

    async fn get_user_by_reset_code(
        &self,
        code: &str,
    ) -> Result<Option<UserResetCodeInfo>, DbError>;

    async fn clear_password_reset_code(&self, user_id: Uuid) -> Result<(), DbError>;

    async fn get_id_and_password_hash_by_did(
        &self,
        did: &Did,
    ) -> Result<Option<UserIdAndPasswordHash>, DbError>;

    async fn update_password_hash(&self, user_id: Uuid, password_hash: &str) -> Result<(), DbError>;

    async fn reset_password_with_sessions(
        &self,
        user_id: Uuid,
        password_hash: &str,
    ) -> Result<PasswordResetResult, DbError>;

    async fn activate_account(&self, did: &Did) -> Result<bool, DbError>;

    async fn deactivate_account(
        &self,
        did: &Did,
        delete_after: Option<DateTime<Utc>>,
    ) -> Result<bool, DbError>;

    async fn has_password_by_did(&self, did: &Did) -> Result<Option<bool>, DbError>;

    async fn get_password_info_by_did(
        &self,
        did: &Did,
    ) -> Result<Option<UserPasswordInfo>, DbError>;

    async fn remove_user_password(&self, user_id: Uuid) -> Result<(), DbError>;

    async fn set_new_user_password(&self, user_id: Uuid, password_hash: &str) -> Result<(), DbError>;

    async fn get_user_key_by_did(&self, did: &Did) -> Result<Option<UserKeyInfo>, DbError>;

    async fn delete_account_complete(
        &self,
        user_id: Uuid,
        did: &Did,
    ) -> Result<(), DbError>;

    async fn set_user_takedown(&self, did: &Did, takedown_ref: Option<&str>) -> Result<bool, DbError>;

    async fn admin_delete_account_complete(&self, user_id: Uuid, did: &Did) -> Result<(), DbError>;

    async fn get_user_for_did_doc(&self, did: &Did) -> Result<Option<UserForDidDoc>, DbError>;

    async fn get_user_for_did_doc_build(&self, did: &Did) -> Result<Option<UserForDidDocBuild>, DbError>;

    async fn upsert_did_web_overrides(
        &self,
        user_id: Uuid,
        verification_methods: Option<serde_json::Value>,
        also_known_as: Option<Vec<String>>,
    ) -> Result<(), DbError>;

    async fn update_migrated_to_pds(
        &self,
        did: &Did,
        endpoint: &str,
    ) -> Result<(), DbError>;

    async fn get_user_for_passkey_setup(&self, did: &Did) -> Result<Option<UserForPasskeySetup>, DbError>;

    async fn get_user_for_passkey_recovery(
        &self,
        identifier: &str,
        normalized_handle: &str,
    ) -> Result<Option<UserForPasskeyRecovery>, DbError>;

    async fn set_recovery_token(
        &self,
        did: &Did,
        token_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), DbError>;

    async fn get_user_for_recovery(&self, did: &Did) -> Result<Option<UserForRecovery>, DbError>;

    async fn get_accounts_scheduled_for_deletion(
        &self,
        limit: i64,
    ) -> Result<Vec<ScheduledDeletionAccount>, DbError>;

    async fn delete_account_with_firehose(
        &self,
        user_id: Uuid,
        did: &Did,
    ) -> Result<i64, DbError>;

    async fn create_password_account(
        &self,
        input: &CreatePasswordAccountInput,
    ) -> Result<CreatePasswordAccountResult, CreateAccountError>;

    async fn create_delegated_account(
        &self,
        input: &CreateDelegatedAccountInput,
    ) -> Result<Uuid, CreateAccountError>;

    async fn create_passkey_account(
        &self,
        input: &CreatePasskeyAccountInput,
    ) -> Result<CreatePasswordAccountResult, CreateAccountError>;

    async fn reactivate_migration_account(
        &self,
        input: &MigrationReactivationInput,
    ) -> Result<ReactivatedAccountInfo, MigrationReactivationError>;

    async fn check_handle_available_for_new_account(&self, handle: &Handle) -> Result<bool, DbError>;

    async fn check_and_consume_invite_code(&self, code: &str) -> Result<bool, DbError>;

    async fn complete_passkey_setup(
        &self,
        input: &CompletePasskeySetupInput,
    ) -> Result<(), DbError>;

    async fn recover_passkey_account(
        &self,
        input: &RecoverPasskeyAccountInput,
    ) -> Result<RecoverPasskeyAccountResult, DbError>;
}

#[derive(Debug, Clone)]
pub struct UserKeyWithId {
    pub id: Uuid,
    pub key_bytes: Vec<u8>,
    pub encryption_version: Option<i32>,
}

#[derive(Debug, Clone)]
pub struct UserKeyInfo {
    pub key_bytes: Vec<u8>,
    pub encryption_version: Option<i32>,
}

#[derive(Debug, Clone)]
pub struct UserIdAndHandle {
    pub id: Uuid,
    pub handle: Handle,
}

#[derive(Debug, Clone)]
pub struct UserDidWebInfo {
    pub id: Uuid,
    pub did: Did,
    pub migrated_to_pds: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DidWebOverrides {
    pub verification_methods: serde_json::Value,
    pub also_known_as: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct UserCommsPrefs {
    pub email: Option<String>,
    pub handle: Handle,
    pub preferred_channel: String,
    pub preferred_locale: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UserForVerification {
    pub id: Uuid,
    pub did: Did,
    pub email: Option<String>,
    pub email_verified: bool,
    pub handle: Handle,
}

#[derive(Debug, Clone)]
pub struct OAuthTokenWithUser {
    pub did: Did,
    pub expires_at: DateTime<Utc>,
    pub deactivated_at: Option<DateTime<Utc>>,
    pub takedown_ref: Option<String>,
    pub is_admin: bool,
    pub key_bytes: Option<Vec<u8>>,
    pub encryption_version: Option<i32>,
}

#[derive(Debug, Clone)]
pub struct UserInfoForAuth {
    pub deactivated_at: Option<DateTime<Utc>>,
    pub takedown_ref: Option<String>,
    pub is_admin: bool,
    pub key_bytes: Option<Vec<u8>>,
    pub encryption_version: Option<i32>,
}

#[derive(Debug, Clone)]
pub struct AccountSearchResult {
    pub did: Did,
    pub handle: Handle,
    pub email: Option<String>,
    pub created_at: DateTime<Utc>,
    pub email_verified: bool,
    pub deactivated_at: Option<DateTime<Utc>>,
    pub invites_disabled: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct UserAuthInfo {
    pub id: Uuid,
    pub did: Did,
    pub password_hash: Option<String>,
    pub deactivated_at: Option<DateTime<Utc>>,
    pub takedown_ref: Option<String>,
    pub email_verified: bool,
    pub discord_verified: bool,
    pub telegram_verified: bool,
    pub signal_verified: bool,
}

#[derive(Debug, Clone)]
pub struct NotificationPrefs {
    pub email: String,
    pub preferred_channel: String,
    pub discord_id: Option<String>,
    pub discord_verified: bool,
    pub telegram_username: Option<String>,
    pub telegram_verified: bool,
    pub signal_number: Option<String>,
    pub signal_verified: bool,
}

#[derive(Debug, Clone)]
pub struct UserIdHandleEmail {
    pub id: Uuid,
    pub handle: Handle,
    pub email: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UserVerificationInfo {
    pub id: Uuid,
    pub handle: Handle,
    pub email: Option<String>,
    pub email_verified: bool,
    pub discord_verified: bool,
    pub telegram_verified: bool,
    pub signal_verified: bool,
}

#[derive(Debug, Clone)]
pub struct StoredPasskey {
    pub id: Uuid,
    pub did: Did,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub sign_count: i32,
    pub created_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
    pub friendly_name: Option<String>,
    pub aaguid: Option<Vec<u8>>,
    pub transports: Option<Vec<String>>,
}

impl StoredPasskey {
    pub fn credential_id_base64(&self) -> String {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        URL_SAFE_NO_PAD.encode(&self.credential_id)
    }
}

#[derive(Debug, Clone)]
pub struct TotpRecord {
    pub secret_encrypted: Vec<u8>,
    pub encryption_version: i32,
    pub verified: bool,
}

#[derive(Debug, Clone)]
pub struct StoredBackupCode {
    pub id: Uuid,
    pub code_hash: String,
}

#[derive(Debug, Clone)]
pub struct UserSessionInfo {
    pub handle: Handle,
    pub email: Option<String>,
    pub email_verified: bool,
    pub is_admin: bool,
    pub deactivated_at: Option<DateTime<Utc>>,
    pub takedown_ref: Option<String>,
    pub preferred_locale: Option<String>,
    pub preferred_comms_channel: CommsChannel,
    pub discord_verified: bool,
    pub telegram_verified: bool,
    pub signal_verified: bool,
    pub migrated_to_pds: Option<String>,
    pub migrated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct UserLegacyLoginPref {
    pub allow_legacy_login: bool,
    pub has_mfa: bool,
}

#[derive(Debug, Clone)]
pub struct UserLoginFull {
    pub id: Uuid,
    pub did: Did,
    pub handle: Handle,
    pub password_hash: Option<String>,
    pub email: Option<String>,
    pub deactivated_at: Option<DateTime<Utc>>,
    pub takedown_ref: Option<String>,
    pub email_verified: bool,
    pub discord_verified: bool,
    pub telegram_verified: bool,
    pub signal_verified: bool,
    pub allow_legacy_login: bool,
    pub migrated_to_pds: Option<String>,
    pub preferred_comms_channel: CommsChannel,
    pub key_bytes: Vec<u8>,
    pub encryption_version: Option<i32>,
    pub totp_enabled: bool,
}

#[derive(Debug, Clone)]
pub struct UserConfirmSignup {
    pub id: Uuid,
    pub did: Did,
    pub handle: Handle,
    pub email: Option<String>,
    pub channel: CommsChannel,
    pub discord_id: Option<String>,
    pub telegram_username: Option<String>,
    pub signal_number: Option<String>,
    pub key_bytes: Vec<u8>,
    pub encryption_version: Option<i32>,
}

#[derive(Debug, Clone)]
pub struct UserResendVerification {
    pub id: Uuid,
    pub handle: Handle,
    pub email: Option<String>,
    pub channel: CommsChannel,
    pub discord_id: Option<String>,
    pub telegram_username: Option<String>,
    pub signal_number: Option<String>,
    pub email_verified: bool,
    pub discord_verified: bool,
    pub telegram_verified: bool,
    pub signal_verified: bool,
}

#[derive(Debug, Clone)]
pub struct UserResetCodeInfo {
    pub id: Uuid,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct UserPasswordInfo {
    pub id: Uuid,
    pub password_hash: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UserIdAndPasswordHash {
    pub id: Uuid,
    pub password_hash: String,
}

#[derive(Debug, Clone)]
pub struct PasswordResetResult {
    pub did: Did,
    pub session_jtis: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct UserForDeletion {
    pub id: Uuid,
    pub password_hash: Option<String>,
    pub handle: Handle,
}

#[derive(Debug, Clone)]
pub struct ScheduledDeletionAccount {
    pub id: Uuid,
    pub did: Did,
    pub handle: Handle,
}

#[derive(Debug, Clone)]
pub struct UserForDidDoc {
    pub id: Uuid,
    pub handle: Handle,
    pub deactivated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct UserForDidDocBuild {
    pub id: Uuid,
    pub handle: Handle,
    pub migrated_to_pds: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UserForPasskeySetup {
    pub id: Uuid,
    pub handle: Handle,
    pub recovery_token: Option<String>,
    pub recovery_token_expires_at: Option<DateTime<Utc>>,
    pub password_required: bool,
}

#[derive(Debug, Clone)]
pub struct UserForPasskeyRecovery {
    pub id: Uuid,
    pub did: Did,
    pub handle: Handle,
    pub password_required: bool,
}

#[derive(Debug, Clone)]
pub struct UserForRecovery {
    pub id: Uuid,
    pub did: Did,
    pub recovery_token: Option<String>,
    pub recovery_token_expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct CreatePasswordAccountInput {
    pub handle: Handle,
    pub email: Option<String>,
    pub did: Did,
    pub password_hash: String,
    pub preferred_comms_channel: CommsChannel,
    pub discord_id: Option<String>,
    pub telegram_username: Option<String>,
    pub signal_number: Option<String>,
    pub deactivated_at: Option<DateTime<Utc>>,
    pub encrypted_key_bytes: Vec<u8>,
    pub encryption_version: i32,
    pub reserved_key_id: Option<Uuid>,
    pub commit_cid: String,
    pub repo_rev: String,
    pub genesis_block_cids: Vec<Vec<u8>>,
    pub invite_code: Option<String>,
    pub birthdate_pref: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Default)]
pub struct CreatePasswordAccountResult {
    pub user_id: Uuid,
    pub is_admin: bool,
}

#[derive(Debug, Clone)]
pub enum CreateAccountError {
    HandleTaken,
    EmailTaken,
    DidExists,
    Database(String),
}

#[derive(Debug, Clone)]
pub struct CreateDelegatedAccountInput {
    pub handle: Handle,
    pub email: Option<String>,
    pub did: Did,
    pub controller_did: Did,
    pub controller_scopes: String,
    pub encrypted_key_bytes: Vec<u8>,
    pub encryption_version: i32,
    pub commit_cid: String,
    pub repo_rev: String,
    pub genesis_block_cids: Vec<Vec<u8>>,
    pub invite_code: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CreatePasskeyAccountInput {
    pub handle: Handle,
    pub email: String,
    pub did: Did,
    pub preferred_comms_channel: CommsChannel,
    pub discord_id: Option<String>,
    pub telegram_username: Option<String>,
    pub signal_number: Option<String>,
    pub setup_token_hash: String,
    pub setup_expires_at: DateTime<Utc>,
    pub deactivated_at: Option<DateTime<Utc>>,
    pub encrypted_key_bytes: Vec<u8>,
    pub encryption_version: i32,
    pub reserved_key_id: Option<Uuid>,
    pub commit_cid: String,
    pub repo_rev: String,
    pub genesis_block_cids: Vec<Vec<u8>>,
    pub invite_code: Option<String>,
    pub birthdate_pref: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct CompletePasskeySetupInput {
    pub user_id: Uuid,
    pub did: Did,
    pub app_password_name: String,
    pub app_password_hash: String,
}

#[derive(Debug, Clone)]
pub struct RecoverPasskeyAccountInput {
    pub did: Did,
    pub password_hash: String,
}

#[derive(Debug, Clone)]
pub struct RecoverPasskeyAccountResult {
    pub passkeys_deleted: u64,
}

#[derive(Debug, Clone)]
pub struct MigrationReactivationInput {
    pub did: Did,
    pub new_handle: Handle,
}

#[derive(Debug, Clone)]
pub struct ReactivatedAccountInfo {
    pub user_id: Uuid,
    pub old_handle: Handle,
}

#[derive(Debug, Clone)]
pub enum MigrationReactivationError {
    NotFound,
    NotDeactivated,
    HandleTaken,
    Database(String),
}
