pub mod account_status;
pub mod app_password;
pub mod email;
pub mod invite;
pub mod logo;
pub mod meta;
pub mod migration;
pub mod passkey_account;
pub mod passkeys;
pub mod password;
pub mod reauth;
pub mod service_auth;
pub mod session;
pub mod signing_key;
pub mod totp;
pub mod trusted_devices;
pub mod verify_email;
pub mod verify_token;

pub use account_status::{
    activate_account, check_account_status, deactivate_account, delete_account,
    request_account_delete,
};
pub use app_password::{create_app_password, list_app_passwords, revoke_app_password};
pub use email::{confirm_email, request_email_update, update_email};
pub use invite::{create_invite_code, create_invite_codes, get_account_invite_codes};
pub use logo::get_logo;
pub use meta::{describe_server, health, robots_txt};
pub use migration::{
    clear_migration_forwarding, get_did_document, get_migration_status, update_did_document,
    update_migration_forwarding,
};
pub use passkey_account::{
    complete_passkey_setup, create_passkey_account, recover_passkey_account,
    request_passkey_recovery, start_passkey_registration_for_setup,
};
pub use passkeys::{
    delete_passkey, finish_passkey_registration, has_passkeys_for_user, has_passkeys_for_user_db,
    list_passkeys, start_passkey_registration, update_passkey,
};
pub use password::{
    change_password, get_password_status, remove_password, request_password_reset, reset_password,
};
pub use reauth::{
    check_legacy_session_mfa, check_reauth_required, get_reauth_status,
    legacy_mfa_required_response, reauth_passkey_finish, reauth_passkey_start, reauth_password,
    reauth_required_response, reauth_totp, update_mfa_verified,
};
pub use service_auth::get_service_auth;
pub use session::{
    confirm_signup, create_session, delete_session, get_legacy_login_preference, get_session,
    list_sessions, refresh_session, resend_verification, revoke_all_sessions, revoke_session,
    update_legacy_login_preference, update_locale,
};
pub use signing_key::reserve_signing_key;
pub use totp::{
    create_totp_secret, disable_totp, enable_totp, get_totp_status, has_totp_enabled,
    has_totp_enabled_db, regenerate_backup_codes, verify_totp_or_backup_for_user,
};
pub use trusted_devices::{
    extend_device_trust, is_device_trusted, list_trusted_devices, revoke_trusted_device,
    trust_device, update_trusted_device,
};
pub use verify_email::{resend_migration_verification, verify_migration_email};
pub use verify_token::{VerifyTokenInput, VerifyTokenOutput, verify_token, verify_token_internal};
