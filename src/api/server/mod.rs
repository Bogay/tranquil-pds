pub mod account_status;
pub mod app_password;
pub mod email;
pub mod invite;
pub mod meta;
pub mod passkeys;
pub mod password;
pub mod service_auth;
pub mod session;
pub mod signing_key;
pub mod totp;

pub use account_status::{
    activate_account, check_account_status, deactivate_account, delete_account,
    request_account_delete,
};
pub use app_password::{create_app_password, list_app_passwords, revoke_app_password};
pub use email::{confirm_email, request_email_update, update_email};
pub use invite::{create_invite_code, create_invite_codes, get_account_invite_codes};
pub use meta::{describe_server, health, robots_txt};
pub use passkeys::{
    delete_passkey, finish_passkey_registration, has_passkeys_for_user, list_passkeys,
    start_passkey_registration, update_passkey,
};
pub use password::{change_password, request_password_reset, reset_password};
pub use service_auth::get_service_auth;
pub use session::{
    confirm_signup, create_session, delete_session, get_session, list_sessions, refresh_session,
    resend_verification, revoke_session,
};
pub use signing_key::reserve_signing_key;
pub use totp::{
    create_totp_secret, disable_totp, enable_totp, get_totp_status, has_totp_enabled,
    regenerate_backup_codes, verify_totp_or_backup_for_user,
};
