mod client;
mod device;
mod dpop;
mod helpers;
mod request;
mod token;
mod two_factor;

pub use client::{get_authorized_client, upsert_authorized_client};
pub use device::{
    DeviceAccountRow, create_device, delete_device, get_device, get_device_accounts,
    update_device_last_seen, upsert_account_device, verify_account_on_device,
};
pub use dpop::{check_and_record_dpop_jti, cleanup_expired_dpop_jtis};
pub use request::{
    consume_authorization_request_by_code, create_authorization_request,
    delete_authorization_request, delete_expired_authorization_requests, get_authorization_request,
    update_authorization_request,
};
pub use token::{
    check_refresh_token_used, count_tokens_for_user, create_token, delete_oldest_tokens_for_user,
    delete_token, delete_token_family, enforce_token_limit_for_user, get_token_by_id,
    get_token_by_refresh_token, list_tokens_for_user, rotate_token,
};
pub use two_factor::{
    TwoFactorChallenge, check_user_2fa_enabled, cleanup_expired_2fa_challenges,
    create_2fa_challenge, delete_2fa_challenge, delete_2fa_challenge_by_request_uri,
    generate_2fa_code, get_2fa_challenge, increment_2fa_attempts,
};
