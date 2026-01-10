mod token;
mod totp;
mod types;
mod verify;

pub use token::{
    SCOPE_ACCESS, SCOPE_APP_PASS, SCOPE_APP_PASS_PRIVILEGED, SCOPE_REFRESH, TOKEN_TYPE_ACCESS,
    TOKEN_TYPE_REFRESH, TOKEN_TYPE_SERVICE, create_access_token, create_access_token_hs256,
    create_access_token_hs256_with_metadata, create_access_token_with_delegation,
    create_access_token_with_metadata, create_access_token_with_scope_metadata,
    create_refresh_token, create_refresh_token_hs256, create_refresh_token_hs256_with_metadata,
    create_refresh_token_with_metadata, create_service_token, create_service_token_hs256,
};

pub use totp::{
    decrypt_totp_secret, encrypt_totp_secret, generate_backup_codes, generate_qr_png_base64,
    generate_totp_secret, generate_totp_uri, hash_backup_code, is_backup_code_format,
    verify_backup_code, verify_totp_code,
};

pub use types::{
    ActClaim, Claims, Header, TokenData, TokenVerifyError, TokenWithMetadata, UnsafeClaims,
};

pub use verify::{
    get_algorithm_from_token, get_did_from_token, get_jti_from_token, verify_access_token,
    verify_access_token_hs256, verify_access_token_typed, verify_refresh_token,
    verify_refresh_token_hs256, verify_token,
};
