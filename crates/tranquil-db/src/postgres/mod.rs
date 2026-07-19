mod backlink;
mod blob;
mod delegation;
mod event_notifier;
mod infra;
mod oauth;
mod repo;
mod session;
mod sso;
mod user;

use sqlx::PgPool;
use std::str::FromStr;
use std::sync::Arc;
use tranquil_db_traits::{ColumnRef, DbError};

pub(crate) mod col {
    use tranquil_db_traits::ColumnRef;

    pub const ACCOUNT_DELEGATIONS_CONTROLLER_DID: ColumnRef =
        ColumnRef::new("account_delegations", "controller_did");
    pub const ACCOUNT_DELEGATIONS_DELEGATED_DID: ColumnRef =
        ColumnRef::new("account_delegations", "delegated_did");
    pub const ACCOUNT_DELEGATIONS_GRANTED_BY: ColumnRef =
        ColumnRef::new("account_delegations", "granted_by");
    pub const ACCOUNT_DELEGATIONS_REVOKED_BY: ColumnRef =
        ColumnRef::new("account_delegations", "revoked_by");
    pub const ACCOUNT_DELETION_REQUESTS_DID: ColumnRef =
        ColumnRef::new("account_deletion_requests", "did");
    pub const APP_PASSWORDS_CREATED_BY_CONTROLLER_DID: ColumnRef =
        ColumnRef::new("app_passwords", "created_by_controller_did");
    pub const BACKLINKS_URI: ColumnRef = ColumnRef::new("backlinks", "uri");
    pub const BLOBS_CID: ColumnRef = ColumnRef::new("blobs", "cid");
    pub const DELEGATION_AUDIT_LOG_ACTOR_DID: ColumnRef =
        ColumnRef::new("delegation_audit_log", "actor_did");
    pub const DELEGATION_AUDIT_LOG_CONTROLLER_DID: ColumnRef =
        ColumnRef::new("delegation_audit_log", "controller_did");
    pub const DELEGATION_AUDIT_LOG_DELEGATED_DID: ColumnRef =
        ColumnRef::new("delegation_audit_log", "delegated_did");
    pub const INVITE_CODES_FOR_ACCOUNT: ColumnRef = ColumnRef::new("invite_codes", "for_account");
    pub const OAUTH_2FA_CHALLENGE_DID: ColumnRef = ColumnRef::new("oauth_2fa_challenge", "did");
    pub const OAUTH_AUTHORIZATION_REQUEST_CONTROLLER_DID: ColumnRef =
        ColumnRef::new("oauth_authorization_request", "controller_did");
    pub const OAUTH_AUTHORIZATION_REQUEST_DID: ColumnRef =
        ColumnRef::new("oauth_authorization_request", "did");
    pub const OAUTH_TOKEN_CONTROLLER_DID: ColumnRef =
        ColumnRef::new("oauth_token", "controller_did");
    pub const OAUTH_TOKEN_DID: ColumnRef = ColumnRef::new("oauth_token", "did");
    pub const PASSKEYS_DID: ColumnRef = ColumnRef::new("passkeys", "did");
    pub const RECORD_BLOBS_BLOB_CID: ColumnRef = ColumnRef::new("record_blobs", "blob_cid");
    pub const RECORD_BLOBS_RECORD_URI: ColumnRef = ColumnRef::new("record_blobs", "record_uri");
    pub const RECORDS_COLLECTION: ColumnRef = ColumnRef::new("records", "collection");
    pub const RECORDS_RECORD_CID: ColumnRef = ColumnRef::new("records", "record_cid");
    pub const RECORDS_RKEY: ColumnRef = ColumnRef::new("records", "rkey");
    pub const REPO_SEQ_BLOBS: ColumnRef = ColumnRef::new("repo_seq", "blobs");
    pub const REPO_SEQ_BLOCKS_CIDS: ColumnRef = ColumnRef::new("repo_seq", "blocks_cids");
    pub const REPO_SEQ_COMMIT_CID: ColumnRef = ColumnRef::new("repo_seq", "commit_cid");
    pub const REPO_SEQ_DID: ColumnRef = ColumnRef::new("repo_seq", "did");
    pub const REPO_SEQ_HANDLE: ColumnRef = ColumnRef::new("repo_seq", "handle");
    pub const REPO_SEQ_PREV_CID: ColumnRef = ColumnRef::new("repo_seq", "prev_cid");
    pub const REPO_SEQ_PREV_DATA_CID: ColumnRef = ColumnRef::new("repo_seq", "prev_data_cid");
    pub const REPO_SEQ_REV: ColumnRef = ColumnRef::new("repo_seq", "rev");
    pub const REPOS_REPO_REV: ColumnRef = ColumnRef::new("repos", "repo_rev");
    pub const REPOS_REPO_ROOT_CID: ColumnRef = ColumnRef::new("repos", "repo_root_cid");
    pub const RESERVED_SIGNING_KEYS_DID: ColumnRef = ColumnRef::new("reserved_signing_keys", "did");
    pub const RESERVED_SIGNING_KEYS_PUBLIC_KEY_DID_KEY: ColumnRef =
        ColumnRef::new("reserved_signing_keys", "public_key_did_key");
    pub const SESSION_TOKENS_CONTROLLER_DID: ColumnRef =
        ColumnRef::new("session_tokens", "controller_did");
    pub const SESSION_TOKENS_DID: ColumnRef = ColumnRef::new("session_tokens", "did");
    pub const USERS_DID: ColumnRef = ColumnRef::new("users", "did");
    pub const USERS_HANDLE: ColumnRef = ColumnRef::new("users", "handle");
}

pub(crate) fn column<T: FromStr>(value: String, name: ColumnRef) -> Result<T, DbError> {
    T::from_str(&value).map_err(|_| {
        tracing::error!(
            column = %name,
            value = %value,
            "column has a value that isn't valid for its type"
        );
        DbError::InvalidColumn(name)
    })
}

pub(crate) fn opt_column<T: FromStr>(
    value: Option<String>,
    name: ColumnRef,
) -> Result<Option<T>, DbError> {
    value.map(|v| column(v, name)).transpose()
}

pub(crate) fn legacy_column<T: FromStr>(value: String, name: ColumnRef) -> Option<T> {
    match T::from_str(&value) {
        Ok(v) => Some(v),
        Err(_) => {
            tracing::warn!(
                column = %name,
                value = %value,
                "ignoring a column value that isn't valid for its type"
            );
            None
        }
    }
}

pub(crate) fn column_vec<T: FromStr>(
    values: Vec<String>,
    name: ColumnRef,
) -> Result<Vec<T>, DbError> {
    values.into_iter().map(|v| column(v, name)).collect()
}

pub use backlink::PostgresBacklinkRepository;
pub use blob::PostgresBlobRepository;
pub use delegation::PostgresDelegationRepository;
pub use event_notifier::PostgresRepoEventNotifier;
pub use infra::PostgresInfraRepository;
pub use oauth::PostgresOAuthRepository;
pub use repo::PostgresRepoRepository;
pub use session::PostgresSessionRepository;
pub use sso::PostgresSsoRepository;
use tranquil_db_traits::{
    BacklinkRepository, BlobRepository, DelegationRepository, InfraRepository, OAuthRepository,
    RepoEventNotifier, RepoRepository, SessionRepository, SsoRepository, UserRepository,
};
pub use user::PostgresUserRepository;

pub struct PostgresRepositories {
    pub pool: Option<PgPool>,
    pub user: Arc<dyn UserRepository>,
    pub oauth: Arc<dyn OAuthRepository>,
    pub session: Arc<dyn SessionRepository>,
    pub delegation: Arc<dyn DelegationRepository>,
    pub repo: Arc<dyn RepoRepository>,
    pub blob: Arc<dyn BlobRepository>,
    pub infra: Arc<dyn InfraRepository>,
    pub backlink: Arc<dyn BacklinkRepository>,
    pub sso: Arc<dyn SsoRepository>,
    pub event_notifier: Arc<dyn RepoEventNotifier>,
}

impl PostgresRepositories {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool: Some(pool.clone()),
            user: Arc::new(PostgresUserRepository::new(pool.clone())),
            oauth: Arc::new(PostgresOAuthRepository::new(pool.clone())),
            session: Arc::new(PostgresSessionRepository::new(pool.clone())),
            delegation: Arc::new(PostgresDelegationRepository::new(pool.clone())),
            repo: Arc::new(PostgresRepoRepository::new(pool.clone())),
            blob: Arc::new(PostgresBlobRepository::new(pool.clone())),
            infra: Arc::new(PostgresInfraRepository::new(pool.clone())),
            backlink: Arc::new(PostgresBacklinkRepository::new(pool.clone())),
            sso: Arc::new(PostgresSsoRepository::new(pool.clone())),
            event_notifier: Arc::new(PostgresRepoEventNotifier::new(pool)),
        }
    }
}
