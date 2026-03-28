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
use std::sync::Arc;

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
