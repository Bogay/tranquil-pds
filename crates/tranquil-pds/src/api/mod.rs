pub mod actor;
pub mod admin;
pub mod age_assurance;
pub mod backup;
pub mod delegation;
pub mod discord_webhook;
pub mod error;
pub mod identity;
pub mod moderation;
pub mod notification_prefs;
pub mod proxy;
pub mod proxy_client;
pub mod repo;
pub mod responses;
pub mod server;
pub mod telegram_webhook;
pub mod temp;
pub mod validation;
pub mod verification;

pub use error::ApiError;
pub use proxy_client::{AtUriParts, proxy_client, validate_at_uri, validate_limit};
pub use responses::{
    DidResponse, EmptyResponse, EnabledResponse, HasPasswordResponse, OptionsResponse,
    StatusResponse, SuccessResponse, TokenRequiredResponse, VerifiedResponse,
};
