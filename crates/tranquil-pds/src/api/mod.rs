pub mod error;
pub mod proxy;
pub mod proxy_client;
pub mod responses;
pub mod validation;

pub use error::ApiError;
pub use proxy_client::{AtUriParts, proxy_client, validate_at_uri, validate_limit};
pub use responses::{
    AccountsOutput, AuditLogOutput, ControllersOutput, DidResponse, EmailUpdateStatusOutput,
    EmptyResponse, EnabledResponse, HasPasswordResponse, InUseOutput, OptionsResponse,
    PasswordResetOutput, PreferredLocaleOutput, PresetsOutput, StatusResponse, SuccessResponse,
    TokenRequiredResponse, VerifiedResponse,
};
