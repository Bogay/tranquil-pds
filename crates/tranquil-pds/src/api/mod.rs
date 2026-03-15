pub mod error;
pub mod proxy;
pub mod proxy_client;
pub mod responses;
pub mod validation;

pub use error::ApiError;
pub use proxy_client::{AtUriParts, proxy_client, validate_at_uri, validate_limit};
pub use responses::{
    DidResponse, EmptyResponse, EnabledResponse, HasPasswordResponse, OptionsResponse,
    StatusResponse, SuccessResponse, TokenRequiredResponse, VerifiedResponse,
};
