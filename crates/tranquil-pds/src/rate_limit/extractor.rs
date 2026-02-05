use std::marker::PhantomData;

use axum::{
    extract::FromRequestParts,
    http::request::Parts,
    response::{IntoResponse, Response},
};

use crate::api::error::ApiError;
use crate::oauth::OAuthError;
use crate::state::{AppState, RateLimitKind};
use crate::util::extract_client_ip;

pub trait RateLimitPolicy: Send + Sync + 'static {
    const KIND: RateLimitKind;
}

pub struct LoginLimit;
impl RateLimitPolicy for LoginLimit {
    const KIND: RateLimitKind = RateLimitKind::Login;
}

pub struct AccountCreationLimit;
impl RateLimitPolicy for AccountCreationLimit {
    const KIND: RateLimitKind = RateLimitKind::AccountCreation;
}

pub struct PasswordResetLimit;
impl RateLimitPolicy for PasswordResetLimit {
    const KIND: RateLimitKind = RateLimitKind::PasswordReset;
}

pub struct ResetPasswordLimit;
impl RateLimitPolicy for ResetPasswordLimit {
    const KIND: RateLimitKind = RateLimitKind::ResetPassword;
}

pub struct RefreshSessionLimit;
impl RateLimitPolicy for RefreshSessionLimit {
    const KIND: RateLimitKind = RateLimitKind::RefreshSession;
}

pub struct OAuthTokenLimit;
impl RateLimitPolicy for OAuthTokenLimit {
    const KIND: RateLimitKind = RateLimitKind::OAuthToken;
}

pub struct OAuthAuthorizeLimit;
impl RateLimitPolicy for OAuthAuthorizeLimit {
    const KIND: RateLimitKind = RateLimitKind::OAuthAuthorize;
}

pub struct OAuthParLimit;
impl RateLimitPolicy for OAuthParLimit {
    const KIND: RateLimitKind = RateLimitKind::OAuthPar;
}

pub struct OAuthIntrospectLimit;
impl RateLimitPolicy for OAuthIntrospectLimit {
    const KIND: RateLimitKind = RateLimitKind::OAuthIntrospect;
}

pub struct AppPasswordLimit;
impl RateLimitPolicy for AppPasswordLimit {
    const KIND: RateLimitKind = RateLimitKind::AppPassword;
}

pub struct EmailUpdateLimit;
impl RateLimitPolicy for EmailUpdateLimit {
    const KIND: RateLimitKind = RateLimitKind::EmailUpdate;
}

pub struct TotpVerifyLimit;
impl RateLimitPolicy for TotpVerifyLimit {
    const KIND: RateLimitKind = RateLimitKind::TotpVerify;
}

pub struct HandleUpdateLimit;
impl RateLimitPolicy for HandleUpdateLimit {
    const KIND: RateLimitKind = RateLimitKind::HandleUpdate;
}

pub struct HandleUpdateDailyLimit;
impl RateLimitPolicy for HandleUpdateDailyLimit {
    const KIND: RateLimitKind = RateLimitKind::HandleUpdateDaily;
}

pub struct VerificationCheckLimit;
impl RateLimitPolicy for VerificationCheckLimit {
    const KIND: RateLimitKind = RateLimitKind::VerificationCheck;
}

pub struct SsoInitiateLimit;
impl RateLimitPolicy for SsoInitiateLimit {
    const KIND: RateLimitKind = RateLimitKind::SsoInitiate;
}

pub struct SsoCallbackLimit;
impl RateLimitPolicy for SsoCallbackLimit {
    const KIND: RateLimitKind = RateLimitKind::SsoCallback;
}

pub struct SsoUnlinkLimit;
impl RateLimitPolicy for SsoUnlinkLimit {
    const KIND: RateLimitKind = RateLimitKind::SsoUnlink;
}

pub struct OAuthRegisterCompleteLimit;
impl RateLimitPolicy for OAuthRegisterCompleteLimit {
    const KIND: RateLimitKind = RateLimitKind::OAuthRegisterComplete;
}

pub struct HandleVerificationLimit;
impl RateLimitPolicy for HandleVerificationLimit {
    const KIND: RateLimitKind = RateLimitKind::HandleVerification;
}

pub trait RateLimitRejection: IntoResponse + Send + 'static {
    fn new() -> Self;
}

pub struct ApiRateLimitRejection;

impl RateLimitRejection for ApiRateLimitRejection {
    fn new() -> Self {
        Self
    }
}

impl IntoResponse for ApiRateLimitRejection {
    fn into_response(self) -> Response {
        ApiError::RateLimitExceeded(None).into_response()
    }
}

pub struct OAuthRateLimitRejection;

impl RateLimitRejection for OAuthRateLimitRejection {
    fn new() -> Self {
        Self
    }
}

impl IntoResponse for OAuthRateLimitRejection {
    fn into_response(self) -> Response {
        OAuthError::RateLimited.into_response()
    }
}

impl From<OAuthRateLimitRejection> for OAuthError {
    fn from(_: OAuthRateLimitRejection) -> Self {
        OAuthError::RateLimited
    }
}

pub struct RateLimitedInner<P: RateLimitPolicy, R: RateLimitRejection> {
    client_ip: String,
    _marker: PhantomData<(P, R)>,
}

impl<P: RateLimitPolicy, R: RateLimitRejection> RateLimitedInner<P, R> {
    pub fn client_ip(&self) -> &str {
        &self.client_ip
    }
}

impl<P: RateLimitPolicy, R: RateLimitRejection> FromRequestParts<AppState>
    for RateLimitedInner<P, R>
{
    type Rejection = R;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let client_ip = extract_client_ip(&parts.headers, None);

        if !state.check_rate_limit(P::KIND, &client_ip).await {
            tracing::warn!(
                ip = %client_ip,
                kind = ?P::KIND,
                "Rate limit exceeded"
            );
            return Err(R::new());
        }

        Ok(RateLimitedInner {
            client_ip,
            _marker: PhantomData,
        })
    }
}

pub type RateLimited<P> = RateLimitedInner<P, ApiRateLimitRejection>;
pub type OAuthRateLimited<P> = RateLimitedInner<P, OAuthRateLimitRejection>;

#[derive(Debug)]
pub struct UserRateLimitError {
    pub kind: RateLimitKind,
    pub message: Option<String>,
}

impl UserRateLimitError {
    pub fn new(kind: RateLimitKind) -> Self {
        Self {
            kind,
            message: None,
        }
    }

    pub fn with_message(kind: RateLimitKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: Some(message.into()),
        }
    }
}

impl std::fmt::Display for UserRateLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.message {
            Some(msg) => write!(f, "{}", msg),
            None => write!(f, "Rate limit exceeded for {:?}", self.kind),
        }
    }
}

impl std::error::Error for UserRateLimitError {}

impl IntoResponse for UserRateLimitError {
    fn into_response(self) -> Response {
        ApiError::RateLimitExceeded(self.message).into_response()
    }
}

pub struct UserRateLimitProof<P: RateLimitPolicy> {
    _marker: PhantomData<P>,
}

impl<P: RateLimitPolicy> UserRateLimitProof<P> {
    fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

pub async fn check_user_rate_limit<P: RateLimitPolicy>(
    state: &AppState,
    user_key: &str,
) -> Result<UserRateLimitProof<P>, UserRateLimitError> {
    if !state.check_rate_limit(P::KIND, user_key).await {
        tracing::warn!(
            key = %user_key,
            kind = ?P::KIND,
            "User rate limit exceeded"
        );
        return Err(UserRateLimitError::new(P::KIND));
    }
    Ok(UserRateLimitProof::new())
}

pub async fn check_user_rate_limit_with_message<P: RateLimitPolicy>(
    state: &AppState,
    user_key: &str,
    error_message: impl Into<String>,
) -> Result<UserRateLimitProof<P>, UserRateLimitError> {
    if !state.check_rate_limit(P::KIND, user_key).await {
        tracing::warn!(
            key = %user_key,
            kind = ?P::KIND,
            "User rate limit exceeded"
        );
        return Err(UserRateLimitError::with_message(P::KIND, error_message));
    }
    Ok(UserRateLimitProof::new())
}
