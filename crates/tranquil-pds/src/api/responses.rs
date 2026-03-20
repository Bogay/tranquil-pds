use crate::types::Did;
use axum::{Json, response::IntoResponse};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct EmptyResponse {}

impl EmptyResponse {
    pub fn ok() -> impl IntoResponse {
        Json(Self {})
    }
}

#[derive(Debug, Serialize)]
pub struct SuccessResponse {
    pub success: bool,
}

impl SuccessResponse {
    pub fn ok() -> impl IntoResponse {
        Json(Self { success: true })
    }
}

#[derive(Debug, Serialize)]
pub struct DidResponse {
    pub did: Did,
}

impl DidResponse {
    pub fn response(did: impl Into<Did>) -> impl IntoResponse {
        Json(Self { did: did.into() })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenRequiredResponse {
    pub token_required: bool,
}

impl TokenRequiredResponse {
    pub fn response(required: bool) -> impl IntoResponse {
        Json(Self {
            token_required: required,
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HasPasswordResponse {
    pub has_password: bool,
}

impl HasPasswordResponse {
    pub fn response(has_password: bool) -> impl IntoResponse {
        Json(Self { has_password })
    }
}

#[derive(Debug, Serialize)]
pub struct VerifiedResponse {
    pub verified: bool,
}

impl VerifiedResponse {
    pub fn response(verified: bool) -> impl IntoResponse {
        Json(Self { verified })
    }
}

#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub status: String,
}

impl StatusResponse {
    pub fn response(status: impl Into<String>) -> impl IntoResponse {
        Json(Self {
            status: status.into(),
        })
    }
}

#[derive(Debug, Serialize)]
pub struct OptionsResponse<T: Serialize> {
    pub options: T,
}

impl<T: Serialize> OptionsResponse<T> {
    pub fn new(options: T) -> Json<Self> {
        Json(Self { options })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountsOutput<T: Serialize> {
    pub accounts: T,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditLogOutput<T: Serialize> {
    pub entries: T,
    pub total: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ControllersOutput<T: Serialize> {
    pub controllers: T,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PresetsOutput<T: Serialize> {
    pub presets: T,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailUpdateStatusOutput {
    pub pending: bool,
    pub authorized: bool,
    pub new_email: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InUseOutput {
    pub in_use: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordResetOutput {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub multiple_accounts: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_count: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreferredLocaleOutput {
    pub preferred_locale: Option<String>,
}
