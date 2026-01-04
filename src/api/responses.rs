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
    pub fn new(did: impl Into<Did>) -> impl IntoResponse {
        Json(Self { did: did.into() })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenRequiredResponse {
    pub token_required: bool,
}

impl TokenRequiredResponse {
    pub fn new(required: bool) -> impl IntoResponse {
        Json(Self { token_required: required })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HasPasswordResponse {
    pub has_password: bool,
}

impl HasPasswordResponse {
    pub fn new(has_password: bool) -> impl IntoResponse {
        Json(Self { has_password })
    }
}

#[derive(Debug, Serialize)]
pub struct VerifiedResponse {
    pub verified: bool,
}

impl VerifiedResponse {
    pub fn new(verified: bool) -> impl IntoResponse {
        Json(Self { verified })
    }
}

#[derive(Debug, Serialize)]
pub struct EnabledResponse {
    pub enabled: bool,
}

impl EnabledResponse {
    pub fn new(enabled: bool) -> impl IntoResponse {
        Json(Self { enabled })
    }
}

#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub status: String,
}

impl StatusResponse {
    pub fn new(status: impl Into<String>) -> impl IntoResponse {
        Json(Self { status: status.into() })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DidDocumentResponse {
    pub did_document: serde_json::Value,
}

impl DidDocumentResponse {
    pub fn new(did_document: serde_json::Value) -> impl IntoResponse {
        Json(Self { did_document })
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
