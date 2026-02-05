use crate::api::error::ApiError;
use crate::rate_limit::{HandleVerificationLimit, RateLimited};
use crate::types::{Did, Handle};
use axum::{
    Json,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct VerifyHandleOwnershipInput {
    pub handle: String,
    pub did: Did,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyHandleOwnershipOutput {
    pub verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub async fn verify_handle_ownership(
    _rate_limit: RateLimited<HandleVerificationLimit>,
    Json(input): Json<VerifyHandleOwnershipInput>,
) -> Response {
    let handle: Handle = match input.handle.parse() {
        Ok(h) => h,
        Err(_) => {
            return ApiError::InvalidHandle(Some("Invalid handle format".into())).into_response();
        }
    };

    let handle_str = handle.as_str();
    let did_str = input.did.as_str();

    let dns_mismatch = match crate::handle::resolve_handle_dns(handle_str).await {
        Ok(did) if did == did_str => {
            return Json(VerifyHandleOwnershipOutput {
                verified: true,
                method: Some("dns".to_string()),
                error: None,
            })
            .into_response();
        }
        Ok(did) => Some(format!(
            "DNS record points to {}, expected {}",
            did, did_str
        )),
        Err(_) => None,
    };

    match crate::handle::resolve_handle_http(handle_str).await {
        Ok(did) if did == did_str => Json(VerifyHandleOwnershipOutput {
            verified: true,
            method: Some("http".to_string()),
            error: None,
        })
        .into_response(),
        Ok(did) => Json(VerifyHandleOwnershipOutput {
            verified: false,
            method: None,
            error: Some(format!("Handle resolves to {}, expected {}", did, did_str)),
        })
        .into_response(),
        Err(e) => Json(VerifyHandleOwnershipOutput {
            verified: false,
            method: None,
            error: Some(dns_mismatch.unwrap_or_else(|| format!("Handle resolution failed: {}", e))),
        })
        .into_response(),
    }
}
