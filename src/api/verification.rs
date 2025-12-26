use crate::state::AppState;
use axum::{
    Json,
    extract::State,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmChannelVerificationInput {
    pub channel: String,
    pub identifier: String,
    pub code: String,
}

pub async fn confirm_channel_verification(
    State(state): State<AppState>,
    Json(input): Json<ConfirmChannelVerificationInput>,
) -> Response {
    let token_input = crate::api::server::VerifyTokenInput {
        token: input.code,
        identifier: input.identifier,
    };

    match crate::api::server::verify_token_internal(&state, token_input).await {
        Ok(output) => Json(json!({"success": output.success})).into_response(),
        Err((status, err_json)) => (status, err_json).into_response(),
    }
}
