use crate::api::SuccessResponse;
use crate::state::AppState;
use axum::{
    Json,
    extract::State,
    response::{IntoResponse, Response},
};
use serde::Deserialize;

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
        Ok(_output) => SuccessResponse::ok().into_response(),
        Err(e) => e.into_response(),
    }
}
