use axum::{
    Json,
    extract::State,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use tranquil_pds::api::SuccessResponse;
use tranquil_pds::state::AppState;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmChannelVerificationInput {
    pub channel: tranquil_db_traits::CommsChannel,
    pub identifier: String,
    pub code: String,
}

pub async fn confirm_channel_verification(
    State(state): State<AppState>,
    Json(input): Json<ConfirmChannelVerificationInput>,
) -> Response {
    let token_input = crate::server::VerifyTokenInput {
        token: input.code,
        identifier: input.identifier,
    };

    match crate::server::verify_token_internal(&state, token_input).await {
        Ok(_output) => SuccessResponse::ok().into_response(),
        Err(e) => e.into_response(),
    }
}
