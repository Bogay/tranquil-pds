use tranquil_pds::api::error::ApiError;
use tranquil_pds::state::AppState;
use tranquil_pds::types::AtIdentifier;
use axum::{
    Json,
    extract::{Query, State},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
pub struct DescribeRepoInput {
    pub repo: AtIdentifier,
}

pub async fn describe_repo(
    State(state): State<AppState>,
    Query(input): Query<DescribeRepoInput>,
) -> Response {
    let hostname_for_handles = tranquil_config::get().server.hostname_without_port();
    let user_row = if input.repo.is_did() {
        let did: tranquil_pds::types::Did = match input.repo.as_str().parse() {
            Ok(d) => d,
            Err(_) => return ApiError::InvalidRequest("Invalid DID format".into()).into_response(),
        };
        state
            .user_repo
            .get_by_did(&did)
            .await
            .map(|opt| opt.map(|r| (r.id, r.handle, r.did)))
    } else {
        let repo_str = input.repo.as_str();
        let handle_str = if !repo_str.contains('.') {
            format!("{}.{}", repo_str, hostname_for_handles)
        } else {
            repo_str.to_string()
        };
        let handle: tranquil_pds::types::Handle = match handle_str.parse() {
            Ok(h) => h,
            Err(_) => {
                return ApiError::InvalidRequest("Invalid handle format".into()).into_response();
            }
        };
        state
            .user_repo
            .get_by_handle(&handle)
            .await
            .map(|opt| opt.map(|r| (r.id, r.handle, r.did)))
    };
    let (user_id, handle, did) = match user_row {
        Ok(Some((id, handle, did))) => (id, handle, did),
        Ok(None) => {
            return ApiError::RepoNotFound(Some("Repo not found".into())).into_response();
        }
        Err(_) => {
            return ApiError::InternalError(None).into_response();
        }
    };
    let collections = state
        .repo_repo
        .list_collections(user_id)
        .await
        .unwrap_or_default();
    let did_doc = json!({
        "id": did,
        "alsoKnownAs": [format!("at://{}", handle)]
    });
    Json(json!({
        "handle": handle,
        "did": did,
        "didDoc": did_doc,
        "collections": collections,
        "handleIsCorrect": true
    }))
    .into_response()
}
