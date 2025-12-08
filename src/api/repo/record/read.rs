use crate::state::AppState;
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use cid::Cid;
use jacquard_repo::storage::BlockStore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::str::FromStr;
use tracing::error;

#[derive(Deserialize)]
pub struct GetRecordInput {
    pub repo: String,
    pub collection: String,
    pub rkey: String,
    pub cid: Option<String>,
}

pub async fn get_record(
    State(state): State<AppState>,
    Query(input): Query<GetRecordInput>,
) -> Response {
    let user_id_opt = if input.repo.starts_with("did:") {
        sqlx::query!("SELECT id FROM users WHERE did = $1", input.repo)
            .fetch_optional(&state.db)
            .await
            .map(|opt| opt.map(|r| r.id))
    } else {
        sqlx::query!("SELECT id FROM users WHERE handle = $1", input.repo)
            .fetch_optional(&state.db)
            .await
            .map(|opt| opt.map(|r| r.id))
    };

    let user_id: uuid::Uuid = match user_id_opt {
        Ok(Some(id)) => id,
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "NotFound", "message": "Repo not found"})),
            )
                .into_response();
        }
    };

    let record_row = sqlx::query!(
        "SELECT record_cid FROM records WHERE repo_id = $1 AND collection = $2 AND rkey = $3",
        user_id,
        input.collection,
        input.rkey
    )
    .fetch_optional(&state.db)
    .await;

    let record_cid_str: String = match record_row {
        Ok(Some(row)) => row.record_cid,
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "NotFound", "message": "Record not found"})),
            )
                .into_response();
        }
    };

    if let Some(expected_cid) = &input.cid {
        if &record_cid_str != expected_cid {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "NotFound", "message": "Record CID mismatch"})),
            )
                .into_response();
        }
    }

    let cid = match Cid::from_str(&record_cid_str) {
        Ok(c) => c,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "Invalid CID in DB"})),
            )
                .into_response();
        }
    };

    let block = match state.block_store.get(&cid).await {
        Ok(Some(b)) => b,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "Record block not found"})),
            )
                .into_response();
        }
    };

    let value: serde_json::Value = match serde_ipld_dagcbor::from_slice(&block) {
        Ok(v) => v,
        Err(e) => {
            error!("Failed to deserialize record: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    Json(json!({
        "uri": format!("at://{}/{}/{}", input.repo, input.collection, input.rkey),
        "cid": record_cid_str,
        "value": value
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct ListRecordsInput {
    pub repo: String,
    pub collection: String,
    pub limit: Option<i32>,
    pub cursor: Option<String>,
    #[serde(rename = "rkeyStart")]
    pub rkey_start: Option<String>,
    #[serde(rename = "rkeyEnd")]
    pub rkey_end: Option<String>,
    pub reverse: Option<bool>,
}

#[derive(Serialize)]
pub struct ListRecordsOutput {
    pub cursor: Option<String>,
    pub records: Vec<serde_json::Value>,
}

pub async fn list_records(
    State(state): State<AppState>,
    Query(input): Query<ListRecordsInput>,
) -> Response {
    let user_id_opt = if input.repo.starts_with("did:") {
        sqlx::query!("SELECT id FROM users WHERE did = $1", input.repo)
            .fetch_optional(&state.db)
            .await
            .map(|opt| opt.map(|r| r.id))
    } else {
        sqlx::query!("SELECT id FROM users WHERE handle = $1", input.repo)
            .fetch_optional(&state.db)
            .await
            .map(|opt| opt.map(|r| r.id))
    };

    let user_id: uuid::Uuid = match user_id_opt {
        Ok(Some(id)) => id,
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "NotFound", "message": "Repo not found"})),
            )
                .into_response();
        }
    };

    let limit = input.limit.unwrap_or(50).clamp(1, 100);
    let reverse = input.reverse.unwrap_or(false);

    // Simplistic query construction - no sophisticated cursor handling or rkey ranges for now, just basic pagination
    // TODO: Implement rkeyStart/End and correct cursor logic

    let limit_i64 = limit as i64;
    let rows_res = if let Some(cursor) = &input.cursor {
        if reverse {
            sqlx::query!(
                "SELECT rkey, record_cid FROM records WHERE repo_id = $1 AND collection = $2 AND rkey < $3 ORDER BY rkey DESC LIMIT $4",
                user_id,
                input.collection,
                cursor,
                limit_i64
            )
            .fetch_all(&state.db)
            .await
            .map(|rows| rows.into_iter().map(|r| (r.rkey, r.record_cid)).collect::<Vec<_>>())
        } else {
            sqlx::query!(
                "SELECT rkey, record_cid FROM records WHERE repo_id = $1 AND collection = $2 AND rkey > $3 ORDER BY rkey ASC LIMIT $4",
                user_id,
                input.collection,
                cursor,
                limit_i64
            )
            .fetch_all(&state.db)
            .await
            .map(|rows| rows.into_iter().map(|r| (r.rkey, r.record_cid)).collect::<Vec<_>>())
        }
    } else {
        if reverse {
            sqlx::query!(
                "SELECT rkey, record_cid FROM records WHERE repo_id = $1 AND collection = $2 ORDER BY rkey DESC LIMIT $3",
                user_id,
                input.collection,
                limit_i64
            )
            .fetch_all(&state.db)
            .await
            .map(|rows| rows.into_iter().map(|r| (r.rkey, r.record_cid)).collect::<Vec<_>>())
        } else {
            sqlx::query!(
                "SELECT rkey, record_cid FROM records WHERE repo_id = $1 AND collection = $2 ORDER BY rkey ASC LIMIT $3",
                user_id,
                input.collection,
                limit_i64
            )
            .fetch_all(&state.db)
            .await
            .map(|rows| rows.into_iter().map(|r| (r.rkey, r.record_cid)).collect::<Vec<_>>())
        }
    };

    let rows = match rows_res {
        Ok(r) => r,
        Err(e) => {
            error!("Error listing records: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let mut records = Vec::new();
    let mut last_rkey = None;

    for (rkey, cid_str) in rows {
        last_rkey = Some(rkey.clone());

        if let Ok(cid) = Cid::from_str(&cid_str) {
            if let Ok(Some(block)) = state.block_store.get(&cid).await {
                if let Ok(value) = serde_ipld_dagcbor::from_slice::<serde_json::Value>(&block) {
                    records.push(json!({
                        "uri": format!("at://{}/{}/{}", input.repo, input.collection, rkey),
                        "cid": cid_str,
                        "value": value
                    }));
                }
            }
        }
    }

    Json(ListRecordsOutput {
        cursor: last_rkey,
        records,
    })
    .into_response()
}
