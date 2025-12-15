use crate::api::proxy_client::{
    is_ssrf_safe, proxy_client, MAX_RESPONSE_SIZE, RESPONSE_HEADERS_TO_FORWARD,
};
use crate::api::ApiError;
use crate::state::AppState;
use axum::{
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use cid::Cid;
use jacquard_repo::storage::BlockStore;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use tracing::{error, info, warn};
use uuid::Uuid;

pub const REPO_REV_HEADER: &str = "atproto-repo-rev";
pub const UPSTREAM_LAG_HEADER: &str = "atproto-upstream-lag";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostRecord {
    #[serde(rename = "$type")]
    pub record_type: Option<String>,
    pub text: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub embed: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub langs: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileRecord {
    #[serde(rename = "$type")]
    pub record_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<Value>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Debug, Clone)]
pub struct RecordDescript<T> {
    pub uri: String,
    pub cid: String,
    pub indexed_at: DateTime<Utc>,
    pub record: T,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LikeRecord {
    #[serde(rename = "$type")]
    pub record_type: Option<String>,
    pub subject: LikeSubject,
    pub created_at: String,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LikeSubject {
    pub uri: String,
    pub cid: String,
}

#[derive(Debug, Default)]
pub struct LocalRecords {
    pub count: usize,
    pub profile: Option<RecordDescript<ProfileRecord>>,
    pub posts: Vec<RecordDescript<PostRecord>>,
    pub likes: Vec<RecordDescript<LikeRecord>>,
}

pub async fn get_records_since_rev(
    state: &AppState,
    did: &str,
    rev: &str,
) -> Result<LocalRecords, String> {
    let mut result = LocalRecords::default();
    let user_id: Uuid = sqlx::query_scalar!("SELECT id FROM users WHERE did = $1", did)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| format!("DB error: {}", e))?
        .ok_or_else(|| "User not found".to_string())?;
    let rows = sqlx::query!(
        r#"
        SELECT record_cid, collection, rkey, created_at, repo_rev
        FROM records
        WHERE repo_id = $1 AND repo_rev > $2
        ORDER BY repo_rev ASC
        LIMIT 10
        "#,
        user_id,
        rev
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| format!("DB error fetching records: {}", e))?;
    if rows.is_empty() {
        return Ok(result);
    }
    let sanity_check = sqlx::query_scalar!(
        "SELECT 1 as val FROM records WHERE repo_id = $1 AND repo_rev <= $2 LIMIT 1",
        user_id,
        rev
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| format!("DB error sanity check: {}", e))?;
    if sanity_check.is_none() {
        warn!("Sanity check failed: no records found before rev {}", rev);
        return Ok(result);
    }
    struct RowData {
        cid_str: String,
        collection: String,
        rkey: String,
        created_at: DateTime<Utc>,
    }
    let mut row_data: Vec<RowData> = Vec::with_capacity(rows.len());
    let mut cids: Vec<Cid> = Vec::with_capacity(rows.len());
    for row in &rows {
        if let Ok(cid) = row.record_cid.parse::<Cid>() {
            cids.push(cid);
            row_data.push(RowData {
                cid_str: row.record_cid.clone(),
                collection: row.collection.clone(),
                rkey: row.rkey.clone(),
                created_at: row.created_at,
            });
        }
    }
    let blocks: Vec<Option<Bytes>> = state
        .block_store
        .get_many(&cids)
        .await
        .map_err(|e| format!("Error fetching blocks: {}", e))?;
    for (data, block_opt) in row_data.into_iter().zip(blocks.into_iter()) {
        let block_bytes = match block_opt {
            Some(b) => b,
            None => continue,
        };
        result.count += 1;
        let uri = format!("at://{}/{}/{}", did, data.collection, data.rkey);
        if data.collection == "app.bsky.actor.profile" && data.rkey == "self" {
            if let Ok(record) = serde_ipld_dagcbor::from_slice::<ProfileRecord>(&block_bytes) {
                result.profile = Some(RecordDescript {
                    uri,
                    cid: data.cid_str,
                    indexed_at: data.created_at,
                    record,
                });
            }
        } else if data.collection == "app.bsky.feed.post" {
            if let Ok(record) = serde_ipld_dagcbor::from_slice::<PostRecord>(&block_bytes) {
                result.posts.push(RecordDescript {
                    uri,
                    cid: data.cid_str,
                    indexed_at: data.created_at,
                    record,
                });
            }
        } else if data.collection == "app.bsky.feed.like" {
            if let Ok(record) = serde_ipld_dagcbor::from_slice::<LikeRecord>(&block_bytes) {
                result.likes.push(RecordDescript {
                    uri,
                    cid: data.cid_str,
                    indexed_at: data.created_at,
                    record,
                });
            }
        }
    }
    Ok(result)
}

pub fn get_local_lag(local: &LocalRecords) -> Option<i64> {
    let mut oldest: Option<DateTime<Utc>> = local.profile.as_ref().map(|p| p.indexed_at);
    for post in &local.posts {
        match oldest {
            None => oldest = Some(post.indexed_at),
            Some(o) if post.indexed_at < o => oldest = Some(post.indexed_at),
            _ => {}
        }
    }
    for like in &local.likes {
        match oldest {
            None => oldest = Some(like.indexed_at),
            Some(o) if like.indexed_at < o => oldest = Some(like.indexed_at),
            _ => {}
        }
    }
    oldest.map(|o| (Utc::now() - o).num_milliseconds())
}

pub fn extract_repo_rev(headers: &HeaderMap) -> Option<String> {
    headers
        .get(REPO_REV_HEADER)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
}

#[derive(Debug)]
pub struct ProxyResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: bytes::Bytes,
}

pub async fn proxy_to_appview(
    method: &str,
    params: &HashMap<String, String>,
    auth_header: Option<&str>,
) -> Result<ProxyResponse, Response> {
    let appview_url = std::env::var("APPVIEW_URL").map_err(|_| {
        ApiError::UpstreamUnavailable("No upstream AppView configured".to_string()).into_response()
    })?;
    if let Err(e) = is_ssrf_safe(&appview_url) {
        error!("SSRF check failed for appview URL: {}", e);
        return Err(ApiError::UpstreamUnavailable(format!("Invalid upstream URL: {}", e))
            .into_response());
    }
    let target_url = format!("{}/xrpc/{}", appview_url, method);
    info!(target = %target_url, "Proxying request to appview");
    let client = proxy_client();
    let mut request_builder = client.get(&target_url).query(params);
    if let Some(auth) = auth_header {
        request_builder = request_builder.header("Authorization", auth);
    }
    match request_builder.send().await {
        Ok(resp) => {
            let status =
                StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let headers: HeaderMap = resp
                .headers()
                .iter()
                .filter(|(k, _)| {
                    RESPONSE_HEADERS_TO_FORWARD
                        .iter()
                        .any(|h| k.as_str().eq_ignore_ascii_case(h))
                })
                .filter_map(|(k, v)| {
                    let name = axum::http::HeaderName::try_from(k.as_str()).ok()?;
                    let value = HeaderValue::from_bytes(v.as_bytes()).ok()?;
                    Some((name, value))
                })
                .collect();
            let content_length = resp
                .content_length()
                .unwrap_or(0);
            if content_length > MAX_RESPONSE_SIZE {
                error!(
                    content_length,
                    max = MAX_RESPONSE_SIZE,
                    "Upstream response too large"
                );
                return Err(ApiError::UpstreamFailure.into_response());
            }
            let body = resp.bytes().await.map_err(|e| {
                error!(error = ?e, "Error reading proxy response body");
                ApiError::UpstreamFailure.into_response()
            })?;
            if body.len() as u64 > MAX_RESPONSE_SIZE {
                error!(
                    len = body.len(),
                    max = MAX_RESPONSE_SIZE,
                    "Upstream response body exceeded size limit"
                );
                return Err(ApiError::UpstreamFailure.into_response());
            }
            Ok(ProxyResponse {
                status,
                headers,
                body,
            })
        }
        Err(e) => {
            error!(error = ?e, "Error sending proxy request");
            if e.is_timeout() {
                Err(ApiError::UpstreamTimeout.into_response())
            } else if e.is_connect() {
                Err(ApiError::UpstreamUnavailable("Failed to connect to upstream".to_string())
                    .into_response())
            } else {
                Err(ApiError::UpstreamFailure.into_response())
            }
        }
    }
}

pub fn format_munged_response<T: Serialize>(data: T, lag: Option<i64>) -> Response {
    let mut response = (StatusCode::OK, Json(data)).into_response();
    if let Some(lag_ms) = lag {
        if let Ok(header_val) = HeaderValue::from_str(&lag_ms.to_string()) {
            response
                .headers_mut()
                .insert(UPSTREAM_LAG_HEADER, header_val);
        }
    }
    response
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorView {
    pub did: String,
    pub handle: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostView {
    pub uri: String,
    pub cid: String,
    pub author: AuthorView,
    pub record: Value,
    pub indexed_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub embed: Option<Value>,
    #[serde(default)]
    pub reply_count: i64,
    #[serde(default)]
    pub repost_count: i64,
    #[serde(default)]
    pub like_count: i64,
    #[serde(default)]
    pub quote_count: i64,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FeedViewPost {
    pub post: PostView,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub feed_context: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedOutput {
    pub feed: Vec<FeedViewPost>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

pub fn format_local_post(
    descript: &RecordDescript<PostRecord>,
    author_did: &str,
    author_handle: &str,
    profile: Option<&RecordDescript<ProfileRecord>>,
) -> PostView {
    let display_name = profile.and_then(|p| p.record.display_name.clone());
    PostView {
        uri: descript.uri.clone(),
        cid: descript.cid.clone(),
        author: AuthorView {
            did: author_did.to_string(),
            handle: author_handle.to_string(),
            display_name,
            avatar: None,
            extra: HashMap::new(),
        },
        record: serde_json::to_value(&descript.record).unwrap_or(Value::Null),
        indexed_at: descript.indexed_at.to_rfc3339(),
        embed: descript.record.embed.clone(),
        reply_count: 0,
        repost_count: 0,
        like_count: 0,
        quote_count: 0,
        extra: HashMap::new(),
    }
}

pub fn insert_posts_into_feed(feed: &mut Vec<FeedViewPost>, posts: Vec<PostView>) {
    if posts.is_empty() {
        return;
    }
    let new_items: Vec<FeedViewPost> = posts
        .into_iter()
        .map(|post| FeedViewPost {
            post,
            reply: None,
            reason: None,
            feed_context: None,
            extra: HashMap::new(),
        })
        .collect();
    feed.extend(new_items);
    feed.sort_by(|a, b| b.post.indexed_at.cmp(&a.post.indexed_at));
}
