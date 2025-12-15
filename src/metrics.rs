use axum::{
    body::Body,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use metrics::{counter, gauge, histogram};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::sync::OnceLock;
use std::time::Instant;

static PROMETHEUS_HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

pub fn init_metrics() -> PrometheusHandle {
    let builder = PrometheusBuilder::new();
    let handle = builder
        .install_recorder()
        .expect("failed to install Prometheus recorder");

    PROMETHEUS_HANDLE.set(handle.clone()).ok();
    describe_metrics();

    handle
}

fn describe_metrics() {
    metrics::describe_counter!(
        "bspds_http_requests_total",
        "Total number of HTTP requests"
    );
    metrics::describe_histogram!(
        "bspds_http_request_duration_seconds",
        "HTTP request duration in seconds"
    );
    metrics::describe_counter!(
        "bspds_auth_cache_hits_total",
        "Total number of authentication cache hits"
    );
    metrics::describe_counter!(
        "bspds_auth_cache_misses_total",
        "Total number of authentication cache misses"
    );
    metrics::describe_gauge!(
        "bspds_firehose_subscribers",
        "Number of active firehose WebSocket subscribers"
    );
    metrics::describe_counter!(
        "bspds_firehose_events_total",
        "Total number of firehose events published"
    );
    metrics::describe_counter!(
        "bspds_block_operations_total",
        "Total number of block store operations"
    );
    metrics::describe_counter!(
        "bspds_s3_operations_total",
        "Total number of S3/blob storage operations"
    );
    metrics::describe_gauge!(
        "bspds_notification_queue_size",
        "Current size of the notification queue"
    );
    metrics::describe_counter!(
        "bspds_rate_limit_rejections_total",
        "Total number of rate limit rejections"
    );
    metrics::describe_counter!(
        "bspds_db_queries_total",
        "Total number of database queries"
    );
    metrics::describe_histogram!(
        "bspds_db_query_duration_seconds",
        "Database query duration in seconds"
    );
}

pub async fn metrics_handler() -> impl IntoResponse {
    match PROMETHEUS_HANDLE.get() {
        Some(handle) => {
            let metrics = handle.render();
            (StatusCode::OK, [("content-type", "text/plain; version=0.0.4")], metrics)
        }
        None => (
            StatusCode::INTERNAL_SERVER_ERROR,
            [("content-type", "text/plain")],
            "Metrics not initialized".to_string(),
        ),
    }
}

pub async fn metrics_middleware(request: Request<Body>, next: Next) -> Response {
    let start = Instant::now();
    let method = request.method().to_string();
    let path = normalize_path(request.uri().path());

    let response = next.run(request).await;

    let duration = start.elapsed().as_secs_f64();
    let status = response.status().as_u16().to_string();

    counter!(
        "bspds_http_requests_total",
        "method" => method.clone(),
        "path" => path.clone(),
        "status" => status.clone()
    )
    .increment(1);

    histogram!(
        "bspds_http_request_duration_seconds",
        "method" => method,
        "path" => path
    )
    .record(duration);

    response
}

fn normalize_path(path: &str) -> String {
    if path.starts_with("/xrpc/") {
        if let Some(method) = path.strip_prefix("/xrpc/") {
            if let Some(q) = method.find('?') {
                return format!("/xrpc/{}", &method[..q]);
            }
            return path.to_string();
        }
    }

    if path.starts_with("/u/") && path.ends_with("/did.json") {
        return "/u/{handle}/did.json".to_string();
    }

    if path.starts_with("/oauth/") {
        return path.to_string();
    }

    path.to_string()
}

pub fn record_auth_cache_hit(cache_type: &str) {
    counter!("bspds_auth_cache_hits_total", "cache_type" => cache_type.to_string()).increment(1);
}

pub fn record_auth_cache_miss(cache_type: &str) {
    counter!("bspds_auth_cache_misses_total", "cache_type" => cache_type.to_string()).increment(1);
}

pub fn set_firehose_subscribers(count: usize) {
    gauge!("bspds_firehose_subscribers").set(count as f64);
}

pub fn increment_firehose_subscribers() {
    counter!("bspds_firehose_events_total").increment(1);
}

pub fn record_firehose_event() {
    counter!("bspds_firehose_events_total").increment(1);
}

pub fn record_block_operation(op_type: &str) {
    counter!("bspds_block_operations_total", "op_type" => op_type.to_string()).increment(1);
}

pub fn record_s3_operation(op_type: &str, status: &str) {
    counter!(
        "bspds_s3_operations_total",
        "op_type" => op_type.to_string(),
        "status" => status.to_string()
    )
    .increment(1);
}

pub fn set_notification_queue_size(size: usize) {
    gauge!("bspds_notification_queue_size").set(size as f64);
}

pub fn record_rate_limit_rejection(limiter: &str) {
    counter!("bspds_rate_limit_rejections_total", "limiter" => limiter.to_string()).increment(1);
}

pub fn record_db_query(query_type: &str, duration_seconds: f64) {
    counter!("bspds_db_queries_total", "query_type" => query_type.to_string()).increment(1);
    histogram!(
        "bspds_db_query_duration_seconds",
        "query_type" => query_type.to_string()
    )
    .record(duration_seconds);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_path() {
        assert_eq!(
            normalize_path("/xrpc/com.atproto.repo.getRecord"),
            "/xrpc/com.atproto.repo.getRecord"
        );
        assert_eq!(
            normalize_path("/xrpc/com.atproto.repo.getRecord?foo=bar"),
            "/xrpc/com.atproto.repo.getRecord"
        );
        assert_eq!(
            normalize_path("/u/alice.example.com/did.json"),
            "/u/{handle}/did.json"
        );
        assert_eq!(normalize_path("/oauth/token"), "/oauth/token");
        assert_eq!(normalize_path("/health"), "/health");
    }
}
