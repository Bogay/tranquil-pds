use crate::circuit_breaker::CircuitBreaker;
use crate::sync::firehose::SequencedEvent;
use reqwest::Client;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, watch};
use tracing::{debug, error, info, warn};

const NOTIFY_THRESHOLD_SECS: u64 = 20 * 60;

pub struct Crawlers {
    hostname: String,
    crawler_urls: Vec<String>,
    http_client: Client,
    last_notified: AtomicU64,
    circuit_breaker: Option<Arc<CircuitBreaker>>,
}

impl Crawlers {
    pub fn new(hostname: String, crawler_urls: Vec<String>) -> Self {
        Self {
            hostname,
            crawler_urls,
            http_client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
            last_notified: AtomicU64::new(0),
            circuit_breaker: None,
        }
    }

    pub fn with_circuit_breaker(mut self, circuit_breaker: Arc<CircuitBreaker>) -> Self {
        self.circuit_breaker = Some(circuit_breaker);
        self
    }

    pub fn from_env() -> Option<Self> {
        let hostname = std::env::var("PDS_HOSTNAME").ok()?;
        let crawler_urls: Vec<String> = std::env::var("CRAWLERS")
            .unwrap_or_default()
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.trim().to_string())
            .collect();

        if crawler_urls.is_empty() {
            return None;
        }

        Some(Self::new(hostname, crawler_urls))
    }

    fn should_notify(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let last = self.last_notified.load(Ordering::Relaxed);
        now - last >= NOTIFY_THRESHOLD_SECS
    }

    fn mark_notified(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_notified.store(now, Ordering::Relaxed);
    }

    pub async fn notify_of_update(&self) {
        if !self.should_notify() {
            debug!("Skipping crawler notification due to debounce");
            return;
        }

        if let Some(cb) = &self.circuit_breaker {
            if !cb.can_execute().await {
                debug!("Skipping crawler notification due to circuit breaker open");
                return;
            }
        }

        self.mark_notified();

        let circuit_breaker = self.circuit_breaker.clone();

        for crawler_url in &self.crawler_urls {
            let url = format!("{}/xrpc/com.atproto.sync.requestCrawl", crawler_url.trim_end_matches('/'));
            let hostname = self.hostname.clone();
            let client = self.http_client.clone();
            let cb = circuit_breaker.clone();

            tokio::spawn(async move {
                match client
                    .post(&url)
                    .json(&serde_json::json!({ "hostname": hostname }))
                    .send()
                    .await
                {
                    Ok(response) => {
                        if response.status().is_success() {
                            debug!(crawler = %url, "Successfully notified crawler");
                            if let Some(cb) = cb {
                                cb.record_success().await;
                            }
                        } else {
                            let status = response.status();
                            let body = response.text().await.unwrap_or_default();
                            warn!(
                                crawler = %url,
                                status = %status,
                                body = %body,
                                hostname = %hostname,
                                "Crawler notification returned non-success status"
                            );
                            if let Some(cb) = cb {
                                cb.record_failure().await;
                            }
                        }
                    }
                    Err(e) => {
                        warn!(crawler = %url, error = %e, "Failed to notify crawler");
                        if let Some(cb) = cb {
                            cb.record_failure().await;
                        }
                    }
                }
            });
        }
    }
}

pub async fn start_crawlers_service(
    crawlers: Arc<Crawlers>,
    mut firehose_rx: broadcast::Receiver<SequencedEvent>,
    mut shutdown: watch::Receiver<bool>,
) {
    info!(
        hostname = %crawlers.hostname,
        crawler_count = crawlers.crawler_urls.len(),
        crawlers = ?crawlers.crawler_urls,
        "Starting crawlers notification service"
    );

    loop {
        tokio::select! {
            result = firehose_rx.recv() => {
                match result {
                    Ok(event) => {
                        if event.event_type == "commit" {
                            crawlers.notify_of_update().await;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!(skipped = n, "Crawlers service lagged behind firehose");
                        crawlers.notify_of_update().await;
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        error!("Firehose channel closed, stopping crawlers service");
                        break;
                    }
                }
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    info!("Crawlers service shutting down");
                    break;
                }
            }
        }
    }
}
