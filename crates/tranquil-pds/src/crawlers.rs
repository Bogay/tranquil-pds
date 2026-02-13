use crate::circuit_breaker::CircuitBreaker;
use crate::sync::firehose::SequencedEvent;
use reqwest::Client;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use tranquil_db_traits::RepoEventType;

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
                .connect_timeout(Duration::from_secs(5))
                .pool_max_idle_per_host(5)
                .pool_idle_timeout(Duration::from_secs(90))
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

    pub fn from_config(cfg: &tranquil_config::TranquilConfig) -> Option<Self> {
        let hostname = &cfg.server.hostname;
        if hostname == "localhost" {
            return None;
        }

        let crawler_urls = cfg.firehose.crawler_list();

        if crawler_urls.is_empty() {
            return None;
        }

        Some(Self::new(hostname.to_string(), crawler_urls))
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

        if let Some(cb) = &self.circuit_breaker
            && !cb.can_execute().await
        {
            debug!("Skipping crawler notification due to circuit breaker open");
            return;
        }

        self.mark_notified();
        let circuit_breaker = self.circuit_breaker.clone();

        self.crawler_urls.iter().for_each(|crawler_url| {
            let url = format!(
                "{}/xrpc/com.atproto.sync.requestCrawl",
                crawler_url.trim_end_matches('/')
            );
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
        });
    }
}

pub async fn start_crawlers_service(
    crawlers: Arc<Crawlers>,
    mut firehose_rx: broadcast::Receiver<SequencedEvent>,
    shutdown: CancellationToken,
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
                        if event.event_type == RepoEventType::Commit {
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
            _ = shutdown.cancelled() => {
                info!("Crawlers service shutting down");
                break;
            }
        }
    }
}
