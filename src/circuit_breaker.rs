use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

pub struct CircuitBreaker {
    name: String,
    failure_threshold: u32,
    success_threshold: u32,
    timeout: Duration,
    state: Arc<RwLock<CircuitState>>,
    failure_count: AtomicU32,
    success_count: AtomicU32,
    last_failure_time: AtomicU64,
}

impl CircuitBreaker {
    pub fn new(name: &str, failure_threshold: u32, success_threshold: u32, timeout_secs: u64) -> Self {
        Self {
            name: name.to_string(),
            failure_threshold,
            success_threshold,
            timeout: Duration::from_secs(timeout_secs),
            state: Arc::new(RwLock::new(CircuitState::Closed)),
            failure_count: AtomicU32::new(0),
            success_count: AtomicU32::new(0),
            last_failure_time: AtomicU64::new(0),
        }
    }

    pub async fn can_execute(&self) -> bool {
        let state = self.state.read().await;

        match *state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                let last_failure = self.last_failure_time.load(Ordering::SeqCst);
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                if now - last_failure >= self.timeout.as_secs() {
                    drop(state);
                    let mut state = self.state.write().await;
                    if *state == CircuitState::Open {
                        *state = CircuitState::HalfOpen;
                        self.success_count.store(0, Ordering::SeqCst);
                        tracing::info!(circuit = %self.name, "Circuit breaker transitioning to half-open");
                        return true;
                    }
                }
                false
            }
            CircuitState::HalfOpen => true,
        }
    }

    pub async fn record_success(&self) {
        let state = *self.state.read().await;

        match state {
            CircuitState::Closed => {
                self.failure_count.store(0, Ordering::SeqCst);
            }
            CircuitState::HalfOpen => {
                let count = self.success_count.fetch_add(1, Ordering::SeqCst) + 1;
                if count >= self.success_threshold {
                    let mut state = self.state.write().await;
                    *state = CircuitState::Closed;
                    self.failure_count.store(0, Ordering::SeqCst);
                    self.success_count.store(0, Ordering::SeqCst);
                    tracing::info!(circuit = %self.name, "Circuit breaker closed after successful recovery");
                }
            }
            CircuitState::Open => {}
        }
    }

    pub async fn record_failure(&self) {
        let state = *self.state.read().await;

        match state {
            CircuitState::Closed => {
                let count = self.failure_count.fetch_add(1, Ordering::SeqCst) + 1;
                if count >= self.failure_threshold {
                    let mut state = self.state.write().await;
                    *state = CircuitState::Open;
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    self.last_failure_time.store(now, Ordering::SeqCst);
                    tracing::warn!(
                        circuit = %self.name,
                        failures = count,
                        "Circuit breaker opened after {} failures",
                        count
                    );
                }
            }
            CircuitState::HalfOpen => {
                let mut state = self.state.write().await;
                *state = CircuitState::Open;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                self.last_failure_time.store(now, Ordering::SeqCst);
                self.success_count.store(0, Ordering::SeqCst);
                tracing::warn!(circuit = %self.name, "Circuit breaker reopened after failure in half-open state");
            }
            CircuitState::Open => {}
        }
    }

    pub async fn state(&self) -> CircuitState {
        *self.state.read().await
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Clone)]
pub struct CircuitBreakers {
    pub plc_directory: Arc<CircuitBreaker>,
    pub relay_notification: Arc<CircuitBreaker>,
}

impl Default for CircuitBreakers {
    fn default() -> Self {
        Self::new()
    }
}

impl CircuitBreakers {
    pub fn new() -> Self {
        Self {
            plc_directory: Arc::new(CircuitBreaker::new("plc_directory", 5, 3, 60)),
            relay_notification: Arc::new(CircuitBreaker::new("relay_notification", 10, 5, 30)),
        }
    }
}

#[derive(Debug)]
pub struct CircuitOpenError {
    pub circuit_name: String,
}

impl std::fmt::Display for CircuitOpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Circuit breaker '{}' is open", self.circuit_name)
    }
}

impl std::error::Error for CircuitOpenError {}

pub async fn with_circuit_breaker<T, E, F, Fut>(
    circuit: &CircuitBreaker,
    operation: F,
) -> Result<T, CircuitBreakerError<E>>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
{
    if !circuit.can_execute().await {
        return Err(CircuitBreakerError::CircuitOpen(CircuitOpenError {
            circuit_name: circuit.name().to_string(),
        }));
    }

    match operation().await {
        Ok(result) => {
            circuit.record_success().await;
            Ok(result)
        }
        Err(e) => {
            circuit.record_failure().await;
            Err(CircuitBreakerError::OperationFailed(e))
        }
    }
}

#[derive(Debug)]
pub enum CircuitBreakerError<E> {
    CircuitOpen(CircuitOpenError),
    OperationFailed(E),
}

impl<E: std::fmt::Display> std::fmt::Display for CircuitBreakerError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CircuitBreakerError::CircuitOpen(e) => write!(f, "{}", e),
            CircuitBreakerError::OperationFailed(e) => write!(f, "Operation failed: {}", e),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for CircuitBreakerError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CircuitBreakerError::CircuitOpen(e) => Some(e),
            CircuitBreakerError::OperationFailed(e) => Some(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_circuit_breaker_starts_closed() {
        let cb = CircuitBreaker::new("test", 3, 2, 10);
        assert_eq!(cb.state().await, CircuitState::Closed);
        assert!(cb.can_execute().await);
    }

    #[tokio::test]
    async fn test_circuit_breaker_opens_after_failures() {
        let cb = CircuitBreaker::new("test", 3, 2, 10);

        cb.record_failure().await;
        assert_eq!(cb.state().await, CircuitState::Closed);

        cb.record_failure().await;
        assert_eq!(cb.state().await, CircuitState::Closed);

        cb.record_failure().await;
        assert_eq!(cb.state().await, CircuitState::Open);
        assert!(!cb.can_execute().await);
    }

    #[tokio::test]
    async fn test_circuit_breaker_success_resets_failures() {
        let cb = CircuitBreaker::new("test", 3, 2, 10);

        cb.record_failure().await;
        cb.record_failure().await;
        cb.record_success().await;

        cb.record_failure().await;
        cb.record_failure().await;
        assert_eq!(cb.state().await, CircuitState::Closed);

        cb.record_failure().await;
        assert_eq!(cb.state().await, CircuitState::Open);
    }

    #[tokio::test]
    async fn test_circuit_breaker_half_open_closes_after_successes() {
        let cb = CircuitBreaker::new("test", 3, 2, 0);

        for _ in 0..3 {
            cb.record_failure().await;
        }
        assert_eq!(cb.state().await, CircuitState::Open);

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(cb.can_execute().await);
        assert_eq!(cb.state().await, CircuitState::HalfOpen);

        cb.record_success().await;
        assert_eq!(cb.state().await, CircuitState::HalfOpen);

        cb.record_success().await;
        assert_eq!(cb.state().await, CircuitState::Closed);
    }

    #[tokio::test]
    async fn test_circuit_breaker_half_open_reopens_on_failure() {
        let cb = CircuitBreaker::new("test", 3, 2, 0);

        for _ in 0..3 {
            cb.record_failure().await;
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
        cb.can_execute().await;

        cb.record_failure().await;
        assert_eq!(cb.state().await, CircuitState::Open);
    }

    #[tokio::test]
    async fn test_with_circuit_breaker_helper() {
        let cb = CircuitBreaker::new("test", 3, 2, 10);

        let result: Result<i32, CircuitBreakerError<std::io::Error>> =
            with_circuit_breaker(&cb, || async { Ok(42) }).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);

        let result: Result<i32, CircuitBreakerError<&str>> =
            with_circuit_breaker(&cb, || async { Err("error") }).await;
        assert!(result.is_err());
    }
}
