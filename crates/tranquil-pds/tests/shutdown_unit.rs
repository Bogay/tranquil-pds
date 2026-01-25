use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio_util::sync::CancellationToken;

#[test]
fn test_panic_hook_cancels_shutdown_token() {
    let shutdown = CancellationToken::new();
    let shutdown_clone = shutdown.clone();

    let panic_occurred = Arc::new(AtomicBool::new(false));
    let panic_occurred_clone = panic_occurred.clone();

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let default_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            panic_occurred_clone.store(true, Ordering::SeqCst);
            shutdown_clone.cancel();
            default_hook(info);
        }));

        panic!("simulated corrupted data panic");
    }));

    assert!(result.is_err());
    assert!(panic_occurred.load(Ordering::SeqCst));
    assert!(shutdown.is_cancelled());

    let _ = std::panic::take_hook();
}

#[test]
fn test_cancellation_token_propagates_to_clones() {
    let shutdown = CancellationToken::new();
    let clone1 = shutdown.clone();
    let clone2 = shutdown.clone();

    assert!(!shutdown.is_cancelled());
    assert!(!clone1.is_cancelled());
    assert!(!clone2.is_cancelled());

    shutdown.cancel();

    assert!(shutdown.is_cancelled());
    assert!(clone1.is_cancelled());
    assert!(clone2.is_cancelled());
}

#[tokio::test]
async fn test_cancelled_future_completes_on_cancel() {
    let shutdown = CancellationToken::new();
    let shutdown_clone = shutdown.clone();

    let handle = tokio::spawn(async move {
        shutdown_clone.cancelled().await;
        true
    });

    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    assert!(!handle.is_finished());

    shutdown.cancel();

    let result = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        handle,
    )
    .await;

    assert!(result.is_ok());
    assert!(result.unwrap().unwrap());
}
