mod client;
pub mod store;

#[cfg(feature = "fjall-store")]
pub mod fjall_store;

#[cfg(test)]
mod tests;

pub use client::{
    DeviceName, InvalidDeviceName, InvalidSignalUsername, LinkGeneration, LinkResult, MessageBody,
    MessageTooLong, SignalClient, SignalError, SignalSlot, SignalUsername,
};
pub use presage;
pub use store::PgSignalStore;

#[async_trait::async_trait]
pub trait SignalStoreProvider: Send + Sync {
    async fn is_signal_linked(&self) -> bool;
    async fn clear_signal_data(&self) -> Result<(), SignalError>;
    async fn link_signal_device(
        &self,
        device_name: DeviceName,
        shutdown: tokio_util::sync::CancellationToken,
        link_cancel: tokio_util::sync::CancellationToken,
        linking_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<LinkResult, SignalError>;
    async fn load_signal_client(
        &self,
        shutdown: tokio_util::sync::CancellationToken,
    ) -> Option<SignalClient>;
}

pub struct PgSignalStoreProvider {
    pub pool: sqlx::PgPool,
}

#[async_trait::async_trait]
impl SignalStoreProvider for PgSignalStoreProvider {
    async fn is_signal_linked(&self) -> bool {
        PgSignalStore::new(self.pool.clone())
            .is_linked()
            .await
            .unwrap_or(false)
    }

    async fn clear_signal_data(&self) -> Result<(), SignalError> {
        PgSignalStore::new(self.pool.clone())
            .clear_all()
            .await
            .map_err(SignalError::from)
    }

    async fn link_signal_device(
        &self,
        device_name: DeviceName,
        shutdown: tokio_util::sync::CancellationToken,
        link_cancel: tokio_util::sync::CancellationToken,
        linking_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<LinkResult, SignalError> {
        SignalClient::link_device(&self.pool, device_name, shutdown, link_cancel, linking_flag)
            .await
    }

    async fn load_signal_client(
        &self,
        shutdown: tokio_util::sync::CancellationToken,
    ) -> Option<SignalClient> {
        SignalClient::from_pool(&self.pool, shutdown).await
    }
}
