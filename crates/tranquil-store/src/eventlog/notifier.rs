use std::sync::Arc;

use async_trait::async_trait;
use tranquil_db_traits::{DbError, RepoEventNotifier, RepoEventReceiver};

use super::{EventLog, EventLogSubscriber, EventSequence};
use crate::io::StorageIO;

pub struct EventLogNotifier<S: StorageIO> {
    log: Arc<EventLog<S>>,
}

impl<S: StorageIO> EventLogNotifier<S> {
    pub fn new(log: Arc<EventLog<S>>) -> Self {
        Self { log }
    }
}

#[async_trait]
impl<S: StorageIO + 'static> RepoEventNotifier for EventLogNotifier<S> {
    async fn subscribe(&self) -> Result<Box<dyn RepoEventReceiver>, DbError> {
        let subscriber = self.log.subscriber(EventSequence::BEFORE_ALL);
        Ok(Box::new(EventLogEventReceiver { subscriber }))
    }
}

struct EventLogEventReceiver<S: StorageIO> {
    subscriber: EventLogSubscriber<S>,
}

#[async_trait]
impl<S: StorageIO + 'static> RepoEventReceiver for EventLogEventReceiver<S> {
    async fn recv(&mut self) -> Option<i64> {
        self.subscriber.next().await.map(|event| event.seq.as_i64())
    }
}
