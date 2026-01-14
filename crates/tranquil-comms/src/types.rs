use uuid::Uuid;

pub use tranquil_db_traits::{CommsChannel, CommsStatus, CommsType, QueuedComms};

pub struct NewComms {
    pub user_id: Uuid,
    pub channel: CommsChannel,
    pub comms_type: CommsType,
    pub recipient: String,
    pub subject: Option<String>,
    pub body: String,
    pub metadata: Option<serde_json::Value>,
}

impl NewComms {
    pub fn new(
        user_id: Uuid,
        channel: CommsChannel,
        comms_type: CommsType,
        recipient: String,
        subject: Option<String>,
        body: String,
    ) -> Self {
        Self {
            user_id,
            channel,
            comms_type,
            recipient,
            subject,
            body,
            metadata: None,
        }
    }

    pub fn email(
        user_id: Uuid,
        comms_type: CommsType,
        recipient: String,
        subject: String,
        body: String,
    ) -> Self {
        Self::new(
            user_id,
            CommsChannel::Email,
            comms_type,
            recipient,
            Some(subject),
            body,
        )
    }
}
