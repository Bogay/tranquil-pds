mod sender;
mod service;
mod types;

pub use sender::{EmailSender, NotificationSender};
pub use service::{
    enqueue_account_deletion, enqueue_email_update, enqueue_email_verification,
    enqueue_notification, enqueue_password_reset, enqueue_welcome_email, NotificationService,
};
pub use types::{
    NewNotification, NotificationChannel, NotificationStatus, NotificationType, QueuedNotification,
};
