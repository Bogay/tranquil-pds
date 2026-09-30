mod service;

pub use service::repo::Notice;
pub use service::{CommsService, VerificationTarget, recipient_for, repo as comms_repo};
pub use tranquil_comms::{
    CommsChannel, CommsMessageType, CommsSender, CommsStatus, DEFAULT_LOCALE, DiscordSender,
    EmailSender, NotificationStrings, QueuedComms, SendError, SignalSender, TelegramSender,
    VALID_LOCALES, format_message, get_strings, is_valid_phone_number, validate_locale,
};
