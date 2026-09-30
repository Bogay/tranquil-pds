mod service;

pub use service::repo::Notice;
pub use service::{
    CommsService, NotificationError, VerificationTarget, recipient_for, repo as comms_repo,
};
pub use tranquil_comms::locale::{ChannelVerificationBody, ChannelVerificationSubject};
pub use tranquil_comms::{
    CommsChannel, CommsMessageType, CommsSender, CommsStatus, DEFAULT_LOCALE, DiscordSender,
    EmailSender, NotificationStrings, QueuedComms, SendError, SignalSender, TelegramSender,
    VALID_LOCALES, init_templates, is_valid_phone_number, validate_locale, validate_templates,
};
