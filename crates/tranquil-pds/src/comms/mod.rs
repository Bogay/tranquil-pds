mod service;

pub use service::repo::Notice;
pub use service::{
    CommsService, NotificationError, VerificationTarget, recipient_for, repo as comms_repo,
};
pub use tranquil_comms::{
    CommsChannel, CommsMessageType, CommsSender, CommsStatus, DiscordSender, EmailSender,
    NotificationStrings, QueuedComms, SendError, SignalSender, TelegramSender, TemplateId,
    get_strings, init_templates, is_valid_phone_number, render_template, validate_locale,
    validate_templates,
};
