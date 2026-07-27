pub mod email;
mod locale;
mod sender;
mod templates;

pub use email::{EmailSender, SendMode};
pub use locale::{NotificationStrings, get_strings, validate_locale};
pub use sender::{
    CommsSender, DiscordSender, SendError, SignalSender, TelegramSender, is_valid_phone_number,
};
pub use templates::{
    REQUIRED_TEMPLATE_IDS, RenderedTemplate, TemplateError, TemplateId, TemplateStore,
    html_body_from_metadata,
};
pub use templates::{
    init as init_templates, render as render_template, validate as validate_templates,
};
pub use tranquil_db_traits::{CommsChannel, CommsMessageType, CommsStatus, QueuedComms};
