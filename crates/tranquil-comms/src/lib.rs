pub mod email;
pub mod locale;
mod sender;
mod templates;

pub use email::{EmailSender, SendMode};
pub use locale::{DEFAULT_LOCALE, NotificationStrings, VALID_LOCALES, validate_locale};
pub use sender::{
    CommsSender, DiscordSender, SendError, SignalSender, TelegramSender, is_valid_phone_number,
};
pub use templates::{
    Part, REQUIRED_TEMPLATE_IDS, RenderedTemplate, TemplateError, TemplateId, TemplateStore,
    render_html, render_part,
};
pub use templates::{init as init_templates, validate as validate_templates};
pub use tranquil_db_traits::{CommsChannel, CommsMessageType, CommsStatus, QueuedComms};
