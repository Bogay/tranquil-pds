use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use tracing::warn;
use tranquil_db_traits::{CommsChannel, Recipient, UserCommsPrefs};
use tranquil_types::{
    ChannelIdentifier, DiscordUserId, DiscordUsername, EmailAddress, SignalUsername,
    TelegramChatId, TelegramUsername,
};
use uuid::Uuid;

macro_rules! display_code {
    ($name:ident, $shape:ident) => {
        #[derive(Debug, Clone)]
        pub struct $name(String);

        impl $name {
            pub fn new(code: &str) -> Result<Self, InvalidCode> {
                $shape(code)
                    .then(|| Self(code.to_owned()))
                    .ok_or(InvalidCode)
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

display_code!(PasswordResetCode, is_human_token_code);
display_code!(TwoFactorCode, is_two_factor_code);
display_code!(DeletionCode, is_uuid_code);
display_code!(PlcToken, is_human_token_code);
display_code!(ShortToken, is_human_token_code);
display_code!(VerificationCode, is_verification_token);
display_code!(RecoveryToken, is_recovery_token);

impl PasswordResetCode {
    pub fn mint() -> Self {
        Self::new(&crate::util::generate_token_code())
            .expect("`generate_token_code` ought to mint a token that looks ok for a human")
    }
}

impl PlcToken {
    pub fn mint() -> Self {
        Self::new(&crate::util::generate_token_code())
            .expect("`generate_token_code` ought to mint a token that looks ok for a human")
    }
}

impl TwoFactorCode {
    pub fn from_challenge(code: &str) -> Self {
        Self::new(code)
            .expect("Challenge codes get minted looking like 6 digits *or* human-friendly tokens")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidCode;

// "human-friendly"
fn is_human_token_code(code: &str) -> bool {
    let bytes = code.as_bytes();
    bytes.len() == 11
        && bytes[5] == b'-'
        && bytes[..5]
            .iter()
            .chain(bytes[6..].iter())
            .all(|b| matches!(b, b'A'..=b'Z' | b'2'..=b'7'))
}

fn is_two_factor_code(code: &str) -> bool {
    is_human_token_code(code) || (code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit()))
}

fn is_uuid_code(code: &str) -> bool {
    Uuid::parse_str(code).is_ok_and(|parsed| parsed.hyphenated().to_string() == code)
}

fn is_verification_token(code: &str) -> bool {
    URL_SAFE_NO_PAD
        .decode(code)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .is_some_and(|payload| {
            let mut fields = payload.split('|');
            fields.next() == Some("1") && fields.count() == 6
        })
}

fn is_recovery_token(code: &str) -> bool {
    code.len() == 32
        && code
            .bytes()
            .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase())
}

// Think about the situation on Telegram and Discord where the user must message a given bot *first* in order to hydrate a chat ID into our system so that we can in fact send things.
// If we can think of a better way to simply error-out later, instead of falling back to email when say Telegram is in an aborted state, let's do that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationTarget {
    Email(EmailAddress),
    Signal(SignalUsername),
    ViaEmail {
        identifier: ChannelIdentifier,
        address: EmailAddress,
    },
}

impl VerificationTarget {
    pub fn parse(
        channel: CommsChannel,
        identifier: &str,
        fallback_email: Option<EmailAddress>,
    ) -> Option<Self> {
        match channel {
            CommsChannel::Email => EmailAddress::new(identifier).ok().map(Self::Email),
            CommsChannel::Signal => SignalUsername::new(identifier).ok().map(Self::Signal),
            CommsChannel::Telegram => Some(Self::ViaEmail {
                identifier: ChannelIdentifier::Telegram(TelegramUsername::new(identifier).ok()?),
                address: fallback_email?,
            }),
            CommsChannel::Discord => Some(Self::ViaEmail {
                identifier: ChannelIdentifier::Discord(DiscordUsername::new(identifier).ok()?),
                address: fallback_email?,
            }),
        }
    }

    pub fn identifier_str(&self) -> &str {
        match self {
            Self::Email(address) => address.as_str(),
            Self::Signal(username) => username.as_str(),
            Self::ViaEmail { identifier, .. } => identifier.as_str(),
        }
    }

    pub fn recipient(&self) -> Recipient {
        match self {
            Self::Email(address) => Recipient::Email(address.clone()),
            Self::Signal(username) => Recipient::Signal(username.clone()),
            Self::ViaEmail { address, .. } => Recipient::Email(address.clone()),
        }
    }

    pub fn channel(&self) -> CommsChannel {
        match self {
            Self::Email(_) => CommsChannel::Email,
            Self::Signal(_) => CommsChannel::Signal,
            Self::ViaEmail { identifier, .. } => identifier.channel(),
        }
    }
}

pub enum MigrationTarget {
    Email(EmailAddress),
    Signal(SignalUsername),
}

impl From<VerificationTarget> for MigrationTarget {
    fn from(target: VerificationTarget) -> Self {
        match target {
            VerificationTarget::Email(address) | VerificationTarget::ViaEmail { address, .. } => {
                Self::Email(address)
            }
            VerificationTarget::Signal(username) => Self::Signal(username),
        }
    }
}

impl MigrationTarget {
    pub fn identifier(&self) -> &str {
        match self {
            Self::Email(address) => address.as_str(),
            Self::Signal(username) => username.as_str(),
        }
    }

    pub fn recipient(&self) -> Recipient {
        match self {
            Self::Email(address) => Recipient::Email(address.clone()),
            Self::Signal(username) => Recipient::Signal(username.clone()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Secrecy {
    Secret,
    NotSecret,
}

pub fn recipient_for(
    prefs: &UserCommsPrefs,
    channel: CommsChannel,
    secrecy: Secrecy,
) -> Option<Recipient> {
    let fallback = || email_recipient(prefs, secrecy);
    match channel {
        CommsChannel::Email => fallback(),
        CommsChannel::Telegram => telegram_recipient(prefs).or_else(fallback),
        CommsChannel::Discord => discord_recipient(prefs).or_else(fallback),
        CommsChannel::Signal => signal_recipient(prefs, secrecy).or_else(fallback),
    }
}

fn telegram_recipient(prefs: &UserCommsPrefs) -> Option<Recipient> {
    let chat_id = prefs.telegram_chat_id?;
    match TelegramChatId::from_i64(chat_id) {
        Some(id) => Some(Recipient::Telegram(id)),
        None => {
            warn!(
                chat_id,
                // I know I know; even though email isn't special I would say it's at least somewhat more likely to exist than the others.
                "Telegram chat ID isn't usable, falling back to email"
            );
            None
        }
    }
}

fn discord_recipient(prefs: &UserCommsPrefs) -> Option<Recipient> {
    let raw = prefs.discord_id.as_deref()?;
    match DiscordUserId::new(raw) {
        Ok(id) => Some(Recipient::Discord(id)),
        Err(_) => {
            warn!(
                discord_id = raw,
                "Discord user ID isn't usable, falling back to email"
            );
            None
        }
    }
}

fn signal_recipient(prefs: &UserCommsPrefs, secrecy: Secrecy) -> Option<Recipient> {
    match secrecy {
        Secrecy::Secret if !prefs.signal_verified => None,
        _ => {
            let raw = prefs.signal_username.as_deref()?;
            match SignalUsername::new(raw) {
                Ok(username) => Some(Recipient::Signal(username)),
                Err(_) => {
                    warn!(
                        signal_username = raw,
                        "Signal username isn't usable, falling back to email"
                    );
                    None
                }
            }
        }
    }
}

fn email_recipient(prefs: &UserCommsPrefs, secrecy: Secrecy) -> Option<Recipient> {
    match secrecy {
        Secrecy::Secret if !prefs.email_verified => None,
        _ => prefs
            .email
            .as_deref()
            .and_then(|email| EmailAddress::new(email).ok())
            .map(Recipient::Email),
    }
}

#[cfg(test)]
mod verification_target_tests {
    use super::*;

    #[test]
    fn bot_handles_send_over_fallback_email_for_now() {
        let target = VerificationTarget::ViaEmail {
            identifier: ChannelIdentifier::Telegram(
                tranquil_types::TelegramUsername::new("oys_01").unwrap(),
            ),
            address: EmailAddress::new("user@jola.dev").unwrap(),
        };
        assert_eq!(target.recipient().channel(), CommsChannel::Email);
        assert_eq!(target.identifier_str(), "oys_01");

        let target = VerificationTarget::ViaEmail {
            identifier: ChannelIdentifier::Discord(
                tranquil_types::DiscordUsername::new("oys").unwrap(),
            ),
            address: EmailAddress::new("user@jola.dev").unwrap(),
        };
        assert_eq!(target.recipient().channel(), CommsChannel::Email);
    }

    #[test]
    fn direct_channels_deliver_to_channel() {
        let email = VerificationTarget::Email(EmailAddress::new("user@nel.pet").unwrap());
        assert_eq!(email.recipient().as_str(), "user@nel.pet");
        assert_eq!(email.channel(), CommsChannel::Email);

        let signal = VerificationTarget::Signal(SignalUsername::new("oys.01").unwrap());
        assert_eq!(signal.recipient().channel(), CommsChannel::Signal);
        assert_eq!(signal.identifier_str(), "oys.01");
    }

    #[test]
    fn migration_targets_bind_delivery_addr() {
        let signup = VerificationTarget::ViaEmail {
            identifier: ChannelIdentifier::Telegram(
                tranquil_types::TelegramUsername::new("oys_01").unwrap(),
            ),
            address: EmailAddress::new("user@jola.dev").unwrap(),
        };
        let migration = MigrationTarget::from(signup);
        assert_eq!(migration.identifier(), "user@jola.dev");
        assert_eq!(migration.recipient().channel(), CommsChannel::Email);

        let signal = MigrationTarget::from(VerificationTarget::Signal(
            SignalUsername::new("oys.01").unwrap(),
        ));
        assert_eq!(signal.identifier(), "oys.01");
        assert_eq!(signal.recipient().channel(), CommsChannel::Signal);
    }

    #[test]
    fn parse_builds_nice_targets() {
        let email = VerificationTarget::parse(CommsChannel::Email, "user@nel.pet", None);
        assert_eq!(
            email,
            Some(VerificationTarget::Email(
                EmailAddress::new("user@nel.pet").unwrap()
            ))
        );

        let signal = VerificationTarget::parse(CommsChannel::Signal, "oys.01", None);
        assert_eq!(
            signal,
            Some(VerificationTarget::Signal(
                SignalUsername::new("oys.01").unwrap()
            ))
        );

        let fallback = EmailAddress::new("user@jola.dev").unwrap();
        let telegram =
            VerificationTarget::parse(CommsChannel::Telegram, "oys_01", Some(fallback.clone()));
        assert_eq!(
            telegram,
            Some(VerificationTarget::ViaEmail {
                identifier: ChannelIdentifier::Telegram(TelegramUsername::new("oys_01").unwrap()),
                address: fallback,
            })
        );

        assert_eq!(
            VerificationTarget::parse(CommsChannel::Telegram, "oys_01", None),
            None
        );
        assert_eq!(
            VerificationTarget::parse(CommsChannel::Discord, "not a handle", None),
            None
        );
        assert_eq!(
            VerificationTarget::parse(CommsChannel::Email, "garbage", None),
            None
        );
    }
}

#[cfg(test)]
mod recipient_for_tests {
    use super::*;
    use tranquil_types::Locale;

    fn undeliverable_prefs() -> UserCommsPrefs {
        UserCommsPrefs {
            email: None,
            email_verified: false,
            handle: "oys.nel.pet".parse().unwrap(),
            preferred_channel: CommsChannel::Telegram,
            preferred_locale: Locale::default(),
            telegram_chat_id: None,
            discord_id: None,
            signal_username: None,
            signal_verified: false,
        }
    }

    #[test]
    fn undeliverable_prefs_dont_resolve_on_all_channels() {
        let prefs = undeliverable_prefs();
        assert_eq!(
            recipient_for(&prefs, CommsChannel::Telegram, Secrecy::Secret),
            None
        );
        assert_eq!(
            recipient_for(&prefs, CommsChannel::Email, Secrecy::NotSecret),
            None
        );
    }

    #[test]
    fn chat_id_number_zero_falls_back_to_email_for_now() {
        let prefs = UserCommsPrefs {
            telegram_chat_id: Some(0),
            email: Some("oys@jola.dev".into()),
            email_verified: true,
            ..undeliverable_prefs()
        };
        assert_eq!(
            recipient_for(&prefs, CommsChannel::Telegram, Secrecy::Secret),
            Some(Recipient::Email(EmailAddress::new("oys@jola.dev").unwrap()))
        );
    }

    #[test]
    fn secrets_reject_unverified_email() {
        let prefs = UserCommsPrefs {
            email: Some("oys@jola.dev".into()),
            email_verified: false,
            ..undeliverable_prefs()
        };
        assert_eq!(
            recipient_for(&prefs, CommsChannel::Email, Secrecy::Secret),
            None
        );
        assert_eq!(
            recipient_for(&prefs, CommsChannel::Telegram, Secrecy::Secret),
            None
        );
        assert_eq!(
            recipient_for(&prefs, CommsChannel::Email, Secrecy::NotSecret),
            Some(Recipient::Email(EmailAddress::new("oys@jola.dev").unwrap()))
        );
    }

    #[test]
    fn secrets_reject_unverified_signal_username() {
        let prefs = UserCommsPrefs {
            signal_username: Some("oys.01".into()),
            email: Some("oys@jola.dev".into()),
            email_verified: true,
            ..undeliverable_prefs()
        };
        assert_eq!(
            recipient_for(&prefs, CommsChannel::Signal, Secrecy::NotSecret),
            Some(Recipient::Signal(SignalUsername::new("oys.01").unwrap()))
        );
        assert_eq!(
            recipient_for(&prefs, CommsChannel::Signal, Secrecy::Secret),
            Some(Recipient::Email(EmailAddress::new("oys@jola.dev").unwrap()))
        );

        let stranded = UserCommsPrefs {
            signal_username: Some("oys.01".into()),
            ..undeliverable_prefs()
        };
        assert_eq!(
            recipient_for(&stranded, CommsChannel::Signal, Secrecy::Secret),
            None
        );
    }
}

#[cfg(test)]
mod code_newtype_tests {
    use super::*;
    use tranquil_types::Did;

    #[test]
    fn codes_accept_well_formed_values() {
        assert!(PasswordResetCode::new("ABCDE-FGHIJ").is_ok());
        assert!(ShortToken::new("ABCDE-FGHIJ").is_ok());
        assert!(PlcToken::new("ABCDE-FGHIJ").is_ok());
        assert!(TwoFactorCode::new("ABCDE-FGHIJ").is_ok());
        assert!(TwoFactorCode::new("042042").is_ok());
        assert!(DeletionCode::new("0f0e8d64-6d91-4c33-8f2a-9db09b86a6e0").is_ok());
        assert!(RecoveryToken::new("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6").is_ok());

        tranquil_config::ensure_test_defaults();
        let did = Did::new("did:plc:code01".to_string()).unwrap();
        let token = crate::auth::verification_token::generate_signup_token(
            &did,
            CommsChannel::Email,
            "user@nel.pet",
        );
        assert!(VerificationCode::new(&token).is_ok());
    }

    #[test]
    fn codes_reject_weird_values() {
        assert_eq!(PasswordResetCode::mint().as_str().len(), 11);
        assert_eq!(PlcToken::mint().as_str().len(), 11);
        assert_eq!(TwoFactorCode::from_challenge("042042").as_str(), "042042");
        assert!(PasswordResetCode::new("042042").is_err());
        assert!(TwoFactorCode::new("not-a-code").is_err());
        assert!(DeletionCode::new("ABCDE-FGHIJ").is_err());
        assert!(DeletionCode::new("0f0e8d646d914c338f2a9db09b86a6e0").is_err());
        assert!(VerificationCode::new("ABCDEFGHIJKLMNOP").is_err());
        assert!(RecoveryToken::new("short").is_err());
        assert!(!is_human_token_code("abcde-fghij"));
        assert!(!is_human_token_code("ABCDEFGH-I"));
    }

    #[test]
    fn no_cross_code_type_contamination() {
        let human_code = "ABCDE-FGHIJ";
        assert!(PasswordResetCode::new(human_code).is_ok());
        assert!(VerificationCode::new(human_code).is_err());
        assert!(DeletionCode::new(human_code).is_err());
    }
}
