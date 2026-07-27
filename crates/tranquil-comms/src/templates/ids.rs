use crate::locale::get_strings;

/// Required template ids when `comms.templates_dir` is configured.
pub const REQUIRED_TEMPLATE_IDS: &[&str] = &[
    "welcome",
    "password_reset",
    "email_update",
    "short_token",
    "account_deletion",
    "plc_operation",
    "two_factor_code",
    "passkey_recovery",
    "signup_verification",
    "legacy_login",
    "migration_verification",
    "channel_verification",
    "channel_verified",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TemplateId {
    Welcome,
    PasswordReset,
    EmailUpdate,
    ShortToken,
    AccountDeletion,
    PlcOperation,
    TwoFactorCode,
    PasskeyRecovery,
    SignupVerification,
    LegacyLogin,
    MigrationVerification,
    ChannelVerification,
    ChannelVerified,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct BuiltinTemplateParts {
    pub subject: &'static str,
    pub body: &'static str,
}

impl TemplateId {
    pub(super) const ALL: &[TemplateId] = &[
        Self::Welcome,
        Self::PasswordReset,
        Self::EmailUpdate,
        Self::ShortToken,
        Self::AccountDeletion,
        Self::PlcOperation,
        Self::TwoFactorCode,
        Self::PasskeyRecovery,
        Self::SignupVerification,
        Self::LegacyLogin,
        Self::MigrationVerification,
        Self::ChannelVerification,
        Self::ChannelVerified,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Welcome => "welcome",
            Self::PasswordReset => "password_reset",
            Self::EmailUpdate => "email_update",
            Self::ShortToken => "short_token",
            Self::AccountDeletion => "account_deletion",
            Self::PlcOperation => "plc_operation",
            Self::TwoFactorCode => "two_factor_code",
            Self::PasskeyRecovery => "passkey_recovery",
            Self::SignupVerification => "signup_verification",
            Self::LegacyLogin => "legacy_login",
            Self::MigrationVerification => "migration_verification",
            Self::ChannelVerification => "channel_verification",
            Self::ChannelVerified => "channel_verified",
        }
    }

    pub(super) fn builtin_parts(self, locale: &str) -> BuiltinTemplateParts {
        let s = get_strings(locale);
        match self {
            Self::Welcome => BuiltinTemplateParts {
                subject: s.welcome_subject,
                body: s.welcome_body,
            },
            Self::PasswordReset => BuiltinTemplateParts {
                subject: s.password_reset_subject,
                body: s.password_reset_body,
            },
            Self::EmailUpdate => BuiltinTemplateParts {
                subject: s.email_update_subject,
                body: s.email_update_body,
            },
            Self::ShortToken => BuiltinTemplateParts {
                subject: s.email_update_subject,
                body: s.short_token_body,
            },
            Self::AccountDeletion => BuiltinTemplateParts {
                subject: s.account_deletion_subject,
                body: s.account_deletion_body,
            },
            Self::PlcOperation => BuiltinTemplateParts {
                subject: s.plc_operation_subject,
                body: s.plc_operation_body,
            },
            Self::TwoFactorCode => BuiltinTemplateParts {
                subject: s.two_factor_code_subject,
                body: s.two_factor_code_body,
            },
            Self::PasskeyRecovery => BuiltinTemplateParts {
                subject: s.passkey_recovery_subject,
                body: s.passkey_recovery_body,
            },
            Self::SignupVerification => BuiltinTemplateParts {
                subject: s.signup_verification_subject,
                body: s.signup_verification_body,
            },
            Self::LegacyLogin => BuiltinTemplateParts {
                subject: s.legacy_login_subject,
                body: s.legacy_login_body,
            },
            Self::MigrationVerification => BuiltinTemplateParts {
                subject: s.migration_verification_subject,
                body: s.migration_verification_body,
            },
            Self::ChannelVerification => BuiltinTemplateParts {
                subject: s.channel_verification_subject,
                body: s.channel_verification_body,
            },
            Self::ChannelVerified => BuiltinTemplateParts {
                subject: s.channel_verified_subject,
                body: s.channel_verified_body,
            },
        }
    }
}
