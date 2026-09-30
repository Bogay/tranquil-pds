/// Required template ids when `comms.templates_dir` is configured.
pub const REQUIRED_TEMPLATE_IDS: &[&str] = &[
    TemplateId::Welcome.as_str(),
    TemplateId::PasswordReset.as_str(),
    TemplateId::EmailUpdate.as_str(),
    TemplateId::ShortToken.as_str(),
    TemplateId::AccountDeletion.as_str(),
    TemplateId::PlcOperation.as_str(),
    TemplateId::TwoFactorCode.as_str(),
    TemplateId::PasskeyRecovery.as_str(),
    TemplateId::SignupVerification.as_str(),
    TemplateId::LegacyLogin.as_str(),
    TemplateId::MigrationVerification.as_str(),
    TemplateId::ChannelVerification.as_str(),
    TemplateId::ChannelVerified.as_str(),
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

impl TemplateId {
    pub const fn as_str(self) -> &'static str {
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
}
