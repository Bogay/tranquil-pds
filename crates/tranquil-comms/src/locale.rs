use tranquil_db_traits::CommsChannel;
pub use tranquil_types::{Handle, Locale};
pub const DEFAULT_LOCALE: &str = "en";
pub const VALID_LOCALES: &[&str] = &["en", "zh", "ja", "ko", "sv", "fi", "fr"];

pub fn validate_locale(locale: &str) -> &str {
    if VALID_LOCALES.contains(&locale) {
        locale
    } else {
        DEFAULT_LOCALE
    }
}

pub struct NotificationStrings {
    welcome_subject: &'static str,
    welcome_body: &'static str,
    password_reset_subject: &'static str,
    password_reset_body: &'static str,
    email_update_subject: &'static str,
    email_update_confirmation_body: &'static str,
    email_update_approval_body: &'static str,
    account_deletion_subject: &'static str,
    account_deletion_body: &'static str,
    plc_operation_subject: &'static str,
    plc_operation_body: &'static str,
    two_factor_code_subject: &'static str,
    two_factor_code_body: &'static str,
    passkey_recovery_subject: &'static str,
    passkey_recovery_body: &'static str,
    signup_verification_subject: &'static str,
    signup_verification_body: &'static str,
    legacy_login_subject: &'static str,
    legacy_login_body: &'static str,
    migration_verification_subject: &'static str,
    migration_verification_body: &'static str,
    channel_verified_subject: &'static str,
    channel_verified_body: &'static str,
    channel_verification_subject: &'static str,
    channel_verification_body: &'static str,
}

pub fn get_strings(locale: Locale) -> &'static NotificationStrings {
    match locale {
        Locale::Zh => &STRINGS_ZH,
        Locale::Ja => &STRINGS_JA,
        Locale::Ko => &STRINGS_KO,
        Locale::Sv => &STRINGS_SV,
        Locale::Fi => &STRINGS_FI,
        Locale::Fr => &STRINGS_FR,
        Locale::En => &STRINGS_EN,
    }
}

trait TemplateValue {
    fn as_template_str(&self) -> &str;
}

impl TemplateValue for str {
    fn as_template_str(&self) -> &str {
        self
    }
}

impl TemplateValue for Handle {
    fn as_template_str(&self) -> &str {
        self.as_str()
    }
}

impl TemplateValue for CommsChannel {
    fn as_template_str(&self) -> &str {
        self.display_name()
    }
}

macro_rules! templates {
    ($([$field:ident, $vars:ident, $id:ident, $part:ident, [$($key:ident : $ty:ty),* $(,)?]]),* $(,)?) => {
        $(
            pub struct $vars<'a> {
                $(pub $key: $ty,)*
            }

            impl<'a> $vars<'a> {
                pub fn as_vars(&self) -> Vec<(&'static str, &str)> {
                    vec![$((stringify!($key), self.$key.as_template_str())),*]
                }
            }
        )*

        impl NotificationStrings {
            $(
                pub fn $field(&self, locale: Locale, v: &$vars<'_>) -> Result<String, crate::templates::TemplateError> {
                    crate::templates::render_part(
                        crate::templates::TemplateId::$id,
                        crate::templates::Part::$part,
                        locale,
                        self.$field,
                        &v.as_vars(),
                    )
                }
            )*
            #[cfg(test)]
            pub fn template_fields_and_texts(&self) -> Vec<(&'static str, &'static str)> {
                vec![$((stringify!($field), self.$field)),*]
            }
        }
        #[cfg(test)]
        pub fn declared_placeholders(field: &str) -> &'static [&'static str] {
            match field {
                $(stringify!($field) => &[$(stringify!($key)),*],)*
                _ => &[],
            }
        }
    };
}

macro_rules! template_aliases {
    ($([$method:ident, $field:ident, $vars:ident, $id:ident, $part:ident]),* $(,)?) => {
        impl NotificationStrings {
            $(
                pub fn $method(&self, locale: Locale, v: &$vars<'_>) -> Result<String, crate::templates::TemplateError> {
                    crate::templates::render_part(
                        crate::templates::TemplateId::$id,
                        crate::templates::Part::$part,
                        locale,
                        self.$field,
                        &v.as_vars(),
                    )
                }
            )*
        }
    };
}

template_aliases! {
    [short_token_subject, email_update_subject, EmailUpdateSubject, ShortToken, Subject],
}

templates! {
    [welcome_subject, WelcomeSubject, Welcome, Subject, [hostname: &'a str]],
    [welcome_body, WelcomeBody, Welcome, Body, [hostname: &'a str, handle: &'a Handle]],
    [password_reset_subject, PasswordResetSubject, PasswordReset, Subject, [hostname: &'a str]],
    [password_reset_body, PasswordResetBody, PasswordReset, Body, [handle: &'a Handle, code: &'a str, valid_for: &'a str]],
    [email_update_subject, EmailUpdateSubject, EmailUpdate, Subject, [hostname: &'a str]],
    [email_update_approval_body, EmailUpdateApprovalBody, ShortToken, Body, [handle: &'a Handle, code: &'a str, verify_page: &'a str, valid_for: &'a str]],
    [email_update_confirmation_body, EmailUpdateConfirmationBody, EmailUpdate, Body, [handle: &'a Handle, code: &'a str, verify_page: &'a str, verify_link: &'a str, valid_for: &'a str]],
    [account_deletion_subject, AccountDeletionSubject, AccountDeletion, Subject, [hostname: &'a str]],
    [account_deletion_body, AccountDeletionBody, AccountDeletion, Body, [handle: &'a Handle, code: &'a str, valid_for: &'a str]],
    [plc_operation_subject, PlcOperationSubject, PlcOperation, Subject, [hostname: &'a str]],
    [plc_operation_body, PlcOperationBody, PlcOperation, Body, [handle: &'a Handle, token: &'a str, valid_for: &'a str]],
    [two_factor_code_subject, TwoFactorCodeSubject, TwoFactorCode, Subject, [hostname: &'a str]],
    [two_factor_code_body, TwoFactorCodeBody, TwoFactorCode, Body, [handle: &'a Handle, code: &'a str, valid_for: &'a str]],
    [passkey_recovery_subject, PasskeyRecoverySubject, PasskeyRecovery, Subject, [hostname: &'a str]],
    [passkey_recovery_body, PasskeyRecoveryBody, PasskeyRecovery, Body, [handle: &'a Handle, url: &'a str, valid_for: &'a str]],
    [signup_verification_subject, SignupVerificationSubject, SignupVerification, Subject, [hostname: &'a str]],
    [signup_verification_body, SignupVerificationBody, SignupVerification, Body, [code: &'a str, hostname: &'a str, verify_page: &'a str, verify_link: &'a str, valid_for: &'a str]],
    [legacy_login_subject, LegacyLoginSubject, LegacyLogin, Subject, [hostname: &'a str]],
    [legacy_login_body, LegacyLoginBody, LegacyLogin, Body, [handle: &'a Handle, timestamp: &'a str, ip: &'a str, hostname: &'a str]],
    [migration_verification_subject, MigrationVerificationSubject, MigrationVerification, Subject, [hostname: &'a str]],
    [migration_verification_body, MigrationVerificationBody, MigrationVerification, Body, [code: &'a str, hostname: &'a str, verify_page: &'a str, verify_link: &'a str, valid_for: &'a str]],
    [channel_verified_subject, ChannelVerifiedSubject, ChannelVerified, Subject, [hostname: &'a str]],
    [channel_verified_body, ChannelVerifiedBody, ChannelVerified, Body, [handle: &'a Handle, channel: CommsChannel, hostname: &'a str]],
    [channel_verification_subject, ChannelVerificationSubject, ChannelVerification, Subject, [hostname: &'a str]],
    [channel_verification_body, ChannelVerificationBody, ChannelVerification, Body, [code: &'a str, verify_link: &'a str]],
}

pub(crate) fn render(template: &str, vars: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            out.push_str(&rest[open..]);
            return out;
        };
        let name = &after[..close];
        match vars.iter().find(|(key, _)| *key == name) {
            Some((_, value)) => out.push_str(value),
            None => {
                out.push('{');
                out.push_str(name);
                out.push('}');
            }
        }
        rest = &after[close + 1..];
    }
    out.push_str(rest);
    out
}

struct DurationPhrases {
    minute: (&'static str, &'static str),
    hour: (&'static str, &'static str),
}

fn duration_phrases(locale: Locale) -> DurationPhrases {
    match locale {
        Locale::En => DurationPhrases {
            minute: ("{} minute", "{} minutes"),
            hour: ("{} hour", "{} hours"),
        },
        Locale::Zh => DurationPhrases {
            minute: ("{}分钟", "{}分钟"),
            hour: ("{}小时", "{}小时"),
        },
        Locale::Ja => DurationPhrases {
            minute: ("{}分", "{}分"),
            hour: ("{}時間", "{}時間"),
        },
        Locale::Ko => DurationPhrases {
            minute: ("{}분", "{}분"),
            hour: ("{}시간", "{}시간"),
        },
        Locale::Sv => DurationPhrases {
            minute: ("{} minut", "{} minuter"),
            hour: ("{} timme", "{} timmar"),
        },
        Locale::Fi => DurationPhrases {
            minute: ("{} minuutissa", "{} minuutissa"),
            hour: ("{} tunnissa", "{} tunnissa"),
        },
        Locale::Fr => DurationPhrases {
            minute: ("{} minute", "{} minutes"),
            hour: ("{} heure", "{} heures"),
        },
    }
}

pub fn localized_duration(locale: Locale, span: std::time::Duration) -> String {
    let phrases = duration_phrases(locale);
    let minutes = span.as_secs() / 60;
    let (form, count) = if minutes >= 60 && minutes.is_multiple_of(60) {
        (phrases.hour, minutes / 60)
    } else {
        (phrases.minute, minutes)
    };
    let template = match count {
        1 => form.0,
        _ => form.1,
    };
    template.replacen("{}", &count.to_string(), 1)
}

static STRINGS_EN: NotificationStrings = NotificationStrings {
    welcome_subject: "Welcome to {hostname}",
    welcome_body: "Welcome to {hostname}!\n\nYour handle is: @{handle}\n\nThank you for joining us.",
    password_reset_subject: "Password Reset - {hostname}",
    password_reset_body: "Hello @{handle},\n\nYour password reset code is: {code}\n\nThis code will expire in {valid_for}.\n\nIf you did not request this, please ignore this message.",
    email_update_subject: "Confirm your new email - {hostname}",
    email_update_confirmation_body: "Hello @{handle},\n\nYour verification code is:\n{code}\n\nCopy the code above and enter it at:\n{verify_page}\n\nThis code will expire in {valid_for}.\n\nOr if you like to live dangerously:\n{verify_link}\n\nIf you did not request this, please ignore this email.",
    email_update_approval_body: "Hello @{handle},\n\nYour verification code is:\n{code}\n\nCopy the code above and enter it at:\n{verify_page}\n\nThis code will expire in {valid_for}.\n\nIf you did not request this, please ignore this email.",
    account_deletion_subject: "Account Deletion Request - {hostname}",
    account_deletion_body: "Hello @{handle},\n\nYour account deletion confirmation code is: {code}\n\nThis code will expire in {valid_for}.\n\nIf you did not request this, please secure your account immediately.",
    plc_operation_subject: "{hostname} - PLC Operation Token",
    plc_operation_body: "Hello @{handle},\n\nYou requested to sign a PLC operation for your account.\n\nYour verification token is: {token}\n\nThis token will expire in {valid_for}.\n\nIf you did not request this, you can safely ignore this message.",
    two_factor_code_subject: "Sign-in Verification - {hostname}",
    two_factor_code_body: "Hello @{handle},\n\nYour sign-in verification code is: {code}\n\nThis code will expire in {valid_for}.\n\nIf you did not request this, please secure your account immediately.",
    passkey_recovery_subject: "Account Recovery - {hostname}",
    passkey_recovery_body: "Hello @{handle},\n\nYou requested to recover your passkey-only account.\n\nClick the link below to set a temporary password and regain access:\n{url}\n\nThis link will expire in {valid_for}.\n\nIf you did not request this, please ignore this message. Your account remains secure.",
    signup_verification_subject: "Verify your account - {hostname}",
    signup_verification_body: "Welcome! Your verification code is:\n{code}\n\nCopy the code above and enter it at:\n{verify_page}\n\nThis code will expire in {valid_for}.\n\nOr if you like to live dangerously:\n{verify_link}\n\nIf you did not create an account on {hostname}, please ignore this message.",
    legacy_login_subject: "Security Alert: Legacy Login Detected - {hostname}",
    legacy_login_body: "Hello @{handle},\n\nA login to your account was detected using a legacy app (like Bluesky) that doesn't support TOTP verification.\n\nDetails:\n- Time: {timestamp}\n- IP Address: {ip}\n\nYour TOTP protection was bypassed for this login. The session has limited permissions for sensitive operations.\n\nIf this wasn't you, please:\n1. Change your password immediately\n2. Review your active sessions\n3. Consider disabling legacy app logins in your security settings\n\nStay safe,\n{hostname}",
    migration_verification_subject: "Verify your account - {hostname}",
    migration_verification_body: "Welcome to {hostname}!\n\nYour account has been migrated successfully. To complete the setup, please verify your account.\n\nYour verification code is:\n{code}\n\nCopy the code above and enter it at:\n{verify_page}\n\nThis code will expire in {valid_for}.\n\nOr if you like to live dangerously:\n{verify_link}\n\nIf you did not migrate your account, please ignore this message.",
    channel_verified_subject: "Channel verified - {hostname}",
    channel_verified_body: "Hello {handle},\n\n{channel} has been verified as a notification channel for your account on {hostname}.",
    channel_verification_subject: "Verify your channel - {hostname}",
    channel_verification_body: "Your verification code is:\n{code}\n\nOr verify directly:\n{verify_link}",
};

static STRINGS_ZH: NotificationStrings = NotificationStrings {
    welcome_subject: "欢迎加入 {hostname}",
    welcome_body: "欢迎加入 {hostname}！\n\n您的用户名是：@{handle}\n\n感谢您的加入。",
    password_reset_subject: "密码重置 - {hostname}",
    password_reset_body: "您好 @{handle}，\n\n您的密码重置验证码是：{code}\n\n此验证码将在{valid_for}后过期。\n\n如果这不是您的操作，请忽略此消息。",
    email_update_subject: "确认您的新邮箱 - {hostname}",
    email_update_confirmation_body: "您好 @{handle}，\n\n您的验证码是：\n{code}\n\n复制上述验证码并在此输入：\n{verify_page}\n\n此验证码将在{valid_for}后过期。\n\n或者直接点击链接：\n{verify_link}\n\n如果这不是您的操作，请忽略此邮件。",
    email_update_approval_body: "您好 @{handle}，\n\n您的验证码是：\n{code}\n\n复制上述验证码并在此输入：\n{verify_page}\n\n此验证码将在{valid_for}后过期。\n\n如果这不是您的操作，请忽略此邮件。",
    account_deletion_subject: "账户删除请求 - {hostname}",
    account_deletion_body: "您好 @{handle}，\n\n您的账户删除确认码是：{code}\n\n此验证码将在{valid_for}后过期。\n\n如果这不是您的操作，请立即保护您的账户。",
    plc_operation_subject: "{hostname} - PLC 操作令牌",
    plc_operation_body: "您好 @{handle}，\n\n您请求为账户签署 PLC 操作。\n\n您的验证令牌是：{token}\n\n此令牌将在{valid_for}后过期。\n\n如果这不是您的操作，您可以安全地忽略此消息。",
    two_factor_code_subject: "登录验证 - {hostname}",
    two_factor_code_body: "您好 @{handle}，\n\n您的登录验证码是：{code}\n\n此验证码将在{valid_for}后过期。\n\n如果这不是您的操作，请立即保护您的账户。",
    passkey_recovery_subject: "账户恢复 - {hostname}",
    passkey_recovery_body: "您好 @{handle}，\n\n您请求恢复仅通行密钥账户的访问权限。\n\n点击以下链接设置临时密码并恢复访问：\n{url}\n\n此链接将在{valid_for}后过期。\n\n如果这不是您的操作，请忽略此消息。您的账户仍然安全。",
    signup_verification_subject: "验证您的账户 - {hostname}",
    signup_verification_body: "欢迎！您的验证码是：\n{code}\n\n复制上述验证码并在此输入：\n{verify_page}\n\n此验证码将在{valid_for}后过期。\n\n或者直接点击链接：\n{verify_link}\n\n如果您没有在 {hostname} 上创建账户，请忽略此消息。",
    legacy_login_subject: "安全提醒：检测到传统应用登录 - {hostname}",
    legacy_login_body: "您好 @{handle}，\n\n检测到使用不支持 TOTP 验证的传统应用（如 Bluesky）登录您的账户。\n\n详细信息：\n- 时间：{timestamp}\n- IP 地址：{ip}\n\n此次登录绕过了 TOTP 保护。该会话对敏感操作的权限有限。\n\n如果这不是您的操作，请：\n1. 立即更改密码\n2. 检查您的活跃会话\n3. 考虑在安全设置中禁用传统应用登录\n\n请注意安全，\n{hostname}",
    migration_verification_subject: "验证您的账户 - {hostname}",
    migration_verification_body: "欢迎来到 {hostname}！\n\n您的账户已成功迁移。要完成设置，请验证您的账户。\n\n您的验证码是：\n{code}\n\n复制上述验证码并在此输入：\n{verify_page}\n\n此验证码将在{valid_for}后过期。\n\n或者直接点击链接：\n{verify_link}\n\n如果您没有迁移账户，请忽略此消息。",
    channel_verified_subject: "通知渠道已验证 - {hostname}",
    channel_verified_body: "您好 {handle}，\n\n{channel} 已被验证为您在 {hostname} 上的通知渠道。",
    channel_verification_subject: "验证您的渠道 - {hostname}",
    channel_verification_body: "您的验证码是：\n{code}\n\n或直接验证：\n{verify_link}",
};

static STRINGS_JA: NotificationStrings = NotificationStrings {
    welcome_subject: "{hostname} へようこそ",
    welcome_body: "{hostname} へようこそ！\n\nお客様のハンドル：@{handle}\n\nご登録ありがとうございます。",
    password_reset_subject: "パスワードリセット - {hostname}",
    password_reset_body: "@{handle} 様\n\nパスワードリセットコードは：{code}\n\nこのコードは{valid_for}後に期限切れとなります。\n\nこの操作に心当たりがない場合は、このメッセージを無視してください。",
    email_update_subject: "新しいメールアドレスの確認 - {hostname}",
    email_update_confirmation_body: "@{handle} 様\n\n確認コードは：\n{code}\n\n上記のコードをコピーして、こちらで入力してください：\n{verify_page}\n\nこのコードは{valid_for}後に期限切れとなります。\n\n自己責任でワンクリック認証：\n{verify_link}\n\nこの操作に心当たりがない場合は、このメールを無視してください。",
    email_update_approval_body: "@{handle} 様\n\n確認コードは：\n{code}\n\n上記のコードをコピーして、こちらで入力してください：\n{verify_page}\n\nこのコードは{valid_for}後に期限切れとなります。\n\nこの操作に心当たりがない場合は、このメールを無視してください。",
    account_deletion_subject: "アカウント削除リクエスト - {hostname}",
    account_deletion_body: "@{handle} 様\n\nアカウント削除の確認コードは：{code}\n\nこのコードは{valid_for}後に期限切れとなります。\n\nこの操作に心当たりがない場合は、直ちにアカウントを保護してください。",
    plc_operation_subject: "{hostname} - PLC 操作トークン",
    plc_operation_body: "@{handle} 様\n\nアカウントの PLC 操作の署名をリクエストされました。\n\n認証トークンは：{token}\n\nこのトークンは{valid_for}後に期限切れとなります。\n\nこの操作に心当たりがない場合は、このメッセージを無視しても問題ありません。",
    two_factor_code_subject: "ログイン認証 - {hostname}",
    two_factor_code_body: "@{handle} 様\n\nログイン認証コードは：{code}\n\nこのコードは{valid_for}後に期限切れとなります。\n\nこの操作に心当たりがない場合は、直ちにアカウントを保護してください。",
    passkey_recovery_subject: "アカウント復旧 - {hostname}",
    passkey_recovery_body: "@{handle} 様\n\nパスキー専用アカウントの復旧をリクエストされました。\n\n以下のリンクをクリックして一時パスワードを設定し、アクセスを回復してください：\n{url}\n\nこのリンクは{valid_for}後に期限切れとなります。\n\nこの操作に心当たりがない場合は、このメッセージを無視してください。アカウントは安全なままです。",
    signup_verification_subject: "アカウント認証 - {hostname}",
    signup_verification_body: "ようこそ！認証コードは：\n{code}\n\n上記のコードをコピーして、こちらで入力してください：\n{verify_page}\n\nこのコードは{valid_for}後に期限切れとなります。\n\n自己責任でワンクリック認証：\n{verify_link}\n\n{hostname} でアカウントを作成していない場合は、このメッセージを無視してください。",
    legacy_login_subject: "セキュリティ警告：レガシーログインを検出 - {hostname}",
    legacy_login_body: "@{handle} 様\n\nTOTP 認証に対応していないレガシーアプリ（Bluesky など）からのログインが検出されました。\n\n詳細：\n- 時刻：{timestamp}\n- IP アドレス：{ip}\n\nこのログインでは TOTP 保護がバイパスされました。このセッションは機密操作に対する権限が制限されています。\n\n心当たりがない場合は：\n1. 直ちにパスワードを変更してください\n2. アクティブなセッションを確認してください\n3. セキュリティ設定でレガシーアプリのログインを無効にすることを検討してください\n\nご注意ください。\n{hostname}",
    migration_verification_subject: "アカウント認証 - {hostname}",
    migration_verification_body: "{hostname} へようこそ！\n\nアカウントの移行が完了しました。設定を完了するには、アカウントを認証してください。\n\n認証コードは：\n{code}\n\n上記のコードをコピーして、こちらで入力してください：\n{verify_page}\n\nこのコードは{valid_for}後に期限切れとなります。\n\n自己責任でワンクリック認証：\n{verify_link}\n\nアカウントを移行していない場合は、このメッセージを無視してください。",
    channel_verified_subject: "通知チャンネル認証完了 - {hostname}",
    channel_verified_body: "{handle} 様\n\n{channel} が {hostname} の通知チャンネルとして認証されました。",
    channel_verification_subject: "チャンネルを認証 - {hostname}",
    channel_verification_body: "認証コードは：\n{code}\n\n直接認証：\n{verify_link}",
};

static STRINGS_KO: NotificationStrings = NotificationStrings {
    welcome_subject: "{hostname}에 오신 것을 환영합니다",
    welcome_body: "{hostname}에 오신 것을 환영합니다!\n\n회원님의 핸들은: @{handle}\n\n가입해 주셔서 감사합니다.",
    password_reset_subject: "비밀번호 재설정 - {hostname}",
    password_reset_body: "안녕하세요 @{handle}님,\n\n비밀번호 재설정 코드는: {code}\n\n이 코드는 {valid_for} 후에 만료됩니다.\n\n요청하지 않으셨다면 이 메시지를 무시하세요.",
    email_update_subject: "새 이메일 주소 확인 - {hostname}",
    email_update_confirmation_body: "안녕하세요 @{handle}님,\n\n인증 코드는:\n{code}\n\n위 코드를 복사하여 여기에 입력하세요:\n{verify_page}\n\n이 코드는 {valid_for} 후에 만료됩니다.\n\n위험을 감수하고 원클릭 인증:\n{verify_link}\n\n요청하지 않으셨다면 이 이메일을 무시하세요.",
    email_update_approval_body: "안녕하세요 @{handle}님,\n\n인증 코드는:\n{code}\n\n위 코드를 복사하여 여기에 입력하세요:\n{verify_page}\n\n이 코드는 {valid_for} 후에 만료됩니다.\n\n요청하지 않으셨다면 이 이메일을 무시하세요.",
    account_deletion_subject: "계정 삭제 요청 - {hostname}",
    account_deletion_body: "안녕하세요 @{handle}님,\n\n계정 삭제 확인 코드는: {code}\n\n이 코드는 {valid_for} 후에 만료됩니다.\n\n요청하지 않으셨다면 즉시 계정을 보호하세요.",
    plc_operation_subject: "{hostname} - PLC 작업 토큰",
    plc_operation_body: "안녕하세요 @{handle}님,\n\n계정의 PLC 작업 서명을 요청하셨습니다.\n\n인증 토큰은: {token}\n\n이 토큰은 {valid_for} 후에 만료됩니다.\n\n요청하지 않으셨다면 이 메시지를 안전하게 무시하셔도 됩니다.",
    two_factor_code_subject: "로그인 인증 - {hostname}",
    two_factor_code_body: "안녕하세요 @{handle}님,\n\n로그인 인증 코드는: {code}\n\n이 코드는 {valid_for} 후에 만료됩니다.\n\n요청하지 않으셨다면 즉시 계정을 보호하세요.",
    passkey_recovery_subject: "계정 복구 - {hostname}",
    passkey_recovery_body: "안녕하세요 @{handle}님,\n\n패스키 전용 계정 복구를 요청하셨습니다.\n\n아래 링크를 클릭하여 임시 비밀번호를 설정하고 액세스를 복구하세요:\n{url}\n\n이 링크는 {valid_for} 후에 만료됩니다.\n\n요청하지 않으셨다면 이 메시지를 무시하세요. 계정은 안전하게 유지됩니다.",
    signup_verification_subject: "계정 인증 - {hostname}",
    signup_verification_body: "환영합니다! 인증 코드는:\n{code}\n\n위 코드를 복사하여 여기에 입력하세요:\n{verify_page}\n\n이 코드는 {valid_for} 후에 만료됩니다.\n\n위험을 감수하고 원클릭 인증:\n{verify_link}\n\n{hostname}에서 계정을 만들지 않았다면 이 메시지를 무시하세요.",
    legacy_login_subject: "보안 알림: 레거시 로그인 감지 - {hostname}",
    legacy_login_body: "안녕하세요 @{handle}님,\n\nTOTP 인증을 지원하지 않는 레거시 앱(예: Bluesky)을 사용한 로그인이 감지되었습니다.\n\n세부 정보:\n- 시간: {timestamp}\n- IP 주소: {ip}\n\n이 로그인에서 TOTP 보호가 우회되었습니다. 이 세션은 민감한 작업에 대한 권한이 제한됩니다.\n\n본인이 아닌 경우:\n1. 즉시 비밀번호를 변경하세요\n2. 활성 세션을 검토하세요\n3. 보안 설정에서 레거시 앱 로그인 비활성화를 고려하세요\n\n{hostname} 드림",
    migration_verification_subject: "계정 인증 - {hostname}",
    migration_verification_body: "{hostname}에 오신 것을 환영합니다!\n\n계정 마이그레이션이 완료되었습니다. 설정을 완료하려면 계정을 인증하세요.\n\n인증 코드는:\n{code}\n\n위 코드를 복사하여 여기에 입력하세요:\n{verify_page}\n\n이 코드는 {valid_for} 후에 만료됩니다.\n\n위험을 감수하고 원클릭 인증:\n{verify_link}\n\n계정을 마이그레이션하지 않았다면 이 메시지를 무시하세요.",
    channel_verified_subject: "알림 채널 인증 완료 - {hostname}",
    channel_verified_body: "안녕하세요 {handle}님,\n\n{channel}이(가) {hostname}의 알림 채널로 인증되었습니다.",
    channel_verification_subject: "채널 인증 - {hostname}",
    channel_verification_body: "인증 코드:\n{code}\n\n직접 인증:\n{verify_link}",
};

static STRINGS_SV: NotificationStrings = NotificationStrings {
    welcome_subject: "Välkommen till {hostname}",
    welcome_body: "Välkommen till {hostname}!\n\nDitt användarnamn är: @{handle}\n\nTack för att du gick med.",
    password_reset_subject: "Lösenordsåterställning - {hostname}",
    password_reset_body: "Hej @{handle},\n\nDin kod för lösenordsåterställning är: {code}\n\nDenna kod upphör om {valid_for}.\n\nOm du inte begärde detta kan du ignorera detta meddelande.",
    email_update_subject: "Bekräfta din nya e-post - {hostname}",
    email_update_confirmation_body: "Hej @{handle},\n\nDin verifieringskod är:\n{code}\n\nKopiera koden ovan och ange den på:\n{verify_page}\n\nDenna kod upphör om {valid_for}.\n\nEller om du gillar att leva farligt:\n{verify_link}\n\nOm du inte begärde detta kan du ignorera detta meddelande.",
    email_update_approval_body: "Hej @{handle},\n\nDin verifieringskod är:\n{code}\n\nKopiera koden ovan och ange den på:\n{verify_page}\n\nDenna kod upphör om {valid_for}.\n\nOm du inte begärde detta kan du ignorera detta meddelande.",
    account_deletion_subject: "Begäran om kontoradering - {hostname}",
    account_deletion_body: "Hej @{handle},\n\nDin bekräftelsekod för kontoradering är: {code}\n\nDenna kod upphör om {valid_for}.\n\nOm du inte begärde detta, skydda ditt konto omedelbart.",
    plc_operation_subject: "{hostname} - PLC-operationstoken",
    plc_operation_body: "Hej @{handle},\n\nDu begärde att signera en PLC-operation för ditt konto.\n\nDin verifieringstoken är: {token}\n\nDenna token upphör om {valid_for}.\n\nOm du inte begärde detta kan du säkert ignorera detta meddelande.",
    two_factor_code_subject: "Inloggningsverifiering - {hostname}",
    two_factor_code_body: "Hej @{handle},\n\nDin inloggningsverifieringskod är: {code}\n\nDenna kod upphör om {valid_for}.\n\nOm du inte begärde detta, skydda ditt konto omedelbart.",
    passkey_recovery_subject: "Kontoåterställning - {hostname}",
    passkey_recovery_body: "Hej @{handle},\n\nDu begärde att återställa ditt endast nyckelkonto.\n\nKlicka på länken nedan för att ställa in ett tillfälligt lösenord och återfå åtkomst:\n{url}\n\nDenna länk upphör om {valid_for}.\n\nOm du inte begärde detta kan du ignorera detta meddelande. Ditt konto förblir säkert.",
    signup_verification_subject: "Verifiera ditt konto - {hostname}",
    signup_verification_body: "Välkommen! Din verifieringskod är:\n{code}\n\nKopiera koden ovan och ange den på:\n{verify_page}\n\nDenna kod upphör om {valid_for}.\n\nEller om du gillar att leva farligt:\n{verify_link}\n\nOm du inte skapade ett konto på {hostname}, ignorera detta meddelande.",
    legacy_login_subject: "Säkerhetsvarning: Äldre inloggning upptäckt - {hostname}",
    legacy_login_body: "Hej @{handle},\n\nEn inloggning till ditt konto upptäcktes med en äldre app (som Bluesky) som inte stöder TOTP-verifiering.\n\nDetaljer:\n- Tid: {timestamp}\n- IP-adress: {ip}\n\nDitt TOTP-skydd kringgicks för denna inloggning. Sessionen har begränsade behörigheter för känsliga operationer.\n\nOm detta inte var du:\n1. Ändra ditt lösenord omedelbart\n2. Granska dina aktiva sessioner\n3. Överväg att inaktivera äldre appinloggningar i dina säkerhetsinställningar\n\nVar försiktig,\n{hostname}",
    migration_verification_subject: "Verifiera ditt konto - {hostname}",
    migration_verification_body: "Välkommen till {hostname}!\n\nDitt konto har migrerats framgångsrikt. För att slutföra installationen, verifiera ditt konto.\n\nDin verifieringskod är:\n{code}\n\nKopiera koden ovan och ange den på:\n{verify_page}\n\nDenna kod upphör om {valid_for}.\n\nEller om du gillar att leva farligt:\n{verify_link}\n\nOm du inte migrerade ditt konto kan du ignorera detta meddelande.",
    channel_verified_subject: "Aviseringskanal verifierad - {hostname}",
    channel_verified_body: "Hej {handle},\n\n{channel} har verifierats som aviseringskanal för ditt konto på {hostname}.",
    channel_verification_subject: "Verifiera din kanal - {hostname}",
    channel_verification_body: "Din verifieringskod är:\n{code}\n\nEller verifiera direkt:\n{verify_link}",
};

static STRINGS_FI: NotificationStrings = NotificationStrings {
    welcome_subject: "Tervetuloa palveluun {hostname}",
    welcome_body: "Tervetuloa palveluun {hostname}!\n\nKäyttäjänimesi on: @{handle}\n\nKiitos liittymisestä.",
    password_reset_subject: "Salasanan palautus - {hostname}",
    password_reset_body: "Hei @{handle},\n\nSalasanan palautuskoodisi on: {code}\n\nTämä koodi vanhenee {valid_for}.\n\nJos et pyytänyt tätä, voit jättää tämän viestin huomiotta.",
    email_update_subject: "Vahvista uusi sähköpostisi - {hostname}",
    email_update_confirmation_body: "Hei @{handle},\n\nVahvistuskoodisi on:\n{code}\n\nKopioi koodi yllä ja syötä se osoitteessa:\n{verify_page}\n\nTämä koodi vanhenee {valid_for}.\n\nTai jos pidät vaarallisesta elämästä:\n{verify_link}\n\nJos et pyytänyt tätä, voit jättää tämän viestin huomiotta.",
    email_update_approval_body: "Hei @{handle},\n\nVahvistuskoodisi on:\n{code}\n\nKopioi koodi yllä ja syötä se osoitteessa:\n{verify_page}\n\nTämä koodi vanhenee {valid_for}.\n\nJos et pyytänyt tätä, voit jättää tämän viestin huomiotta.",
    account_deletion_subject: "Tilin poistopyyntö - {hostname}",
    account_deletion_body: "Hei @{handle},\n\nTilin poiston vahvistuskoodisi on: {code}\n\nTämä koodi vanhenee {valid_for}.\n\nJos et pyytänyt tätä, suojaa tilisi välittömästi.",
    plc_operation_subject: "{hostname} - PLC-toimintotunniste",
    plc_operation_body: "Hei @{handle},\n\nPyysit allekirjoittamaan PLC-toiminnon tilillesi.\n\nVahvistustunnisteesi on: {token}\n\nTämä tunniste vanhenee {valid_for}.\n\nJos et pyytänyt tätä, voit turvallisesti jättää tämän viestin huomiotta.",
    two_factor_code_subject: "Kirjautumisen vahvistus - {hostname}",
    two_factor_code_body: "Hei @{handle},\n\nKirjautumisen vahvistuskoodisi on: {code}\n\nTämä koodi vanhenee {valid_for}.\n\nJos et pyytänyt tätä, suojaa tilisi välittömästi.",
    passkey_recovery_subject: "Tilin palautus - {hostname}",
    passkey_recovery_body: "Hei @{handle},\n\nPyysit palauttamaan vain pääsyavaintilisi.\n\nKlikkaa alla olevaa linkkiä asettaaksesi väliaikaisen salasanan ja saadaksesi pääsyn takaisin:\n{url}\n\nTämä linkki vanhenee {valid_for}.\n\nJos et pyytänyt tätä, voit jättää tämän viestin huomiotta. Tilisi pysyy turvassa.",
    signup_verification_subject: "Vahvista tilisi - {hostname}",
    signup_verification_body: "Tervetuloa! Vahvistuskoodisi on:\n{code}\n\nKopioi koodi yllä ja syötä se osoitteessa:\n{verify_page}\n\nTämä koodi vanhenee {valid_for}.\n\nTai jos pidät vaarallisesta elämästä:\n{verify_link}\n\nJos et luonut tiliä palveluun {hostname}, jätä tämä viesti huomiotta.",
    legacy_login_subject: "Turvallisuushälytys: Vanha kirjautuminen havaittu - {hostname}",
    legacy_login_body: "Hei @{handle},\n\nTilillesi havaittiin kirjautuminen vanhalla sovelluksella (kuten Bluesky), joka ei tue TOTP-vahvistusta.\n\nTiedot:\n- Aika: {timestamp}\n- IP-osoite: {ip}\n\nTOTP-suojauksesi ohitettiin tässä kirjautumisessa. Istunnolla on rajoitetut oikeudet arkaluontoisiin toimintoihin.\n\nJos tämä et ollut sinä:\n1. Vaihda salasanasi välittömästi\n2. Tarkista aktiiviset istuntosi\n3. Harkitse vanhojen sovellusten kirjautumisen poistamista käytöstä turvallisuusasetuksissa\n\nOle varovainen,\n{hostname}",
    migration_verification_subject: "Vahvista tilisi - {hostname}",
    migration_verification_body: "Tervetuloa palveluun {hostname}!\n\nTilisi on siirretty onnistuneesti. Viimeistele asennus vahvistamalla tilisi.\n\nVahvistuskoodisi on:\n{code}\n\nKopioi koodi yllä ja syötä se osoitteessa:\n{verify_page}\n\nTämä koodi vanhenee {valid_for}.\n\nTai jos pidät vaarallisesta elämästä:\n{verify_link}\n\nJos et siirtänyt tiliäsi, voit jättää tämän viestin huomiotta.",
    channel_verified_subject: "Ilmoituskanava vahvistettu - {hostname}",
    channel_verified_body: "Hei {handle},\n\n{channel} on vahvistettu ilmoituskanavaksi tilillesi palvelussa {hostname}.",
    channel_verification_subject: "Vahvista kanavasi - {hostname}",
    channel_verification_body: "Vahvistuskoodisi on:\n{code}\n\nTai vahvista suoraan:\n{verify_link}",
};

static STRINGS_FR: NotificationStrings = NotificationStrings {
    welcome_subject: "Bienvenue sur {hostname}",
    welcome_body: "Bienvenue sur {hostname} !\n\nVotre identifiant est : @{handle}\n\nMerci de nous avoir rejoint.",
    password_reset_subject: "Réinitialisation du mot de passe - {hostname}",
    password_reset_body: "Bonjour @{handle},\n\nVotre code de réinitialisation du mot de passe est : {code}\n\nCe code expirera dans {valid_for}.\n\nSi vous n'avez pas demandé cela, veuillez ignorer ce message.",
    email_update_subject: "Confirmer votre nouvelle adresse e-mail - {hostname}",
    email_update_confirmation_body: "Bonjour @{handle},\n\nVotre code de vérification est :\n{code}\n\nCopiez le code ci-dessus et saisissez-le ici :\n{verify_page}\n\nCe code expirera dans {valid_for}.\n\nOu si vous aimez vivre dangereusement :\n{verify_link}\n\nSi vous n'avez pas demandé cela, veuillez ignorer cet e-mail.",
    email_update_approval_body: "Bonjour @{handle},\n\nVotre code de vérification est :\n{code}\n\nCopiez le code ci-dessus et saisissez-le ici :\n{verify_page}\n\nCe code expirera dans {valid_for}.\n\nSi vous n'avez pas demandé cela, veuillez ignorer cet e-mail.",
    account_deletion_subject: "Demande de suppression de compte - {hostname}",
    account_deletion_body: "Bonjour @{handle},\n\nVotre code de confirmation de suppression de compte est : {code}\n\nCe code expirera dans {valid_for}.\n\nSi vous n'avez pas demandé cela, sécurisez votre compte immédiatement.",
    plc_operation_subject: "{hostname} - Jeton d'opération PLC",
    plc_operation_body: "Bonjour @{handle},\n\nVous avez demandé à signer une opération PLC pour votre compte.\n\nVotre jeton de vérification est : {token}\n\nCe jeton expirera dans {valid_for}.\n\nSi vous n'avez pas demandé cela, vous pouvez ignorer ce message en toute sécurité.",
    two_factor_code_subject: "Vérification de connexion - {hostname}",
    two_factor_code_body: "Bonjour @{handle},\n\nVotre code de vérification de connexion est : {code}\n\nCe code expirera dans {valid_for}.\n\nSi vous n'avez pas demandé cela, sécurisez votre compte immédiatement.",
    passkey_recovery_subject: "Récupération de compte - {hostname}",
    passkey_recovery_body: "Bonjour @{handle},\n\nVous avez demandé la récupération de votre compte à clé d'accès uniquement.\n\nCliquez sur le lien ci-dessous pour définir un mot de passe temporaire et retrouver l'accès :\n{url}\n\nCe lien expirera dans {valid_for}.\n\nSi vous n'avez pas demandé cela, veuillez ignorer ce message. Votre compte reste sécurisé.",
    signup_verification_subject: "Vérifier votre compte - {hostname}",
    signup_verification_body: "Bienvenue ! Votre code de vérification est :\n{code}\n\nCopiez le code ci-dessus et saisissez-le ici :\n{verify_page}\n\nCe code expirera dans {valid_for}.\n\nOu si vous aimez vivre dangereusement :\n{verify_link}\n\nSi vous n'avez pas créé de compte sur {hostname}, veuillez ignorer ce message.",
    legacy_login_subject: "Alerte de sécurité : Connexion classique détectée - {hostname}",
    legacy_login_body: "Bonjour @{handle},\n\nUne connexion à votre compte a été détectée via une application classique (comme Bluesky) qui ne prend pas en charge la vérification TOTP.\n\nDétails :\n- Date : {timestamp}\n- Adresse IP : {ip}\n\nVotre protection TOTP a été contournée pour cette connexion. La session dispose de permissions limitées pour les opérations sensibles.\n\nSi ce n'était pas vous :\n1. Changez votre mot de passe immédiatement\n2. Vérifiez vos sessions actives\n3. Envisagez de désactiver les connexions d'applications classiques dans vos paramètres de sécurité\n\nRestez vigilant,\n{hostname}",
    migration_verification_subject: "Vérifier votre compte - {hostname}",
    migration_verification_body: "Bienvenue sur {hostname} !\n\nVotre compte a été migré avec succès. Pour finaliser la configuration, veuillez vérifier votre compte.\n\nVotre code de vérification est :\n{code}\n\nCopiez le code ci-dessus et saisissez-le ici :\n{verify_page}\n\nCe code expirera dans {valid_for}.\n\nOu si vous aimez vivre dangereusement :\n{verify_link}\n\nSi vous n'avez pas migré votre compte, veuillez ignorer ce message.",
    channel_verified_subject: "Canal de notification vérifié - {hostname}",
    channel_verified_body: "Bonjour {handle},\n\n{channel} a été vérifié comme canal de notification pour votre compte sur {hostname}.",
    channel_verification_subject: "Vérifier votre canal - {hostname}",
    channel_verification_body: "Votre code de vérification est :\n{code}\n\nOu vérifiez directement :\n{verify_link}",
};

#[cfg(test)]
mod tests {
    use super::*;

    fn placeholders(template: &str) -> Vec<&str> {
        let mut found = template
            .split('{')
            .skip(1)
            .filter_map(|rest| rest.split('}').next())
            .filter(|name| !name.is_empty())
            .collect::<Vec<_>>();
        found.sort_unstable();
        found
    }

    #[test]
    fn every_locale_returns_declared_placeholders() {
        Locale::ALL.iter().for_each(|locale| {
            get_strings(*locale)
                .template_fields_and_texts()
                .iter()
                .for_each(|(field, text)| {
                    let mut declared = declared_placeholders(field).to_vec();
                    declared.sort_unstable();
                    assert_eq!(
                        placeholders(text),
                        declared,
                        "{} {} shows placeholders that our templates macro thingy doesn't have. Where did those come from?",
                        locale,
                        field
                    );
                });
        });
    }

    #[test]
    fn render_substitutes_values_wo_rescanning() {
        let body = render(
            STRINGS_EN.two_factor_code_body,
            &[
                ("handle", "x{code}y"),
                ("code", "123"),
                ("valid_for", "5 minutes"),
            ],
        );
        assert!(
            body.contains("x{code}y"),
            "subbed value must be verbatim: {body}"
        );
        assert!(body.contains("Your sign-in verification code is: 123"));
        assert!(body.contains("expire in 5 minutes"));
    }

    #[test]
    fn render_unknown_placeholders_verbatim() {
        let vars = [("known", "x")];
        assert_eq!(
            render("a {known} b {unknown} c", &vars),
            "a x b {unknown} c"
        );
        assert_eq!(
            render("dangling { open brace", &vars),
            "dangling { open brace"
        );
        assert_eq!(render("no braces at all", &vars), "no braces at all");
    }

    #[test]
    fn welcome_body_renders_completely() {
        let handle: Handle = "oys.nel.pet".parse().unwrap();
        let body = get_strings(Locale::En)
            .welcome_body(
                Locale::En,
                &WelcomeBody {
                    hostname: "nel.pet",
                    handle: &handle,
                },
            )
            .unwrap();
        assert_eq!(
            body,
            "Welcome to nel.pet!\n\nYour handle is: @oys.nel.pet\n\nThank you for joining us."
        );
    }

    #[test]
    fn localized_durations_match_each_grammar() {
        use std::time::Duration;
        let en = |secs| localized_duration(Locale::En, Duration::from_secs(secs));
        assert_eq!(en(300), "5 minutes");
        assert_eq!(en(60), "1 minute");
        assert_eq!(en(1800), "30 minutes");
        assert_eq!(en(3600), "1 hour");
        assert_eq!(en(48 * 3600), "48 hours");
        assert_eq!(
            localized_duration(Locale::Fi, Duration::from_secs(600)),
            "10 minuutissa"
        );
        assert_eq!(
            localized_duration(Locale::Fi, Duration::from_secs(3600)),
            "1 tunnissa"
        );
        assert_eq!(
            localized_duration(Locale::Ja, Duration::from_secs(600)),
            "10分"
        );
        assert_eq!(
            localized_duration(Locale::Zh, Duration::from_secs(48 * 3600)),
            "48小时"
        );
        assert_eq!(
            localized_duration(Locale::Sv, Duration::from_secs(3600)),
            // I keep mixing up whether it's timme or stund
            "1 timme"
        );
    }
}
