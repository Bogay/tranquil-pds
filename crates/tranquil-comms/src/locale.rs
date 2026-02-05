pub const DEFAULT_LOCALE: &str = "en";
pub const VALID_LOCALES: &[&str] = &["en", "zh", "ja", "ko", "sv", "fi"];

pub fn validate_locale(locale: &str) -> &str {
    if VALID_LOCALES.contains(&locale) {
        locale
    } else {
        DEFAULT_LOCALE
    }
}

pub struct NotificationStrings {
    pub welcome_subject: &'static str,
    pub welcome_body: &'static str,
    pub password_reset_subject: &'static str,
    pub password_reset_body: &'static str,
    pub email_update_subject: &'static str,
    pub email_update_body: &'static str,
    pub short_token_body: &'static str,
    pub account_deletion_subject: &'static str,
    pub account_deletion_body: &'static str,
    pub plc_operation_subject: &'static str,
    pub plc_operation_body: &'static str,
    pub two_factor_code_subject: &'static str,
    pub two_factor_code_body: &'static str,
    pub passkey_recovery_subject: &'static str,
    pub passkey_recovery_body: &'static str,
    pub signup_verification_subject: &'static str,
    pub signup_verification_body: &'static str,
    pub legacy_login_subject: &'static str,
    pub legacy_login_body: &'static str,
    pub migration_verification_subject: &'static str,
    pub migration_verification_body: &'static str,
    pub channel_verified_subject: &'static str,
    pub channel_verified_body: &'static str,
    pub channel_verification_subject: &'static str,
    pub channel_verification_body: &'static str,
}

pub fn get_strings(locale: &str) -> &'static NotificationStrings {
    match validate_locale(locale) {
        "zh" => &STRINGS_ZH,
        "ja" => &STRINGS_JA,
        "ko" => &STRINGS_KO,
        "sv" => &STRINGS_SV,
        "fi" => &STRINGS_FI,
        _ => &STRINGS_EN,
    }
}

static STRINGS_EN: NotificationStrings = NotificationStrings {
    welcome_subject: "Welcome to {hostname}",
    welcome_body: "Welcome to {hostname}!\n\nYour handle is: @{handle}\n\nThank you for joining us.",
    password_reset_subject: "Password Reset - {hostname}",
    password_reset_body: "Hello @{handle},\n\nYour password reset code is: {code}\n\nThis code will expire in 10 minutes.\n\nIf you did not request this, please ignore this message.",
    email_update_subject: "Confirm your new email - {hostname}",
    email_update_body: "Hello @{handle},\n\nYour verification code is:\n{code}\n\nCopy the code above and enter it at:\n{verify_page}\n\nThis code will expire in 10 minutes.\n\nOr if you like to live dangerously:\n{verify_link}\n\nIf you did not request this, please ignore this email.",
    short_token_body: "Hello @{handle},\n\nYour verification code is:\n{code}\n\nThis code will expire in 15 minutes.\n\nIf you did not request this, please ignore this email.",
    account_deletion_subject: "Account Deletion Request - {hostname}",
    account_deletion_body: "Hello @{handle},\n\nYour account deletion confirmation code is: {code}\n\nThis code will expire in 10 minutes.\n\nIf you did not request this, please secure your account immediately.",
    plc_operation_subject: "{hostname} - PLC Operation Token",
    plc_operation_body: "Hello @{handle},\n\nYou requested to sign a PLC operation for your account.\n\nYour verification token is: {token}\n\nThis token will expire in 10 minutes.\n\nIf you did not request this, you can safely ignore this message.",
    two_factor_code_subject: "Sign-in Verification - {hostname}",
    two_factor_code_body: "Hello @{handle},\n\nYour sign-in verification code is: {code}\n\nThis code will expire in 10 minutes.\n\nIf you did not request this, please secure your account immediately.",
    passkey_recovery_subject: "Account Recovery - {hostname}",
    passkey_recovery_body: "Hello @{handle},\n\nYou requested to recover your passkey-only account.\n\nClick the link below to set a temporary password and regain access:\n{url}\n\nThis link will expire in 1 hour.\n\nIf you did not request this, please ignore this message. Your account remains secure.",
    signup_verification_subject: "Verify your account - {hostname}",
    signup_verification_body: "Welcome! Your verification code is:\n{code}\n\nCopy the code above and enter it at:\n{verify_page}\n\nThis code will expire in 30 minutes.\n\nOr if you like to live dangerously:\n{verify_link}\n\nIf you did not create an account on {hostname}, please ignore this message.",
    legacy_login_subject: "Security Alert: Legacy Login Detected - {hostname}",
    legacy_login_body: "Hello @{handle},\n\nA login to your account was detected using a legacy app (like Bluesky) that doesn't support TOTP verification.\n\nDetails:\n- Time: {timestamp}\n- IP Address: {ip}\n\nYour TOTP protection was bypassed for this login. The session has limited permissions for sensitive operations.\n\nIf this wasn't you, please:\n1. Change your password immediately\n2. Review your active sessions\n3. Consider disabling legacy app logins in your security settings\n\nStay safe,\n{hostname}",
    migration_verification_subject: "Verify your email - {hostname}",
    migration_verification_body: "Welcome to {hostname}!\n\nYour account has been migrated successfully. To complete the setup, please verify your email address.\n\nYour verification code is:\n{code}\n\nCopy the code above and enter it at:\n{verify_page}\n\nThis code will expire in 48 hours.\n\nOr if you like to live dangerously:\n{verify_link}\n\nIf you did not migrate your account, please ignore this email.",
    channel_verified_subject: "Channel verified - {hostname}",
    channel_verified_body: "Hello {handle},\n\n{channel} has been verified as a notification channel for your account on {hostname}.",
    channel_verification_subject: "Verify your channel - {hostname}",
    channel_verification_body: "Your verification code is:\n{code}\n\nOr verify directly:\n{verify_link}",
};

static STRINGS_ZH: NotificationStrings = NotificationStrings {
    welcome_subject: "欢迎加入 {hostname}",
    welcome_body: "欢迎加入 {hostname}！\n\n您的用户名是：@{handle}\n\n感谢您的加入。",
    password_reset_subject: "密码重置 - {hostname}",
    password_reset_body: "您好 @{handle}，\n\n您的密码重置验证码是：{code}\n\n此验证码将在10分钟后过期。\n\n如果这不是您的操作，请忽略此消息。",
    email_update_subject: "确认您的新邮箱 - {hostname}",
    email_update_body: "您好 @{handle}，\n\n您的验证码是：\n{code}\n\n复制上述验证码并在此输入：\n{verify_page}\n\n此验证码将在10分钟后过期。\n\n或者直接点击链接：\n{verify_link}\n\n如果这不是您的操作，请忽略此邮件。",
    short_token_body: "您好 @{handle}，\n\n您的验证码是：\n{code}\n\n此验证码将在15分钟后过期。\n\n如果这不是您的操作，请忽略此邮件。",
    account_deletion_subject: "账户删除请求 - {hostname}",
    account_deletion_body: "您好 @{handle}，\n\n您的账户删除确认码是：{code}\n\n此验证码将在10分钟后过期。\n\n如果这不是您的操作，请立即保护您的账户。",
    plc_operation_subject: "{hostname} - PLC 操作令牌",
    plc_operation_body: "您好 @{handle}，\n\n您请求为账户签署 PLC 操作。\n\n您的验证令牌是：{token}\n\n此令牌将在10分钟后过期。\n\n如果这不是您的操作，您可以安全地忽略此消息。",
    two_factor_code_subject: "登录验证 - {hostname}",
    two_factor_code_body: "您好 @{handle}，\n\n您的登录验证码是：{code}\n\n此验证码将在10分钟后过期。\n\n如果这不是您的操作，请立即保护您的账户。",
    passkey_recovery_subject: "账户恢复 - {hostname}",
    passkey_recovery_body: "您好 @{handle}，\n\n您请求恢复仅通行密钥账户的访问权限。\n\n点击以下链接设置临时密码并恢复访问：\n{url}\n\n此链接将在1小时后过期。\n\n如果这不是您的操作，请忽略此消息。您的账户仍然安全。",
    signup_verification_subject: "验证您的账户 - {hostname}",
    signup_verification_body: "欢迎！您的验证码是：\n{code}\n\n复制上述验证码并在此输入：\n{verify_page}\n\n此验证码将在30分钟后过期。\n\n或者直接点击链接：\n{verify_link}\n\n如果您没有在 {hostname} 上创建账户，请忽略此消息。",
    legacy_login_subject: "安全提醒：检测到传统应用登录 - {hostname}",
    legacy_login_body: "您好 @{handle}，\n\n检测到使用不支持 TOTP 验证的传统应用（如 Bluesky）登录您的账户。\n\n详细信息：\n- 时间：{timestamp}\n- IP 地址：{ip}\n\n此次登录绕过了 TOTP 保护。该会话对敏感操作的权限有限。\n\n如果这不是您的操作，请：\n1. 立即更改密码\n2. 检查您的活跃会话\n3. 考虑在安全设置中禁用传统应用登录\n\n请注意安全，\n{hostname}",
    migration_verification_subject: "验证您的邮箱 - {hostname}",
    migration_verification_body: "欢迎来到 {hostname}！\n\n您的账户已成功迁移。要完成设置，请验证您的邮箱地址。\n\n您的验证码是：\n{code}\n\n复制上述验证码并在此输入：\n{verify_page}\n\n此验证码将在 48 小时后过期。\n\n或者直接点击链接：\n{verify_link}\n\n如果您没有迁移账户，请忽略此邮件。",
    channel_verified_subject: "通知渠道已验证 - {hostname}",
    channel_verified_body: "您好 {handle}，\n\n{channel} 已被验证为您在 {hostname} 上的通知渠道。",
    channel_verification_subject: "验证您的渠道 - {hostname}",
    channel_verification_body: "您的验证码是：\n{code}\n\n或直接验证：\n{verify_link}",
};

static STRINGS_JA: NotificationStrings = NotificationStrings {
    welcome_subject: "{hostname} へようこそ",
    welcome_body: "{hostname} へようこそ！\n\nお客様のハンドル：@{handle}\n\nご登録ありがとうございます。",
    password_reset_subject: "パスワードリセット - {hostname}",
    password_reset_body: "@{handle} 様\n\nパスワードリセットコードは：{code}\n\nこのコードは10分後に期限切れとなります。\n\nこの操作に心当たりがない場合は、このメッセージを無視してください。",
    email_update_subject: "新しいメールアドレスの確認 - {hostname}",
    email_update_body: "@{handle} 様\n\n確認コードは：\n{code}\n\n上記のコードをコピーして、こちらで入力してください：\n{verify_page}\n\nこのコードは10分後に期限切れとなります。\n\n自己責任でワンクリック認証：\n{verify_link}\n\nこの操作に心当たりがない場合は、このメールを無視してください。",
    short_token_body: "@{handle} 様\n\n確認コードは：\n{code}\n\nこのコードは15分後に期限切れとなります。\n\nこの操作に心当たりがない場合は、このメールを無視してください。",
    account_deletion_subject: "アカウント削除リクエスト - {hostname}",
    account_deletion_body: "@{handle} 様\n\nアカウント削除の確認コードは：{code}\n\nこのコードは10分後に期限切れとなります。\n\nこの操作に心当たりがない場合は、直ちにアカウントを保護してください。",
    plc_operation_subject: "{hostname} - PLC 操作トークン",
    plc_operation_body: "@{handle} 様\n\nアカウントの PLC 操作の署名をリクエストされました。\n\n認証トークンは：{token}\n\nこのトークンは10分後に期限切れとなります。\n\nこの操作に心当たりがない場合は、このメッセージを無視しても問題ありません。",
    two_factor_code_subject: "ログイン認証 - {hostname}",
    two_factor_code_body: "@{handle} 様\n\nログイン認証コードは：{code}\n\nこのコードは10分後に期限切れとなります。\n\nこの操作に心当たりがない場合は、直ちにアカウントを保護してください。",
    passkey_recovery_subject: "アカウント復旧 - {hostname}",
    passkey_recovery_body: "@{handle} 様\n\nパスキー専用アカウントの復旧をリクエストされました。\n\n以下のリンクをクリックして一時パスワードを設定し、アクセスを回復してください：\n{url}\n\nこのリンクは1時間後に期限切れとなります。\n\nこの操作に心当たりがない場合は、このメッセージを無視してください。アカウントは安全なままです。",
    signup_verification_subject: "アカウント認証 - {hostname}",
    signup_verification_body: "ようこそ！認証コードは：\n{code}\n\n上記のコードをコピーして、こちらで入力してください：\n{verify_page}\n\nこのコードは30分後に期限切れとなります。\n\n自己責任でワンクリック認証：\n{verify_link}\n\n{hostname} でアカウントを作成していない場合は、このメールを無視してください。",
    legacy_login_subject: "セキュリティ警告：レガシーログインを検出 - {hostname}",
    legacy_login_body: "@{handle} 様\n\nTOTP 認証に対応していないレガシーアプリ（Bluesky など）からのログインが検出されました。\n\n詳細：\n- 時刻：{timestamp}\n- IP アドレス：{ip}\n\nこのログインでは TOTP 保護がバイパスされました。このセッションは機密操作に対する権限が制限されています。\n\n心当たりがない場合は：\n1. 直ちにパスワードを変更してください\n2. アクティブなセッションを確認してください\n3. セキュリティ設定でレガシーアプリのログインを無効にすることを検討してください\n\nご注意ください。\n{hostname}",
    migration_verification_subject: "メールアドレスの認証 - {hostname}",
    migration_verification_body: "{hostname} へようこそ！\n\nアカウントの移行が完了しました。設定を完了するには、メールアドレスを認証してください。\n\n認証コードは：\n{code}\n\n上記のコードをコピーして、こちらで入力してください：\n{verify_page}\n\nこのコードは48時間後に期限切れとなります。\n\n自己責任でワンクリック認証：\n{verify_link}\n\nアカウントを移行していない場合は、このメールを無視してください。",
    channel_verified_subject: "通知チャンネル認証完了 - {hostname}",
    channel_verified_body: "{handle} 様\n\n{channel} が {hostname} の通知チャンネルとして認証されました。",
    channel_verification_subject: "チャンネルを認証 - {hostname}",
    channel_verification_body: "認証コードは：\n{code}\n\n直接認証：\n{verify_link}",
};

static STRINGS_KO: NotificationStrings = NotificationStrings {
    welcome_subject: "{hostname}에 오신 것을 환영합니다",
    welcome_body: "{hostname}에 오신 것을 환영합니다!\n\n회원님의 핸들은: @{handle}\n\n가입해 주셔서 감사합니다.",
    password_reset_subject: "비밀번호 재설정 - {hostname}",
    password_reset_body: "안녕하세요 @{handle}님,\n\n비밀번호 재설정 코드는: {code}\n\n이 코드는 10분 후에 만료됩니다.\n\n요청하지 않으셨다면 이 메시지를 무시하세요.",
    email_update_subject: "새 이메일 주소 확인 - {hostname}",
    email_update_body: "안녕하세요 @{handle}님,\n\n인증 코드는:\n{code}\n\n위 코드를 복사하여 여기에 입력하세요:\n{verify_page}\n\n이 코드는 10분 후에 만료됩니다.\n\n위험을 감수하고 원클릭 인증:\n{verify_link}\n\n요청하지 않으셨다면 이 이메일을 무시하세요.",
    short_token_body: "안녕하세요 @{handle}님,\n\n인증 코드는:\n{code}\n\n이 코드는 15분 후에 만료됩니다.\n\n요청하지 않으셨다면 이 이메일을 무시하세요.",
    account_deletion_subject: "계정 삭제 요청 - {hostname}",
    account_deletion_body: "안녕하세요 @{handle}님,\n\n계정 삭제 확인 코드는: {code}\n\n이 코드는 10분 후에 만료됩니다.\n\n요청하지 않으셨다면 즉시 계정을 보호하세요.",
    plc_operation_subject: "{hostname} - PLC 작업 토큰",
    plc_operation_body: "안녕하세요 @{handle}님,\n\n계정의 PLC 작업 서명을 요청하셨습니다.\n\n인증 토큰은: {token}\n\n이 토큰은 10분 후에 만료됩니다.\n\n요청하지 않으셨다면 이 메시지를 안전하게 무시하셔도 됩니다.",
    two_factor_code_subject: "로그인 인증 - {hostname}",
    two_factor_code_body: "안녕하세요 @{handle}님,\n\n로그인 인증 코드는: {code}\n\n이 코드는 10분 후에 만료됩니다.\n\n요청하지 않으셨다면 즉시 계정을 보호하세요.",
    passkey_recovery_subject: "계정 복구 - {hostname}",
    passkey_recovery_body: "안녕하세요 @{handle}님,\n\n패스키 전용 계정 복구를 요청하셨습니다.\n\n아래 링크를 클릭하여 임시 비밀번호를 설정하고 액세스를 복구하세요:\n{url}\n\n이 링크는 1시간 후에 만료됩니다.\n\n요청하지 않으셨다면 이 메시지를 무시하세요. 계정은 안전하게 유지됩니다.",
    signup_verification_subject: "계정 인증 - {hostname}",
    signup_verification_body: "환영합니다! 인증 코드는:\n{code}\n\n위 코드를 복사하여 여기에 입력하세요:\n{verify_page}\n\n이 코드는 30분 후에 만료됩니다.\n\n위험을 감수하고 원클릭 인증:\n{verify_link}\n\n{hostname}에서 계정을 만들지 않았다면 이 이메일을 무시하세요.",
    legacy_login_subject: "보안 알림: 레거시 로그인 감지 - {hostname}",
    legacy_login_body: "안녕하세요 @{handle}님,\n\nTOTP 인증을 지원하지 않는 레거시 앱(예: Bluesky)을 사용한 로그인이 감지되었습니다.\n\n세부 정보:\n- 시간: {timestamp}\n- IP 주소: {ip}\n\n이 로그인에서 TOTP 보호가 우회되었습니다. 이 세션은 민감한 작업에 대한 권한이 제한됩니다.\n\n본인이 아닌 경우:\n1. 즉시 비밀번호를 변경하세요\n2. 활성 세션을 검토하세요\n3. 보안 설정에서 레거시 앱 로그인 비활성화를 고려하세요\n\n{hostname} 드림",
    migration_verification_subject: "이메일 인증 - {hostname}",
    migration_verification_body: "{hostname}에 오신 것을 환영합니다!\n\n계정 마이그레이션이 완료되었습니다. 설정을 완료하려면 이메일 주소를 인증하세요.\n\n인증 코드는:\n{code}\n\n위 코드를 복사하여 여기에 입력하세요:\n{verify_page}\n\n이 코드는 48시간 후에 만료됩니다.\n\n위험을 감수하고 원클릭 인증:\n{verify_link}\n\n계정을 마이그레이션하지 않았다면 이 이메일을 무시하세요.",
    channel_verified_subject: "알림 채널 인증 완료 - {hostname}",
    channel_verified_body: "안녕하세요 {handle}님,\n\n{channel}이(가) {hostname}의 알림 채널로 인증되었습니다.",
    channel_verification_subject: "채널 인증 - {hostname}",
    channel_verification_body: "인증 코드:\n{code}\n\n직접 인증:\n{verify_link}",
};

static STRINGS_SV: NotificationStrings = NotificationStrings {
    welcome_subject: "Välkommen till {hostname}",
    welcome_body: "Välkommen till {hostname}!\n\nDitt användarnamn är: @{handle}\n\nTack för att du gick med.",
    password_reset_subject: "Lösenordsåterställning - {hostname}",
    password_reset_body: "Hej @{handle},\n\nDin kod för lösenordsåterställning är: {code}\n\nDenna kod upphör om 10 minuter.\n\nOm du inte begärde detta kan du ignorera detta meddelande.",
    email_update_subject: "Bekräfta din nya e-post - {hostname}",
    email_update_body: "Hej @{handle},\n\nDin verifieringskod är:\n{code}\n\nKopiera koden ovan och ange den på:\n{verify_page}\n\nDenna kod upphör om 10 minuter.\n\nEller om du gillar att leva farligt:\n{verify_link}\n\nOm du inte begärde detta kan du ignorera detta meddelande.",
    short_token_body: "Hej @{handle},\n\nDin verifieringskod är:\n{code}\n\nDenna kod upphör om 15 minuter.\n\nOm du inte begärde detta kan du ignorera detta meddelande.",
    account_deletion_subject: "Begäran om kontoradering - {hostname}",
    account_deletion_body: "Hej @{handle},\n\nDin bekräftelsekod för kontoradering är: {code}\n\nDenna kod upphör om 10 minuter.\n\nOm du inte begärde detta, skydda ditt konto omedelbart.",
    plc_operation_subject: "{hostname} - PLC-operationstoken",
    plc_operation_body: "Hej @{handle},\n\nDu begärde att signera en PLC-operation för ditt konto.\n\nDin verifieringstoken är: {token}\n\nDenna token upphör om 10 minuter.\n\nOm du inte begärde detta kan du säkert ignorera detta meddelande.",
    two_factor_code_subject: "Inloggningsverifiering - {hostname}",
    two_factor_code_body: "Hej @{handle},\n\nDin inloggningsverifieringskod är: {code}\n\nDenna kod upphör om 10 minuter.\n\nOm du inte begärde detta, skydda ditt konto omedelbart.",
    passkey_recovery_subject: "Kontoåterställning - {hostname}",
    passkey_recovery_body: "Hej @{handle},\n\nDu begärde att återställa ditt endast nyckelkonto.\n\nKlicka på länken nedan för att ställa in ett tillfälligt lösenord och återfå åtkomst:\n{url}\n\nDenna länk upphör om 1 timme.\n\nOm du inte begärde detta kan du ignorera detta meddelande. Ditt konto förblir säkert.",
    signup_verification_subject: "Verifiera ditt konto - {hostname}",
    signup_verification_body: "Välkommen! Din verifieringskod är:\n{code}\n\nKopiera koden ovan och ange den på:\n{verify_page}\n\nDenna kod upphör om 30 minuter.\n\nEller om du gillar att leva farligt:\n{verify_link}\n\nOm du inte skapade ett konto på {hostname}, ignorera detta meddelande.",
    legacy_login_subject: "Säkerhetsvarning: Äldre inloggning upptäckt - {hostname}",
    legacy_login_body: "Hej @{handle},\n\nEn inloggning till ditt konto upptäcktes med en äldre app (som Bluesky) som inte stöder TOTP-verifiering.\n\nDetaljer:\n- Tid: {timestamp}\n- IP-adress: {ip}\n\nDitt TOTP-skydd kringgicks för denna inloggning. Sessionen har begränsade behörigheter för känsliga operationer.\n\nOm detta inte var du:\n1. Ändra ditt lösenord omedelbart\n2. Granska dina aktiva sessioner\n3. Överväg att inaktivera äldre appinloggningar i dina säkerhetsinställningar\n\nVar försiktig,\n{hostname}",
    migration_verification_subject: "Verifiera din e-post - {hostname}",
    migration_verification_body: "Välkommen till {hostname}!\n\nDitt konto har migrerats framgångsrikt. För att slutföra installationen, verifiera din e-postadress.\n\nDin verifieringskod är:\n{code}\n\nKopiera koden ovan och ange den på:\n{verify_page}\n\nDenna kod upphör om 48 timmar.\n\nEller om du gillar att leva farligt:\n{verify_link}\n\nOm du inte migrerade ditt konto kan du ignorera detta meddelande.",
    channel_verified_subject: "Aviseringskanal verifierad - {hostname}",
    channel_verified_body: "Hej {handle},\n\n{channel} har verifierats som aviseringskanal för ditt konto på {hostname}.",
    channel_verification_subject: "Verifiera din kanal - {hostname}",
    channel_verification_body: "Din verifieringskod är:\n{code}\n\nEller verifiera direkt:\n{verify_link}",
};

static STRINGS_FI: NotificationStrings = NotificationStrings {
    welcome_subject: "Tervetuloa palveluun {hostname}",
    welcome_body: "Tervetuloa palveluun {hostname}!\n\nKäyttäjänimesi on: @{handle}\n\nKiitos liittymisestä.",
    password_reset_subject: "Salasanan palautus - {hostname}",
    password_reset_body: "Hei @{handle},\n\nSalasanan palautuskoodisi on: {code}\n\nTämä koodi vanhenee 10 minuutissa.\n\nJos et pyytänyt tätä, voit jättää tämän viestin huomiotta.",
    email_update_subject: "Vahvista uusi sähköpostisi - {hostname}",
    email_update_body: "Hei @{handle},\n\nVahvistuskoodisi on:\n{code}\n\nKopioi koodi yllä ja syötä se osoitteessa:\n{verify_page}\n\nTämä koodi vanhenee 10 minuutissa.\n\nTai jos pidät vaarallisesta elämästä:\n{verify_link}\n\nJos et pyytänyt tätä, voit jättää tämän viestin huomiotta.",
    short_token_body: "Hei @{handle},\n\nVahvistuskoodisi on:\n{code}\n\nTämä koodi vanhenee 15 minuutissa.\n\nJos et pyytänyt tätä, voit jättää tämän viestin huomiotta.",
    account_deletion_subject: "Tilin poistopyyntö - {hostname}",
    account_deletion_body: "Hei @{handle},\n\nTilin poiston vahvistuskoodisi on: {code}\n\nTämä koodi vanhenee 10 minuutissa.\n\nJos et pyytänyt tätä, suojaa tilisi välittömästi.",
    plc_operation_subject: "{hostname} - PLC-toimintotunniste",
    plc_operation_body: "Hei @{handle},\n\nPyysit allekirjoittamaan PLC-toiminnon tilillesi.\n\nVahvistustunnisteesi on: {token}\n\nTämä tunniste vanhenee 10 minuutissa.\n\nJos et pyytänyt tätä, voit turvallisesti jättää tämän viestin huomiotta.",
    two_factor_code_subject: "Kirjautumisen vahvistus - {hostname}",
    two_factor_code_body: "Hei @{handle},\n\nKirjautumisen vahvistuskoodisi on: {code}\n\nTämä koodi vanhenee 10 minuutissa.\n\nJos et pyytänyt tätä, suojaa tilisi välittömästi.",
    passkey_recovery_subject: "Tilin palautus - {hostname}",
    passkey_recovery_body: "Hei @{handle},\n\nPyysit palauttamaan vain pääsyavaintilisi.\n\nKlikkaa alla olevaa linkkiä asettaaksesi väliaikaisen salasanan ja saadaksesi pääsyn takaisin:\n{url}\n\nTämä linkki vanhenee tunnissa.\n\nJos et pyytänyt tätä, voit jättää tämän viestin huomiotta. Tilisi pysyy turvassa.",
    signup_verification_subject: "Vahvista tilisi - {hostname}",
    signup_verification_body: "Tervetuloa! Vahvistuskoodisi on:\n{code}\n\nKopioi koodi yllä ja syötä se osoitteessa:\n{verify_page}\n\nTämä koodi vanhenee 30 minuutissa.\n\nTai jos pidät vaarallisesta elämästä:\n{verify_link}\n\nJos et luonut tiliä palveluun {hostname}, jätä tämä viesti huomiotta.",
    legacy_login_subject: "Turvallisuushälytys: Vanha kirjautuminen havaittu - {hostname}",
    legacy_login_body: "Hei @{handle},\n\nTilillesi havaittiin kirjautuminen vanhalla sovelluksella (kuten Bluesky), joka ei tue TOTP-vahvistusta.\n\nTiedot:\n- Aika: {timestamp}\n- IP-osoite: {ip}\n\nTOTP-suojauksesi ohitettiin tässä kirjautumisessa. Istunnolla on rajoitetut oikeudet arkaluontoisiin toimintoihin.\n\nJos tämä et ollut sinä:\n1. Vaihda salasanasi välittömästi\n2. Tarkista aktiiviset istuntosi\n3. Harkitse vanhojen sovellusten kirjautumisen poistamista käytöstä turvallisuusasetuksissa\n\nOle varovainen,\n{hostname}",
    migration_verification_subject: "Vahvista sähköpostisi - {hostname}",
    migration_verification_body: "Tervetuloa palveluun {hostname}!\n\nTilisi on siirretty onnistuneesti. Viimeistele asennus vahvistamalla sähköpostiosoitteesi.\n\nVahvistuskoodisi on:\n{code}\n\nKopioi koodi yllä ja syötä se osoitteessa:\n{verify_page}\n\nTämä koodi vanhenee 48 tunnissa.\n\nTai jos pidät vaarallisesta elämästä:\n{verify_link}\n\nJos et siirtänyt tiliäsi, voit jättää tämän viestin huomiotta.",
    channel_verified_subject: "Ilmoituskanava vahvistettu - {hostname}",
    channel_verified_body: "Hei {handle},\n\n{channel} on vahvistettu ilmoituskanavaksi tilillesi palvelussa {hostname}.",
    channel_verification_subject: "Vahvista kanavasi - {hostname}",
    channel_verification_body: "Vahvistuskoodisi on:\n{code}\n\nTai vahvista suoraan:\n{verify_link}",
};

pub fn format_message(template: &str, vars: &[(&str, &str)]) -> String {
    vars.iter()
        .fold(template.to_string(), |result, (key, value)| {
            result.replace(&format!("{{{}}}", key), value)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_locale() {
        assert_eq!(validate_locale("en"), "en");
        assert_eq!(validate_locale("zh"), "zh");
        assert_eq!(validate_locale("ja"), "ja");
        assert_eq!(validate_locale("ko"), "ko");
        assert_eq!(validate_locale("invalid"), DEFAULT_LOCALE);
        assert_eq!(validate_locale(""), DEFAULT_LOCALE);
    }

    #[test]
    fn test_format_message() {
        let template = "Hello {name}, your code is {code}";
        let result = format_message(template, &[("name", "Alice"), ("code", "123456")]);
        assert_eq!(result, "Hello Alice, your code is 123456");
    }

    #[test]
    fn test_get_strings() {
        let en = get_strings("en");
        assert!(en.welcome_subject.contains("{hostname}"));

        let zh = get_strings("zh");
        assert!(zh.welcome_subject.contains("{hostname}"));
        assert!(zh.welcome_body.contains("欢迎"));
    }
}
