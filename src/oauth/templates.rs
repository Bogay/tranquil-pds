use chrono::{DateTime, Utc};

fn base_styles() -> &'static str {
    r#"
        :root {
            --primary: #0085ff;
            --primary-hover: #0077e6;
            --primary-contrast: #ffffff;
            --primary-100: #dbeafe;
            --primary-400: #60a5fa;
            --primary-600-30: rgba(37, 99, 235, 0.3);
            --contrast-0: #ffffff;
            --contrast-25: #f8f9fa;
            --contrast-50: #f1f3f5;
            --contrast-100: #e9ecef;
            --contrast-200: #dee2e6;
            --contrast-300: #ced4da;
            --contrast-400: #adb5bd;
            --contrast-500: #6b7280;
            --contrast-600: #4b5563;
            --contrast-700: #374151;
            --contrast-800: #1f2937;
            --contrast-900: #111827;
            --error: #dc2626;
            --error-bg: #fef2f2;
            --success: #059669;
            --success-bg: #ecfdf5;
        }

        @media (prefers-color-scheme: dark) {
            :root {
                --contrast-0: #111827;
                --contrast-25: #1f2937;
                --contrast-50: #374151;
                --contrast-100: #4b5563;
                --contrast-200: #6b7280;
                --contrast-300: #9ca3af;
                --contrast-400: #d1d5db;
                --contrast-500: #e5e7eb;
                --contrast-600: #f3f4f6;
                --contrast-700: #f9fafb;
                --contrast-800: #ffffff;
                --contrast-900: #ffffff;
                --error-bg: #451a1a;
                --success-bg: #064e3b;
            }
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: var(--contrast-50);
            color: var(--contrast-900);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 1rem;
            line-height: 1.5;
        }

        .container {
            width: 100%;
            max-width: 400px;
        }

        .card {
            background: var(--contrast-0);
            border: 1px solid var(--contrast-100);
            border-radius: 0.75rem;
            padding: 1.5rem;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 8px 10px -6px rgba(0, 0, 0, 0.1);
        }

        @media (prefers-color-scheme: dark) {
            .card {
                box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.4), 0 8px 10px -6px rgba(0, 0, 0, 0.3);
            }
        }

        h1 {
            font-size: 1.5rem;
            font-weight: 600;
            color: var(--contrast-900);
            margin-bottom: 0.5rem;
        }

        .subtitle {
            color: var(--contrast-500);
            font-size: 0.875rem;
            margin-bottom: 1.5rem;
        }

        .subtitle strong {
            color: var(--contrast-700);
        }

        .client-info {
            background: var(--contrast-25);
            border-radius: 0.5rem;
            padding: 1rem;
            margin-bottom: 1.5rem;
        }

        .client-info .client-name {
            font-weight: 500;
            color: var(--contrast-900);
            display: block;
            margin-bottom: 0.25rem;
        }

        .client-info .scope {
            color: var(--contrast-500);
            font-size: 0.875rem;
        }

        .error-banner {
            background: var(--error-bg);
            color: var(--error);
            border-radius: 0.5rem;
            padding: 0.75rem 1rem;
            margin-bottom: 1rem;
            font-size: 0.875rem;
        }

        .form-group {
            margin-bottom: 1.25rem;
        }

        label {
            display: block;
            font-size: 0.875rem;
            font-weight: 500;
            color: var(--contrast-700);
            margin-bottom: 0.375rem;
        }

        input[type="text"],
        input[type="email"],
        input[type="password"] {
            width: 100%;
            padding: 0.625rem 0.875rem;
            border: 2px solid var(--contrast-200);
            border-radius: 0.375rem;
            font-size: 1rem;
            color: var(--contrast-900);
            background: var(--contrast-0);
            transition: border-color 0.15s, box-shadow 0.15s;
        }

        input[type="text"]:focus,
        input[type="email"]:focus,
        input[type="password"]:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px var(--primary-600-30);
        }

        input[type="text"]::placeholder,
        input[type="email"]::placeholder,
        input[type="password"]::placeholder {
            color: var(--contrast-400);
        }

        .checkbox-group {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            margin-bottom: 1.5rem;
        }

        .checkbox-group input[type="checkbox"] {
            width: 1.125rem;
            height: 1.125rem;
            accent-color: var(--primary);
        }

        .checkbox-group label {
            margin-bottom: 0;
            font-weight: normal;
            color: var(--contrast-600);
            cursor: pointer;
        }

        .buttons {
            display: flex;
            gap: 0.75rem;
        }

        .btn {
            flex: 1;
            padding: 0.625rem 1.25rem;
            border-radius: 0.375rem;
            font-size: 1rem;
            font-weight: 500;
            cursor: pointer;
            transition: background-color 0.15s, transform 0.1s;
            border: none;
            text-align: center;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            justify-content: center;
        }

        .btn:active {
            transform: scale(0.98);
        }

        .btn-primary {
            background: var(--primary);
            color: var(--primary-contrast);
        }

        .btn-primary:hover {
            background: var(--primary-hover);
        }

        .btn-primary:disabled {
            background: var(--primary-400);
            cursor: not-allowed;
        }

        .btn-secondary {
            background: var(--contrast-200);
            color: var(--contrast-800);
        }

        .btn-secondary:hover {
            background: var(--contrast-300);
        }

        .footer {
            text-align: center;
            margin-top: 1.5rem;
            font-size: 0.75rem;
            color: var(--contrast-400);
        }

        .accounts {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
            margin-bottom: 1rem;
        }

        .account-item {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            width: 100%;
            padding: 0.75rem;
            background: var(--contrast-25);
            border: 1px solid var(--contrast-100);
            border-radius: 0.5rem;
            cursor: pointer;
            transition: background-color 0.15s, border-color 0.15s;
            text-align: left;
        }

        .account-item:hover {
            background: var(--contrast-50);
            border-color: var(--contrast-200);
        }

        .avatar {
            width: 2.5rem;
            height: 2.5rem;
            border-radius: 50%;
            background: var(--primary);
            color: var(--primary-contrast);
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
            font-size: 0.875rem;
            flex-shrink: 0;
        }

        .account-info {
            flex: 1;
            min-width: 0;
        }

        .account-info .handle {
            display: block;
            font-weight: 500;
            color: var(--contrast-900);
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .account-info .email {
            display: block;
            font-size: 0.875rem;
            color: var(--contrast-500);
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .chevron {
            color: var(--contrast-400);
            font-size: 1.25rem;
            flex-shrink: 0;
        }

        .divider {
            height: 1px;
            background: var(--contrast-100);
            margin: 1rem 0;
        }

        .link-button {
            background: none;
            border: none;
            color: var(--primary);
            cursor: pointer;
            font-size: inherit;
            padding: 0;
            text-decoration: underline;
        }

        .link-button:hover {
            color: var(--primary-hover);
        }

        .new-account-link {
            display: block;
            text-align: center;
            color: var(--primary);
            text-decoration: none;
            font-size: 0.875rem;
        }

        .new-account-link:hover {
            text-decoration: underline;
        }

        .help-text {
            text-align: center;
            margin-top: 1rem;
            font-size: 0.875rem;
            color: var(--contrast-500);
        }

        .icon {
            font-size: 3rem;
            margin-bottom: 1rem;
        }

        .error-code {
            background: var(--error-bg);
            color: var(--error);
            padding: 0.5rem 1rem;
            border-radius: 0.375rem;
            font-family: monospace;
            display: inline-block;
            margin-bottom: 1rem;
        }

        .success-icon {
            width: 3rem;
            height: 3rem;
            border-radius: 50%;
            background: var(--success-bg);
            color: var(--success);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.5rem;
            margin: 0 auto 1rem;
        }

        .text-center {
            text-align: center;
        }

        .code-input {
            letter-spacing: 0.5em;
            text-align: center;
            font-size: 1.5rem;
            font-family: monospace;
        }
    "#
}

pub fn login_page(
    client_id: &str,
    client_name: Option<&str>,
    scope: Option<&str>,
    request_uri: &str,
    error_message: Option<&str>,
    login_hint: Option<&str>,
) -> String {
    let client_display = client_name.unwrap_or(client_id);
    let scope_display = scope.unwrap_or("access your account");

    let error_html = error_message
        .map(|msg| format!(r#"<div class="error-banner">{}</div>"#, html_escape(msg)))
        .unwrap_or_default();

    let login_hint_value = login_hint.unwrap_or("");

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex">
    <title>Sign in</title>
    <style>{styles}</style>
</head>
<body>
    <div class="container">
        <div class="card">
            <h1>Sign in</h1>
            <p class="subtitle">to continue to <strong>{client_display}</strong></p>

            <div class="client-info">
                <span class="client-name">{client_display}</span>
                <span class="scope">wants to {scope_display}</span>
            </div>

            {error_html}

            <form method="POST" action="/oauth/authorize">
                <input type="hidden" name="request_uri" value="{request_uri}">

                <div class="form-group">
                    <label for="username">Handle or Email</label>
                    <input type="text" id="username" name="username" value="{login_hint_value}"
                           required autocomplete="username" autofocus
                           placeholder="you@example.com">
                </div>

                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" required
                           autocomplete="current-password" placeholder="Enter your password">
                </div>

                <div class="checkbox-group">
                    <input type="checkbox" id="remember_device" name="remember_device" value="true">
                    <label for="remember_device">Remember this device</label>
                </div>

                <div class="buttons">
                    <button type="submit" formaction="/oauth/authorize/deny" class="btn btn-secondary">Cancel</button>
                    <button type="submit" class="btn btn-primary">Sign in</button>
                </div>
            </form>

            <div class="footer">
                By signing in, you agree to share your account information with this application.
            </div>
        </div>
    </div>
</body>
</html>"#,
        styles = base_styles(),
        client_display = html_escape(client_display),
        scope_display = html_escape(scope_display),
        request_uri = html_escape(request_uri),
        error_html = error_html,
        login_hint_value = html_escape(login_hint_value),
    )
}

pub struct DeviceAccount {
    pub did: String,
    pub handle: String,
    pub email: Option<String>,
    pub last_used_at: DateTime<Utc>,
}

pub fn account_selector_page(
    client_id: &str,
    client_name: Option<&str>,
    request_uri: &str,
    accounts: &[DeviceAccount],
) -> String {
    let client_display = client_name.unwrap_or(client_id);

    let accounts_html: String = accounts
        .iter()
        .map(|account| {
            let initials = get_initials(&account.handle);
            let email_display = account.email.as_deref().unwrap_or("");
            format!(
                r#"<form method="POST" action="/oauth/authorize/select" style="margin:0">
                    <input type="hidden" name="request_uri" value="{request_uri}">
                    <input type="hidden" name="did" value="{did}">
                    <button type="submit" class="account-item">
                        <div class="avatar">{initials}</div>
                        <div class="account-info">
                            <span class="handle">@{handle}</span>
                            <span class="email">{email}</span>
                        </div>
                        <span class="chevron">›</span>
                    </button>
                </form>"#,
                request_uri = html_escape(request_uri),
                did = html_escape(&account.did),
                initials = html_escape(&initials),
                handle = html_escape(&account.handle),
                email = html_escape(email_display),
            )
        })
        .collect();

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex">
    <title>Choose an account</title>
    <style>{styles}</style>
</head>
<body>
    <div class="container">
        <div class="card">
            <h1>Choose an account</h1>
            <p class="subtitle">to continue to <strong>{client_display}</strong></p>

            <div class="accounts">
                {accounts_html}
            </div>

            <div class="divider"></div>

            <a href="/oauth/authorize?request_uri={request_uri_encoded}&new_account=true" class="new-account-link">
                Sign in with another account
            </a>
        </div>
    </div>
</body>
</html>"#,
        styles = base_styles(),
        client_display = html_escape(client_display),
        accounts_html = accounts_html,
        request_uri_encoded = urlencoding::encode(request_uri),
    )
}

pub fn two_factor_page(
    request_uri: &str,
    channel: &str,
    error_message: Option<&str>,
) -> String {
    let error_html = error_message
        .map(|msg| format!(r#"<div class="error-banner">{}</div>"#, html_escape(msg)))
        .unwrap_or_default();

    let (title, subtitle) = match channel {
        "email" => ("Check your email", "We sent a verification code to your email"),
        "Discord" => ("Check Discord", "We sent a verification code to your Discord"),
        "Telegram" => ("Check Telegram", "We sent a verification code to your Telegram"),
        "Signal" => ("Check Signal", "We sent a verification code to your Signal"),
        _ => ("Check your messages", "We sent you a verification code"),
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex">
    <title>Verify your identity</title>
    <style>{styles}</style>
</head>
<body>
    <div class="container">
        <div class="card">
            <h1>{title}</h1>
            <p class="subtitle">{subtitle}</p>

            {error_html}

            <form method="POST" action="/oauth/authorize/2fa">
                <input type="hidden" name="request_uri" value="{request_uri}">

                <div class="form-group">
                    <label for="code">Verification code</label>
                    <input type="text" id="code" name="code" class="code-input"
                           placeholder="000000"
                           pattern="[0-9]{{6}}" maxlength="6"
                           inputmode="numeric" autocomplete="one-time-code"
                           autofocus required>
                </div>

                <button type="submit" class="btn btn-primary" style="width:100%">Verify</button>
            </form>

            <p class="help-text">
                Code expires in 10 minutes.
            </p>
        </div>
    </div>
</body>
</html>"#,
        styles = base_styles(),
        title = title,
        subtitle = subtitle,
        request_uri = html_escape(request_uri),
        error_html = error_html,
    )
}

pub fn error_page(error: &str, error_description: Option<&str>) -> String {
    let description = error_description.unwrap_or("An error occurred during the authorization process.");

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex">
    <title>Authorization Error</title>
    <style>{styles}</style>
</head>
<body>
    <div class="container">
        <div class="card text-center">
            <div class="icon">⚠️</div>
            <h1>Authorization Failed</h1>
            <div class="error-code">{error}</div>
            <p class="subtitle" style="margin-bottom:0">{description}</p>
            <div style="margin-top:1.5rem">
                <button onclick="window.close()" class="btn btn-secondary">Close this window</button>
            </div>
        </div>
    </div>
</body>
</html>"#,
        styles = base_styles(),
        error = html_escape(error),
        description = html_escape(description),
    )
}

pub fn success_page(client_name: Option<&str>) -> String {
    let client_display = client_name.unwrap_or("The application");

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex">
    <title>Authorization Successful</title>
    <style>{styles}</style>
</head>
<body>
    <div class="container">
        <div class="card text-center">
            <div class="success-icon">✓</div>
            <h1 style="color:var(--success)">Authorization Successful</h1>
            <p class="subtitle">{client_display} has been granted access to your account.</p>
            <p class="help-text">You can close this window and return to the application.</p>
        </div>
    </div>
</body>
</html>"#,
        styles = base_styles(),
        client_display = html_escape(client_display),
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn get_initials(handle: &str) -> String {
    let clean = handle.trim_start_matches('@');
    if clean.is_empty() {
        return "?".to_string();
    }
    clean.chars().next().unwrap_or('?').to_uppercase().to_string()
}

pub fn mask_email(email: &str) -> String {
    if let Some(at_pos) = email.find('@') {
        let local = &email[..at_pos];
        let domain = &email[at_pos..];

        if local.len() <= 2 {
            format!("{}***{}", local.chars().next().unwrap_or('*'), domain)
        } else {
            let first = local.chars().next().unwrap_or('*');
            let last = local.chars().last().unwrap_or('*');
            format!("{}***{}{}", first, last, domain)
        }
    } else {
        "***".to_string()
    }
}
