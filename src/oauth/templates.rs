use chrono::{DateTime, Utc};

fn format_scope_for_display(scope: Option<&str>) -> String {
    let scope = scope.unwrap_or("");
    if scope.is_empty() || scope.contains("atproto") || scope.contains("transition:generic") {
        return "access your account".to_string();
    }
    let parts: Vec<&str> = scope.split_whitespace().collect();
    let friendly: Vec<&str> = parts
        .iter()
        .filter_map(|s| {
            match *s {
                "atproto" | "transition:generic" | "transition:chat.bsky" => None,
                "read" => Some("read your data"),
                "write" => Some("write data"),
                other => Some(other),
            }
        })
        .collect();
    if friendly.is_empty() {
        "access your account".to_string()
    } else {
        friendly.join(", ")
    }
}

fn base_styles() -> &'static str {
    r#"
        :root {
            --bg-primary: #fafafa;
            --bg-secondary: #f9f9f9;
            --bg-card: #ffffff;
            --bg-input: #ffffff;
            --text-primary: #333333;
            --text-secondary: #666666;
            --text-muted: #999999;
            --border-color: #dddddd;
            --border-color-light: #cccccc;
            --accent: #0066cc;
            --accent-hover: #0052a3;
            --success-bg: #dfd;
            --success-border: #8c8;
            --success-text: #060;
            --error-bg: #fee;
            --error-border: #fcc;
            --error-text: #c00;
        }
        @media (prefers-color-scheme: dark) {
            :root {
                --bg-primary: #1a1a1a;
                --bg-secondary: #242424;
                --bg-card: #2a2a2a;
                --bg-input: #333333;
                --text-primary: #e0e0e0;
                --text-secondary: #a0a0a0;
                --text-muted: #707070;
                --border-color: #404040;
                --border-color-light: #505050;
                --accent: #4da6ff;
                --accent-hover: #7abbff;
                --success-bg: #1a3d1a;
                --success-border: #2d5a2d;
                --success-text: #7bc67b;
                --error-bg: #3d1a1a;
                --error-border: #5a2d2d;
                --error-text: #ff7b7b;
            }
        }
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        body {
            font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            line-height: 1.5;
        }
        .container {
            max-width: 400px;
            margin: 4rem auto;
            padding: 2rem;
        }
        h1 {
            margin: 0 0 0.5rem 0;
            font-weight: 600;
        }
        .subtitle {
            color: var(--text-secondary);
            margin: 0 0 2rem 0;
        }
        .subtitle strong {
            color: var(--text-primary);
        }
        .client-info {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1rem;
            margin-bottom: 1.5rem;
        }
        .client-info .client-name {
            font-weight: 500;
            color: var(--text-primary);
            display: block;
            margin-bottom: 0.25rem;
        }
        .client-info .scope {
            color: var(--text-secondary);
            font-size: 0.875rem;
        }
        .error-banner {
            background: var(--error-bg);
            border: 1px solid var(--error-border);
            color: var(--error-text);
            border-radius: 4px;
            padding: 0.75rem;
            margin-bottom: 1rem;
        }
        .form-group {
            margin-bottom: 1rem;
        }
        label {
            display: block;
            font-size: 0.875rem;
            font-weight: 500;
            margin-bottom: 0.25rem;
        }
        input[type="text"],
        input[type="email"],
        input[type="password"] {
            width: 100%;
            padding: 0.75rem;
            border: 1px solid var(--border-color-light);
            border-radius: 4px;
            font-size: 1rem;
            color: var(--text-primary);
            background: var(--bg-input);
        }
        input[type="text"]:focus,
        input[type="email"]:focus,
        input[type="password"]:focus {
            outline: none;
            border-color: var(--accent);
        }
        input[type="text"]::placeholder,
        input[type="email"]::placeholder,
        input[type="password"]::placeholder {
            color: var(--text-muted);
        }
        .checkbox-group {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            margin-bottom: 1.5rem;
        }
        .checkbox-group input[type="checkbox"] {
            width: 1rem;
            height: 1rem;
            accent-color: var(--accent);
        }
        .checkbox-group label {
            margin-bottom: 0;
            font-weight: normal;
            color: var(--text-secondary);
            cursor: pointer;
        }
        .buttons {
            display: flex;
            gap: 0.75rem;
        }
        .btn {
            flex: 1;
            padding: 0.75rem;
            border-radius: 4px;
            font-size: 1rem;
            cursor: pointer;
            border: none;
            text-align: center;
            text-decoration: none;
        }
        .btn-primary {
            background: var(--accent);
            color: white;
        }
        .btn-primary:hover {
            background: var(--accent-hover);
        }
        .btn-primary:disabled {
            opacity: 0.6;
            cursor: not-allowed;
        }
        .btn-secondary {
            background: transparent;
            color: var(--accent);
            border: 1px solid var(--accent);
        }
        .btn-secondary:hover {
            background: var(--accent);
            color: white;
        }
        .footer {
            text-align: center;
            margin-top: 1.5rem;
            font-size: 0.75rem;
            color: var(--text-muted);
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
            justify-content: space-between;
            width: 100%;
            padding: 1rem;
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            cursor: pointer;
            transition: border-color 0.15s, box-shadow 0.15s;
            text-align: left;
        }
        .account-item:hover {
            border-color: var(--accent);
            box-shadow: 0 2px 8px rgba(77, 166, 255, 0.15);
        }
        .account-info {
            display: flex;
            flex-direction: column;
            gap: 0.25rem;
            flex: 1;
            min-width: 0;
        }
        .account-info .handle {
            font-weight: 500;
            color: var(--text-primary);
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .account-info .did {
            font-size: 0.75rem;
            color: var(--text-muted);
            font-family: monospace;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        .chevron {
            color: var(--text-muted);
            font-size: 1.25rem;
            flex-shrink: 0;
            margin-left: 0.5rem;
        }
        .divider {
            height: 1px;
            background: var(--border-color);
            margin: 1rem 0;
        }
        .new-account-link {
            display: block;
            text-align: center;
            color: var(--accent);
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
            color: var(--text-secondary);
        }
        .icon {
            font-size: 3rem;
            margin-bottom: 1rem;
        }
        .error-code {
            background: var(--error-bg);
            border: 1px solid var(--error-border);
            color: var(--error-text);
            padding: 0.5rem 1rem;
            border-radius: 4px;
            font-family: monospace;
            display: inline-block;
            margin-bottom: 1rem;
        }
        .success-icon {
            width: 3rem;
            height: 3rem;
            border-radius: 50%;
            background: var(--success-bg);
            border: 1px solid var(--success-border);
            color: var(--success-text);
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
    let scope_display = format_scope_for_display(scope);
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
        <h1>Sign In</h1>
        <p class="subtitle">Sign in to continue to <strong>{client_display}</strong></p>
        <div class="client-info">
            <span class="client-name">{client_display}</span>
            <span class="scope">wants to {scope_display}</span>
        </div>
        {error_html}
        <form method="POST" action="/oauth/authorize">
            <input type="hidden" name="request_uri" value="{request_uri}">
            <div class="form-group">
                <label for="username">Handle</label>
                <input type="text" id="username" name="username" value="{login_hint_value}"
                       required autocomplete="username" autofocus
                       placeholder="your.handle">
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
                <button type="submit" class="btn btn-primary">Sign In</button>
                <button type="submit" formaction="/oauth/authorize/deny" class="btn btn-secondary">Cancel</button>
            </div>
        </form>
        <p class="help-text">
            By signing in, you agree to share your account information with this application.
        </p>
    </div>
</body>
</html>"#,
        styles = base_styles(),
        client_display = html_escape(client_display),
        scope_display = html_escape(&scope_display),
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
            format!(
                r#"<form method="POST" action="/oauth/authorize/select" style="margin:0">
                    <input type="hidden" name="request_uri" value="{request_uri}">
                    <input type="hidden" name="did" value="{did}">
                    <button type="submit" class="account-item">
                        <div class="account-info">
                            <span class="handle">@{handle}</span>
                            <span class="did">{did}</span>
                        </div>
                        <span class="chevron">›</span>
                    </button>
                </form>"#,
                request_uri = html_escape(request_uri),
                did = html_escape(&account.did),
                handle = html_escape(&account.handle),
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
        <h1>Sign In</h1>
        <p class="subtitle">Choose an account to continue to <strong>{client_display}</strong></p>
        <div class="accounts">
            {accounts_html}
        </div>
        <div class="divider"></div>
        <a href="/oauth/authorize?request_uri={request_uri_encoded}&new_account=true" class="new-account-link">
            Sign in to another account
        </a>
    </div>
</body>
</html>"#,
        styles = base_styles(),
        client_display = html_escape(client_display),
        accounts_html = accounts_html,
        request_uri_encoded = urlencoding::encode(request_uri),
    )
}

pub fn two_factor_page(request_uri: &str, channel: &str, error_message: Option<&str>) -> String {
    let error_html = error_message
        .map(|msg| format!(r#"<div class="error-banner">{}</div>"#, html_escape(msg)))
        .unwrap_or_default();
    let (title, subtitle) = match channel {
        "email" => (
            "Check Your Email",
            "We sent a verification code to your email",
        ),
        "Discord" => (
            "Check Discord",
            "We sent a verification code to your Discord",
        ),
        "Telegram" => (
            "Check Telegram",
            "We sent a verification code to your Telegram",
        ),
        "Signal" => ("Check Signal", "We sent a verification code to your Signal"),
        _ => ("Check Your Messages", "We sent you a verification code"),
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
        <h1>{title}</h1>
        <p class="subtitle">{subtitle}</p>
        {error_html}
        <form method="POST" action="/oauth/authorize/2fa">
            <input type="hidden" name="request_uri" value="{request_uri}">
            <div class="form-group">
                <label for="code">Verification Code</label>
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
    let description =
        error_description.unwrap_or("An error occurred during the authorization process.");
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
    <div class="container text-center">
        <h1>Authorization Failed</h1>
        <div class="error-code">{error}</div>
        <p class="subtitle" style="margin-bottom:0">{description}</p>
        <div style="margin-top:1.5rem">
            <button onclick="window.close()" class="btn btn-secondary" style="width:100%">Close this window</button>
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
    <div class="container text-center">
        <div class="success-icon">✓</div>
        <h1 style="color:var(--success-text)">Authorization Successful</h1>
        <p class="subtitle">{client_display} has been granted access to your account.</p>
        <p class="help-text">You can close this window and return to the application.</p>
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
