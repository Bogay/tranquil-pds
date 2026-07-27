# Notification templates

Channel-neutral templates used by every comms channel (email, Telegram, Discord,
Signal). The same `body.txt` renders the message content for each channel; the
optional `body.html` is used only for the email HTML part (via queue metadata).

Layout expected by tranquil-pds when `comms.templates_dir` is set:

```
{templates_dir}/{locale}/{id}.subject.txt
{templates_dir}/{locale}/{id}.body.txt
{templates_dir}/{locale}/{id}.body.html
```

Templates use [Handlebars](https://handlebarsjs.com/) syntax (`{{hostname}}`,
`{{handle}}`, `{{code}}`, and so on). Built-in notification strings use the same
syntax. Plain-text templates support the full expression set (`{{#if}}`,
`{{else if}}`, `{{#unless}}`, `{{#with}}`); HTML templates HTML-escape
interpolated values by default, while subjects and plain-text bodies do not.

Required ids: welcome, password_reset, email_update, short_token, account_deletion,
plc_operation, two_factor_code, passkey_recovery, signup_verification, legacy_login,
migration_verification, channel_verification, channel_verified.

The `en/` directory is a complete example set you can copy and brand. It shows
conditionals in both plain text and HTML, e.g. `email_update` only renders the
one-click verify link when `verify_link` is provided.
