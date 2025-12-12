# BSPDS, a Personal Data Server

A production-grade Personal Data Server (PDS) implementation for the AT Protocol.

Uses PostgreSQL instead of SQLite, S3-compatible blob storage, and is designed to be a complete drop-in replacement for Bluesky's reference PDS implementation.

## Features

- Full AT Protocol support, all `com.atproto.*` endpoints implemented
- OAuth 2.1 Provider. PKCE, DPoP, Pushed Authorization Requests
- PostgreSQL, prod-ready database backend
- S3-compatible object storage for blobs; works with AWS S3, UpCloud object storage, self-hosted MinIO, etc.
- WebSocket `subscribeRepos` endpoint for real-time sync
- Crawler notifications via `requestCrawl`
- Multi-channel notifications: email, discord, telegram, signal
- Per-IP rate limiting on sensitive endpoints
- Built-in web UI for account management

## Running Locally

Requires Rust installed locally.

Run PostgreSQL and S3-compatible object store (e.g., with podman/docker):

```bash
podman compose up db objsto -d
```

Run the PDS:

```bash
just run
```

## Configuration

### Required

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | PostgreSQL connection string |
| `S3_BUCKET` | Blob storage bucket name |
| `S3_ENDPOINT` | S3 endpoint URL (for MinIO, etc.) |
| `AWS_ACCESS_KEY_ID` | S3 credentials |
| `AWS_SECRET_ACCESS_KEY` | S3 credentials |
| `AWS_REGION` | S3 region |
| `PDS_HOSTNAME` | Public hostname of this PDS |
| `JWT_SECRET` | Secret for OAuth token signing (HS256) |
| `KEY_ENCRYPTION_KEY` | Key for encrypting user signing keys (AES-256-GCM) |

### Optional

| Variable | Description |
|----------|-------------|
| `APPVIEW_URL` | Appview URL to proxy unimplemented endpoints to |
| `CRAWLERS` | Comma-separated list of relay URLs to notify via `requestCrawl` |

### Notifications

At least one channel should be configured for user notifications (password reset, email verification, etc.):

| Variable | Description |
|----------|-------------|
| `MAIL_FROM_ADDRESS` | Email sender address (enables email via sendmail) |
| `MAIL_FROM_NAME` | Email sender name (default: "BSPDS") |
| `SENDMAIL_PATH` | Path to sendmail binary (default: /usr/sbin/sendmail) |
| `DISCORD_WEBHOOK_URL` | Discord webhook URL for notifications |
| `TELEGRAM_BOT_TOKEN` | Telegram bot token for notifications |
| `SIGNAL_CLI_PATH` | Path to signal-cli binary |
| `SIGNAL_SENDER_NUMBER` | Signal sender phone number (+1234567890 format) |

## Development

```bash
just              # Show available commands
just test         # Run tests (auto-starts postgres/minio, runs nextest)
just lint         # Clippy + fmt check
just db-reset     # Drop and recreate local database
```

## Web UI

BSPDS includes a built-in web frontend for users to manage their accounts. Users can:

- Sign in and register new accounts
- Manage app passwords
- View and create invite codes
- Update email and handle
- Configure notification preferences
- Browse their repository data

The frontend is built with svelte and deno, and is served directly by the PDS.

```bash
just frontend-dev      # Run frontend dev server
just frontend-build    # Build for production
just frontend-test     # Run frontend tests
```

## Project Structure

```
src/
  main.rs           Server entrypoint
  lib.rs            Router setup
  state.rs          AppState (db pool, stores, rate limiters, circuit breakers)
  api/              XRPC handlers organized by namespace
  auth/             JWT authentication (ES256K per-user keys)
  oauth/            OAuth 2.1 provider (HS256 server-wide)
  repo/             PostgreSQL block store
  storage/          S3 blob storage
  sync/             Firehose, CAR export, crawler notifications
  notifications/    Multi-channel notification service
  plc/              PLC directory client
  circuit_breaker/  Circuit breaker for external services
  rate_limit/       Per-IP rate limiting
frontend/           Svelte web UI (deno)
tests/              Integration tests
migrations/         SQLx migrations
```

## License

TBD
