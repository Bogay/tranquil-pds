# BSPDS

A production-grade Personal Data Server (PDS) for the AT Protocol. Drop-in replacement for Bluesky's reference PDS, using postgres and s3-compatible blob storage.

## Features

- Full AT Protocol support (`com.atproto.*` endpoints)
- OAuth 2.1 provider (PKCE, DPoP, PAR)
- WebSocket firehose (`subscribeRepos`)
- Multi-channel notifications (email, discord, telegram, signal)
- Built-in web UI for account management
- Per-IP rate limiting

## Quick Start

```bash
cp .env.example .env
podman compose up -d
just run
```

## Configuration

See `.env.example` for all configuration options.

## Development

Run `just` to see available commands.

```bash
just test      # run tests
just lint      # clippy + fmt
```

## License

TBD
