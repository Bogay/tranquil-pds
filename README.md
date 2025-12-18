# Tranquil PDS

A production-grade Personal Data Server (PDS) for the AT Protocol. Drop-in replacement for Bluesky's reference PDS, written in rust with postgres and s3-compatible blob storage.

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
just test
just lint
```

## Production Deployment

### Quick Deploy (Docker/Podman Compose)

Edit `.env.prod` with your values. Generate secrets with `openssl rand -base64 48`.

```bash
cp .env.prod.example .env.prod
podman-compose -f docker-compose.prod.yml up -d
```

### Installation Guides

| Guide | Best For |
|-------|----------|
| [Debian](docs/install-debian.md) | Debian 13+ with systemd |
| [Alpine](docs/install-alpine.md) | Alpine 3.23+ with OpenRC |
| [OpenBSD](docs/install-openbsd.md) | OpenBSD 7.8+ with rc.d |
| [Containers](docs/install-containers.md) | Podman with quadlets or OpenRC |
| [Kubernetes](docs/install-kubernetes.md) | You know what you're doing |

## License

TBD
