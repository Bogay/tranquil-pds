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
## Production Deployment
### Quick Deploy (Docker/Podman Compose)
```bash
cp .env.prod.example .env.prod
# Edit .env.prod with your values (generate secrets with: openssl rand -base64 48)
podman-compose -f docker-compose.prod.yml up -d
```
### Full Installation Guides
| Guide | Best For |
|-------|----------|
| **Native Installation** | Maximum performance, full control |
| [Debian](docs/install-debian.md) | Debian 13+ with systemd |
| [Alpine](docs/install-alpine.md) | Alpine 3.23+ with OpenRC |
| [OpenBSD](docs/install-openbsd.md) | OpenBSD 7.8+ with rc.d |
| **Containerized** | Easier updates, isolation |
| [Containers](docs/install-containers.md) | Podman with quadlets (Debian) or OpenRC (Alpine) |
| **Orchestrated** | High availability, auto-scaling |
| [Kubernetes](docs/install-kubernetes.md) | Multi-node k8s cluster deployment |
## License
TBD
