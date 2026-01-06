# Tranquil PDS

A Personal Data Server for the AT Protocol.

Bluesky runs on a federated protocol called AT Protocol. Your account lives on a PDS, a server that stores your posts, profile, follows, and cryptographic keys. Bluesky hosts one for you at bsky.social, but you can run your own. Self-hosting means you control your data; you're not dependent on any company's servers, and your account + data is actually yours.

This particular PDS thrives under harsh conditions. It is a dandelion growing through the cracks in the sidewalk concrete.

It has full compatibility with Bluesky's reference PDS: same endpoints, same behavior, same client compatibility. Everything works: repo operations, blob storage, firehose, OAuth, handle resolution, account migration, the lot.

Another excellent PDS is [Cocoon](https://tangled.org/hailey.at/cocoon), written in go.

## What's different about Tranquil PDS

It is a superset of the reference PDS, including: passkeys and 2FA (WebAuthn/FIDO2, TOTP, backup codes, trusted devices), did:web support (PDS-hosted subdomains or bring-your-own), multi-channel communication (email, discord, telegram, signal) for verification and alerts, granular OAuth scopes with a consent UI showing human-readable descriptions, app passwords with granular permissions (read-only, post-only, or custom scopes), account delegation (letting others manage an account with configurable permission levels), automatic backups to s3-compatible object storage (configurable retention and frequency, one-click restore), and a built-in web UI for account management, OAuth consent, repo browsing, and admin.

The PDS itself is a single small binary with no node/npm runtime. It does require postgres, valkey, and s3-compatible storage, which makes setup heavier than the reference PDS's sqlite. The tradeoff is that these are battle-tested pieces of infra that we already know how to scale, back up, and monitor. 

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

## Thanks

This project is very grateful to [@nel.pet](https://bsky.app/profile/did:plc:h5wsnqetncv6lu2weom35lg2), [@nonbinary.computer](https://bsky.app/profile/did:plc:yfvwmnlztr4dwkb7hwz55r2g), [@juli.ee](https://bsky.app/profile/did:plc:7vimlesenouvuaqvle42yhvo), [@mary.my.id](https://bsky.app/profile/did:plc:ia76kvnndjutgedggx2ibrem), and [@baileytownsend.dev](https://bsky.app/profile/did:plc:rnpkyqnmsw4ipey6eotbdnnf) for their help and their code to lean on.

## License

AGPL-3.0-or-later. Documentation is CC BY-SA 4.0. See [LICENSE](LICENSE) for details.

