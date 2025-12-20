# Tranquil PDS

A Personal Data Server for the AT Protocol.

Bluesky runs on a federated protocol called AT Protocol. Your account lives on a PDS, a server that stores your posts, profile, follows, and cryptographic keys. Bluesky hosts one for you at bsky.social, but you can run your own. Self-hosting means you control your data; you're not dependent on any company's servers, and your account + data is actually yours.

This particular PDS thrives under harsh conditions. It is a dandelion growing through the cracks in the sidewalk concrete.

It has full compatibility with Bluesky's reference PDS: same endpoints, same behavior, same client compatibility. Everything works: repo operations, blob storage, firehose, OAuth, handle resolution, account migration, the lot.

Another excellent PDS is [Cocoon](https://github.com/haileyok/cocoon), written in go.

## What's different about Tranquil PDS

This software isn't an afterthought by a company with limited resources.

It is a superset of the reference PDS, including: multi-channel communication (email, discord, telegram, signal) for verification and alerts. Built-in web UI for account management, OAuth consent, repo browsing, and admin. Granular OAuth scopes with UI support such that users choose exactly what apps can access.

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

TBD
