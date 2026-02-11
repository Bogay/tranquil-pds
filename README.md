# Tranquil PDS

A Personal Data Server for the AT Protocol.

Bluesky runs on a federated protocol called AT Protocol. Your account lives on a PDS, a server that stores your posts, profile, follows, and cryptographic keys. Bluesky hosts one for you at bsky.social, but you can run your own. Self-hosting means you control your data; you're not dependent on any company's servers, and your account + data is actually yours.

This particular PDS thrives under harsh conditions. It is a dandelion growing through the cracks in the sidewalk concrete.

It has full compatibility with Bluesky's reference PDS.

## What's different about Tranquil PDS

It is a superset of the reference PDS, including: passkeys and 2FA (WebAuthn/FIDO2, TOTP, backup codes, trusted devices), SSO login and signup, did:web support (PDS-hosted subdomains or bring-your-own), multi-channel communication (email, discord, telegram, signal) for verification and alerts, granular OAuth scopes with a consent UI showing human-readable descriptions, app passwords with granular permissions (read-only, post-only, or custom scopes), account delegation (letting others manage an account with configurable permission levels), and a built-in web UI for account management, repo browsing, and admin.

The PDS itself is a single binary with no nodeJS runtime. However, at time of writing, Tranquil requires postgres running separately. Blobs are stored on the local filesystem by default (S3 optional). Valkey is also optional (as an alternative to the built-in cache).

## Quick Start

```bash
cp .env.example .env
podman compose up db -d
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

Edit `.env` with your values. Generate secrets with `openssl rand -base64 48`.

```bash
cp .env.example .env
podman-compose -f docker-compose.prod.yaml up -d
```

### Installation Guides

- [Debian](docs/install-debian.md)
- [Containers](docs/install-containers.md)
- [Kubernetes](docs/install-kubernetes.md)

## Maintainers to ping

- [@lewis.moe](https://bsky.app/profile/did:plc:3fwecdnvtcscjnrx2p4n7alz)
- [@nel.pet](https://bsky.app/profile/did:plc:h5wsnqetncv6lu2weom35lg2)

## Thanks

This project is very grateful to [@nonbinary.computer](https://bsky.app/profile/did:plc:yfvwmnlztr4dwkb7hwz55r2g), [@juli.ee](https://bsky.app/profile/did:plc:7vimlesenouvuaqvle42yhvo), [@mary.my.id](https://bsky.app/profile/did:plc:ia76kvnndjutgedggx2ibrem), and [@baileytownsend.dev](https://bsky.app/profile/did:plc:rnpkyqnmsw4ipey6eotbdnnf) for their help and their code to lean on.

## License

AGPL-3.0-or-later. Documentation is CC BY-SA 4.0. See [LICENSE](LICENSE) for details.

