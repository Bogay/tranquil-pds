# Tranquil PDS

A Personal Data Server for the AT Protocol.

"A what for the what?" -> glad you asked: Bluesky, Tangled, and a bunch of other web applications use a federated protocol called AT Protocol (atproto). Your account lives on a PDS, a server that stores your posts, profile, follows, cryptographic keys, et cetera. The beauty is that a PDS is the *only* place your data lives permanently - so you can navigate any atproto app knowing that your data is yours and not getting locked behind any one app's walls.

We came together to make this PDS to enable and empower our users to better host their data on this shared protocol. All of our decisions as a project are guided by their usefulness to the community: PDS hosters and end-users both. 

Comparatively: Bluesky the company created a "reference PDS" that we can self-host quite easily, and that's great, but Bluesky has an incentive to make software for themselvess first & foremost, then secondly their software can be useful for us self-hosters. In contrast, Tranquil is not from a company, and will never be.

## What's different about Tranquil PDS

It is a superset of the reference PDS, including:
- passkeys and 2FA: WebAuthn/FIDO2, TOTP, backup codes, trusted devices
- SSO login and signup
- did:web support: PDS-hosted subdomains or bring-your-own
- multi-channel communication: you can be notified via email, discord, telegram, and signal for verification and alerts
- granular OAuth scopes with a consent UI that allows unchecking specific scopes
- app passwords with the same granular permission scope system as OAuth
- account delegation: letting others manage an account with configurable permission levels
- a built-in web UI for account management, repo browsing, and admin

Unlike the ref PDS, Tranquil itself is compiled to a single binary with no nodeJS runtime. However, at time of writing, Tranquil requires postgres running separately.

## Quick Start

```bash
cp example.toml config.toml
podman compose up db -d
just run
```

## Configuration

See `example.toml` for all configuration options.

> [!NOTE]
> The order of configuration precedence is: environment variables, then a config file passed via `--config`, then `/etc/tranquil-pds/config.toml`, then the built-in defaults. So you can use environment variables, or a config file, or both.

## Development

Run `just` to see available commands.

```bash
just test
just lint
```

## Production Deployment

### Quick Deploy (Docker/Podman Compose)

Edit `config.toml` with your values. Generate secrets with `openssl rand -base64 48`.

```bash
cp example.toml config.toml
podman-compose -f docker-compose.prod.yaml up -d
```

### Installation Guides

- [Debian](docs/install-debian.md)
- [Containers](docs/install-containers.md)
- [Kubernetes](docs/install-kubernetes.md)

## Community

### "Let's connect!" or whatever linkedin-types say

We currently don't have a shared space to chat and organize Tranquil things, but we're very interested in changing that in the near future. What do you suggest? Anything but a discord server.

### Core team

- [@oyster.cafe](https://tangled.org/did:plc:3fwecdnvtcscjnrx2p4n7alz)
- [@nel.pet](https://tangled.org/did:plc:h5wsnqetncv6lu2weom35lg2)

### Amazing contributers

- [@isabelroses.com](https://tangled.org/did:plc:qxichs7jsycphrsmbujwqbfb)
- [@quilling.dev](https://tangled.org/did:plc:jrtgsidnmxaen4offglr5lsh)
- [@koi.rip](https://tangled.org/did:plc:b26ewgkrnx3yvsp2cdao3ntu)
- [@bas.sh](https://tangled.org/did:plc:c52wep6lj4sfbsqiz3yvb55h)
- [@nekomimi.pet](https://tangled.org/did:plc:ttdrpj45ibqunmfhdsb4zdwq)
- [@islacant.win](https://tangled.org/did:plc:aut6evcs6d6ngaunqgfhdzzu)
- [@a.starrysky.fyi](https://tangled.org/did:plc:uuyqs6y3pwtbteet4swt5i5y)
- [@sans-self.org](https://tangled.org/did:plc:wydyrngmxbcsqdvhmd7whmye)
- [@tachyonism.tngl.sh](https://tangled.org/did:plc:w6qiwij62bmdugsd3gemhpy2)
- Could be your name here too!

### Tranquil PDS instances in the wild!

- [Tranquil Farm](https://tranquil.farm)
- Your instance here!! Don't be a stranger.

### Special thanks

This project is very grateful to [@nonbinary.computer](https://tangled.org/did:plc:yfvwmnlztr4dwkb7hwz55r2g), [@juliet.paris](https://tangled.org/did:plc:hs3aly5l26pozymy4b6hz7ae), [@mary.my.id](https://tangled.org/did:plc:ia76kvnndjutgedggx2ibrem), [@baileytownsend.dev](https://tangled.org/did:plc:rnpkyqnmsw4ipey6eotbdnnf), and [@ptr.pet](https://tangled.org/did:plc:dfl62fgb7wtjj3fcbb72naae) for their help and their code to lean on.

## License

AGPL-3.0-or-later. Documentation is CC BY-SA 4.0. See [LICENSE](LICENSE) for details.

