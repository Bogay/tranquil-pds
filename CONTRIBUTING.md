# Contributing to Tranquil PDS

## When PRing

In order of importance:

- If your change involves how Tranquil implements atproto make sure its correct! See more below.
- **You must run your change! Every contribution that says "here's xyz. untested." does not help the project.**
- Relevant tests to your PR must pass. The whole suite doesn't have to be proven to have run, because there are a *ton* of tests and they're quite heavy, but hopefully there are existing tests for whatever you're PRing, and if there aren't, please add those too.
- Run cargo fmt :P

> 🦪 Lewis
>
> Good CI fixes some of these. We should really get around to that.

Things that would also be nice but aren't like, a pain in our side:

- Big changes should be stacked PRs that are broken up into digestible pieces. Those stacked PRs should hopefully be able to be merged individually if necessary.

### How we define a "correct" PDS implementation

The atproto specs are notoriously imprecise, ambiguious,
lacks specifications for large parts of the protocol and network (even including what implementing a PDS entails!)
and is generally none specific.
This is bad.
We won't waste time here describing all the ways in which that is problematic,
the important thing for Tranquil is that this means that "follows spec" is not sufficient to describe a "correct" PDS implementation.
Thus we need to come up with a description of "correct".
In order of importance the following rules describe what "correct" means for Tranquil:

- The specs take precedence.
  If the spec *is* specific enough then follow it.
  Even if the reference implementation doesn't.
- If the specs aren't sufficiently specific
  rely on the reference implementation, potential supporting documents or discussions,
  and/or community sentiment or common sense.
  If the matter is still debated and/or PBCs opinion differs from community sentiment we generally side with the community.
  - Examples here include what features and APIs to implement,
    here we look at what the reference implementation implements
    as well as https://github.com/bluesky-social/atproto/discussions/2350 as a supporting document.
    Another example is whether `include` scopes are allowed to use a `*` `aud` parameter.
    Discussion here has happened in https://github.com/bluesky-social/atproto/issues/4490.
    PBC has voiced an opinion that this should be disallowed,
    community sentiment seems to strongly lean to allowing it. Tranquil allows it.
  - Please mark locations like this with a `// SPECAMB: ...` comment explaining the ambiguity
    and what parts of the reference implementation and/or supporting documents have been used as reference.
- If the reference implementation has behaviour that is only ever relevant for the Bluesky application.
  Implementions of such behaviour **must** be gated behind a `bsky-support` cargo feature of the implementing crate.
  - Examples here include bluesky feedgen specific service proxying behaviour,
    the `app.bsky.actor.getPreferences` and `app.bsky.actor.putPreferences` APIs,
    and special handling of the `X-BSKY-TOPICS` HTTP header during service proxying.
  - Please add a comment next to these implementations with an explanation of the behaviour.
  - Most of these behaviours are required for proper functioning of the official Bluesky client, though not all.
    If the behaviour isn't required for the official client consider not implementing it.
  - One such behaviour that we have a *hard rule* to never implement is default proxying to a configured Bluesky appview
    for `app.bsky.*` APIs and as fallback for `com.atproto.repo.getRecord`.
    Many third-party Bluesky clients rely on this behaviour, the official client used to do the same but does not anymore.
    Third-party clients breaking because they don't specify an `atproto-proxy` header is thus *not* a Tranquil bug but a bug in said clients.
  - Bluesky is the only application that will ever recieve application specific behaviour like this.
    It does so only because such a big section of atproto usage is Bluesky
    and because Bluesky is the only application that can practically rely on application specific behaviour.
    Application specific behaviour for other applications may still be added to Tranquil if such behaviour is a Tranquil feature,
    for example for Tranquils rudimentary banned content moderation feature,
    and not something said application relies on for proper functioning.

There is bound to be edge cases that these rules don't fully cover.
Here common sense, community sentiment, furthering the goals of atproto itself, and ultimately maintainer opinion take precedence over support for any individual application.
Even Bluesky.

The rules above are meant to capture Tranquils goals of being correct while being community oriented and avoiding as much "Bluesky-defaultism" as possible.
Tranquil is a community atproto PDS, *not* a company-led Bluesky (or other atproto app) PDS.
See also "Tranquil & the world" in docs/1_WELCOME_TO_TRANQUIL_PDS.md.

## Local Development

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) and Docker Compose
- Add `pds.test` to your hosts file (one-time setup):

  ```
  127.0.0.1 pds.test
  ```

  - **macOS / Linux:** `/etc/hosts`
  - **Windows:** `C:\Windows\System32\drivers\etc\hosts`

### Starting the dev environment

```bash
just run-dev
```

This starts the following services via `docker-compose`:

- **Traefik** — HTTPS reverse proxy at `https://pds.test`
- **Backend** — Rust server with `cargo-watch` (auto-rebuilds on file changes)
- **Frontend** — Vite dev server with hot module replacement
- **Postgres** — Database on port 5432
- **PLC Directory** — Local [did-method-plc](https://github.com/did-method-plc/did-method-plc) server for DID registration
- **Mailpit** — Local email server with web UI at [http://localhost:8025](http://localhost:8025)

Once all services are running, open **https://pds.test** in your browser.

### Trusting the self-signed certificate

Traefik generates a self-signed TLS certificate. Your browser will show a security warning on first visit. You can either click through it, or add the certificate to your system trust store for a seamless experience:

**macOS:**

```bash
# Extract the cert from traefik and add it to the system keychain
echo | openssl s_client -connect localhost:443 -servername pds.test 2>/dev/null | openssl x509 > /tmp/pds-test.pem
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain /tmp/pds-test.pem
```

**Linux (Debian/Ubuntu):**

```bash
echo | openssl s_client -connect localhost:443 -servername pds.test 2>/dev/null | openssl x509 | sudo tee /usr/local/share/ca-certificates/pds-test.crt
sudo update-ca-certificates
```

**Linux (Fedora/RHEL):**

```bash
echo | openssl s_client -connect localhost:443 -servername pds.test 2>/dev/null | openssl x509 | sudo tee /etc/pki/ca-trust/source/anchors/pds-test.pem
sudo update-ca-trust
```

**Windows (PowerShell as Administrator):**

```powershell
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
$cert.Import([System.Text.Encoding]::UTF8.GetBytes((echo | openssl s_client -connect localhost:443 -servername pds.test 2>$null | openssl x509)))
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
$store.Open("ReadWrite")
$store.Add($cert)
$store.Close()
```

Restart your browser after adding the certificate.

### Stopping the dev environment

```bash
# Stop containers (preserves database + build cache)
docker compose --profile dev down

# Stop and wipe all data (fresh start)
docker compose --profile dev down -v
```

### Direct database access

Postgres is exposed on port 5432:

```bash
psql postgres://postgres:postgres@localhost:5432/pds
```

### How it works

- **Source code** is bind-mounted into the containers so that changes made on the host will be immediately reflected in the application
- **Backend** uses `cargo-watch` to recompile and restart when Rust files change
- **Frontend** uses Vite's HMR for instant browser updates when frontend files change
- **Build cache** (`target/` directory and cargo registry) are stored in Docker volumes, so incremental compilation persists across container restarts
- **Traefik** routes `/`, `/xrpc`, `/oauth`, `/.well-known`, `/u`, and `/health` to the backend; everything else goes to the Vite dev server
- **Mailpit** captures all outgoing email — open [http://localhost:8025](http://localhost:8025) to view verification emails during registration
- **PLC Directory** runs locally so DID registration doesn't hit the real `plc.directory`

### Running the backend natively

If you prefer running the Rust backend outside Docker (faster incremental builds on host), you need:

- Rust toolchain (see `rust-toolchain.toml`)
- `protoc` (`brew install protobuf` on macOS)
- PostgreSQL (start with `docker compose up db`)

Then run:

```bash
cargo run -p tranquil-server -- --config config.toml
```

And start the frontend separately:

```bash
cd frontend && pnpm install && pnpm dev
```
