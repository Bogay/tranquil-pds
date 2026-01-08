# Lewis' Big Boy TODO list

## Active development

### Storage backend abstraction
Make storage layers swappable via traits.

filesystem blob storage
- [ ] FilesystemBlobStorage implementation
- [ ] directory structure (content-addressed like blobs/{cid} already used in objsto)
- [ ] atomic writes (write to temp, rename)
- [ ] config option to choose backend (env var or config flag)
- [ ] also traitify BackupStorage (currently hardcoded to objsto)

sqlite database backend
- [ ] abstract db layer behind trait (queries, transactions, migrations)
- [ ] sqlite implementation matching postgres behavior
- [ ] handle sqlite's single-writer limitation (connection pooling strategy)
- [ ] migrations system that works for both
- [ ] testing: run full test suite against both backends
- [ ] config option to choose backend (postgres vs sqlite)
- [ ] document tradeoffs (sqlite for single-user/small, postgres for multi-user/scale)

### Plugin system
WASM component model plugins. Compile to wasm32-wasip2, sandboxed via wasmtime, capability-gated. Based on zed's extensions.

WIT interface
- [ ] record hooks before/after create, update, delete
- [ ] blob hooks before/after upload, validate
- [ ] xrpc hooks before/after (middleware), custom endpoint handler
- [ ] firehose hook on_commit
- [ ] host imports http client, kv store, logging, read records

wasmtime host
- [ ] engine with epoch interruption (kill runaway plugins)
- [ ] plugin manifest (plugin.toml): id, version, capabilities, hooks
- [ ] capability enforcement at runtime
- [ ] plugin loader, lifecycle (enable/disable/reload)
- [ ] resource limits (memory, time)
- [ ] per-plugin fs sandbox

capabilities
- [ ] http:fetch with domain allowlist
- [ ] kv:read, kv:write
- [ ] record:read, blob:read
- [ ] xrpc:register
- [ ] firehose:subscribe

pds-plugin-api (rust), MVP for plugin system
- [ ] plugin trait with default impls
- [ ] register_plugin! macro
- [ ] typed host import wrappers
- [ ] publish to crates.io
- [ ] docs + example

pds-plugin-api in golang, nice to have after the fact
- [ ] wit-bindgen-go bindings
- [ ] go wrappers
- [ ] tinygo build instructions
- [ ] example

@pds/plugin-api in typescript, nice to have after the fact
- [ ] jco/componentize-js bindings
- [ ] typeScript types
- [ ] build tooling
- [ ] example

example plugins
- [ ] content filter
- [ ] webhook notifier
- [ ] objsto backup mirror
- [ ] custom lexicon handler
- [ ] better audit logger

### Misc

migration handle preservation
- [ ] allow users to keep their existing handle during migration (eg. lewis.moe instead of forcing lewis.newpds.com)
- [ ] UI option to preserve external handle vs create new pds-subdomain handle
- [ ] handle the DNS verification flow for external handles during migration

cross-pds delegation
when a client (eg. tangled.org) tries to log into a delegated account:
- [ ] client starts oauth flow to delegated account's pds
- [ ] delegated pds sees account is externally controlled, launches oauth to controller's pds (delegated pds acts as oauth client)
- [ ] controller authenticates at their own pds
- [ ] delegated pds verifies controller perms and scope from its local delegation grants
- [ ] delegated pds issues session to client within the intersection of controller's granted scope and client's requested scope

per-request "act as"
- [ ] authed as user X, perform action as delegated user Y in single request
- [ ] approach decision
  - [ ] option 1: `X-Act-As` header with target did, server verifies delegation grant
  - [ ] option 2: token exchange (RFC 8693) for short-lived delegated token
  - [ ] option 3 (lewis fav): extend existing `act` claim to support on-demand minting
  - [ ] something else?

### Private/encrypted data
Records only authorized parties can see and decrypt.

research
- [ ] survey atproto discourse on private data
- [ ] document bluesky team's likely approach. wait.. are they even gonna do this? whatever
- [ ] look at matrix/signal for federated e2ee patterns

key management
- [ ] db schema for encryption keys (user_keys, key_grants, key_rotations)
- [ ] per-user encryption keypair generation (separate from signing keys)
- [ ] key derivation scheme (per-collection? per-record? both?)
- [ ] key storage (encrypted at rest, hsm option?)
- [ ] rotation and revocation flow

storage layer
- [ ] encrypted record format (encrypted cbor blob + metadata)
- [ ] collection-level vs per-record encryption flag
- [ ] how encrypted records appear in mst (hash of ciphertext? separate tree?)
- [ ] blob encryption (same keys? separate?)

api surface
- [ ] xrpc getPublicKey, grantAccess, revokeAccess, listGrants
- [ ] xrpc getEncryptedRecord (ciphertext for client-side decrypt)
- [ ] or transparent server-side decrypt if requester has grant?
- [ ] lexicon for key grant records

sync/federation
- [ ] how encrypted records appear on firehose (ciphertext? omitted? placeholder?)
- [ ] pds-to-pds key exchange protocol
- [ ] appview behavior (can't index without grants)
- [ ] relay behavior with encrypted commits

client integration
- [ ] client-side encryption (pds never sees plaintext) vs server-side with trust
- [ ] key backup/recovery (lose key = lose data)

plugin hooks (once core exists)
- [ ] on_access_grant_request for custom authorization
- [ ] on_key_rotation to notify interested parties

---

## Completed

Core ATProto: Health, describeServer, all session endpoints, full repo CRUD, applyWrites, blob upload, importRepo, firehose with cursor replay, CAR export, blob sync, crawler notifications, handle resolution, PLC operations, full admin API, moderation reports.

did:web support: Self-hosted did:web (subdomain format `did:web:handle.pds.com`), external/BYOD did:web, DID document serving via `/.well-known/did.json`, clear registration warnings about did:web trade-offs vs did:plc.

OAuth 2.1: Authorization server metadata, JWKS, PAR, authorize endpoint with login UI, token endpoint (auth code + refresh), revocation, introspection, DPoP, PKCE S256, client metadata validation, private_key_jwt verification.

OAuth Scope Enforcement: Full granular scope system with consent UI, human-readable scope descriptions, per-client scope preferences, scope parsing (repo/blob/rpc/account/identity), endpoint-level scope checks, DPoP token support in auth extractors, token revocation on re-authorization, response_mode support (query/fragment).

App endpoints: getPreferences, putPreferences, getProfile, getProfiles, getTimeline, getAuthorFeed, getActorLikes, getPostThread, getFeed, registerPush (all with local-first + proxy fallback).

Infrastructure: Sequencer with cursor replay, postgres repo storage with atomic transactions, valkey DID cache, debounced crawler notifications with circuit breakers, multi-channel notifications (email/Discord/Telegram/Signal), image processing, distributed rate limiting, security hardening.

Web UI: OAuth login, registration, email verification, password reset, multi-account selector, dashboard, sessions, app passwords, invites, notification preferences, repo browser, CAR export, admin panel, OAuth consent screen with scope selection.

Auth: ES256K + HS256 dual support, JTI-only token storage, refresh token family tracking, encrypted signing keys (AES-256-GCM), DPoP replay protection, constant-time comparisons.

Passkeys and 2FA: WebAuthn/FIDO2 passkey registration and authentication, TOTP with QR setup, backup codes (hashed, one-time use), passkey-only account creation, trusted devices (remember this browser), re-auth for sensitive actions, rate-limited 2FA attempts, settings UI for managing all auth methods.

App password scopes: Granular permissions for app passwords using the same scope system as OAuth. Preset buttons for common use cases (full access, read-only, post-only), scope stored in session and preserved across token refresh, explicit RPC/repo/blob scope enforcement for restricted passwords.

Account Delegation: Delegated accounts controlled by other accounts instead of passwords. OAuth delegation flow (authenticate as controller), scope-based permissions (owner/admin/editor/viewer presets), scope intersection (tokens limited to granted permissions), `act` claim for delegation tracking, creating delegated account flow, controller management UI, "act as" account switcher, comprehensive audit logging with actor/controller tracking, delegation-aware OAuth consent with permission limitation notices.

Migration: OAuth-based inbound migration wizard with PLC token flow, offline restore from CAR file + rotation key for disaster recovery, scheduled automatic backups, standalone repo/blob export, did:web DID document editor for self-service identity management.
