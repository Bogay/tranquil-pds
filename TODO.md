# Lewis' Big Boy TODO list

## Active development

### Migration tool
Seamless account migration built into the UI, inspired by pdsmoover. Users shouldn't need external tools or brain surgery on half-done account states.

- [x] Inbound UI wizard: login to old PDS -> choose handle -> import -> PLC token flow
- [x] Support `createAccount` with existing DID + service auth token
- [x] Progress tracking with resume capability
- [ ] Scheduled automatic backups (CAR export)
- [ ] One-click restore from backup

Outbound migration wizard exists but is disabled. Rethinking the approach: instead of a managed flow with `migratingTo` state, pds-hosted did:web users should just have direct control over their DID document. They can independently update serviceEndpoint, add/remove keys, export their repo, deactivate their account.

- [ ] Remove `migratingTo` field and related state machine
- [ ] Let did:web users edit their DID doc fields (serviceEndpoint, keys) whenever
- [ ] Repo export as standalone feature, not tied to migration wizard

### Plugin system
Extensible architecture allowing third-party plugins to add functionality. Going with wasm-based rather than scripting language.

- [ ] Plugin manifest format (name, version, deps, permissions, hooks)
- [ ] Plugin loading and lifecycle (enable/disable/hot reload)
- [ ] WASM host bindings for PDS APIs (database, storage, http, etc.)
- [ ] Resource limits (memory, cpu time, capability restrictions)
- [ ] Extension points: request middleware, record lifecycle hooks, custom XRPC endpoints
- [ ] Extension points: custom lexicons, storage backends, auth providers, notification channels
- [ ] Extension points: firehose consumers (react to repo events)
- [ ] Plugin sdk crate with traits and helpers?
- [ ] Example plugins: cdc, extra logging to 3rd party, content filter, better S3 backup
- [ ] Plugin registry with signature verification?

### Plugin: Private/encrypted data
Records that only authorized parties can see and decrypt. Requires key federation between PDSes. Implemented as a plugin using the plugin system above.

- [ ] Survey current ATProto discourse on private data
- [ ] Document Bluesky team's likely approach
- [ ] Design key management strategy
- [ ] Per-user encryption keys (separate from signing keys)
- [ ] Key derivation for per-record or per-collection encryption
- [ ] Encrypted record storage format
- [ ] Transparent encryption/decryption in repo operations
- [ ] Protocol for sharing decryption keys between PDSes
- [ ] Handle key rotation and revocation

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
