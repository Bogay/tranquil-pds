# Lewis' Big Boy TODO list

## Active development

### Delegated accounts
Accounts controlled by other accounts rather than having their own password. When logging in as a delegated account, OAuth asks you to authenticate with a linked controller account. Uses OAuth scopes as the permission model.

- [ ] Account type flag in actors table (personal | delegated)
- [ ] account_delegations table (delegated_did, controller_did, granted_scopes[], granted_at, granted_by, revoked_at)
- [ ] Detect delegated account during authorize flow
- [ ] Redirect to "authenticate as controller" instead of password prompt
- [ ] Validate controller has delegation grant for this account
- [ ] Issue token with intersection of (requested scopes :intersection-emoji: granted scopes)
- [ ] Token includes act_as claim indicating delegation
- [ ] Define standard scope sets (owner, admin, editor, viewer)
- [ ] Create delegated account flow (no password, must add initial controller)
- [ ] Controller management page (add/remove controllers, modify scopes)
- [ ] "Act as" account switcher for users with delegation grants
- [ ] Log all actions with both actor DID and controller DID
- [ ] Audit log view for delegated account owners

### Migration tool
Seamless account migration built into the UI, inspired by pdsmoover. Users shouldn't need external tools or brain surgery on half-done account states.

- [ ] Add `migratingTo` parameter to `deactivateAccount` endpoint
- [ ] For self-hosted did:web users: set `migrated_to_pds`, update DID doc serviceEndpoint
- [ ] "Migrated" account state for self-hosted did:web: can authenticate but no repo operations
- [ ] Migrated did:web user UI: minimal dashboard with "update forwarding PDS" setting, or full migration wizard to handle PDS 2 -> PDS 3 moves automatically
- [ ] Outbound UI wizard: new PDS URL -> export repo -> guide account creation -> complete migration
- [ ] Inbound UI wizard: login to old PDS -> choose handle -> import -> PLC token flow
- [ ] Support `createAccount` with existing DID + service auth token
- [ ] Progress tracking with resume capability
- [ ] Scheduled automatic backups (CAR export)
- [ ] One-click restore from backup

### Plugin system
Extensible architecture allowing third-party plugins to add functionality, like minecraft mods or browser extensions.

- [ ] Research: survey Fabric/Forge, VS Code, Grafana, Caddy plugin architectures
- [ ] Evaluate rust approaches: WASM, dynamic linking, subprocess IPC, embedded scripting (Lua/Rhai)
- [ ] Define security model (sandboxing, permissions, resource limits)
- [ ] Plugin manifest format (name, version, deps, permissions, hooks)
- [ ] Plugin discovery, loading, lifecycle (enable/disable/hot reload)
- [ ] Error isolation (bad plugin shouldn't crash PDS)
- [ ] Extension points: request middleware, record lifecycle hooks, custom XRPC endpoints
- [ ] Extension points: custom lexicons, storage backends, auth providers, notification channels
- [ ] Extension points: firehose consumers (react to repo events)
- [ ] Plugin SDK crate with traits and helpers
- [ ] Example plugins: custom feed algorithm, content filter, S3 backup
- [ ] Plugin registry with signature verification and version compatibility

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

did:web support: Self-hosted did:web (subdomain format `did:web:handle.pds.com`), external/BYOD did:web, DID document serving via `/.well-known/did.json`, migration tracking for did:web users who leave (serviceEndpoint redirect), clear registration warnings about did:web trade-offs vs did:plc.

OAuth 2.1: Authorization server metadata, JWKS, PAR, authorize endpoint with login UI, token endpoint (auth code + refresh), revocation, introspection, DPoP, PKCE S256, client metadata validation, private_key_jwt verification.

OAuth Scope Enforcement: Full granular scope system with consent UI, human-readable scope descriptions, per-client scope preferences, scope parsing (repo/blob/rpc/account/identity), endpoint-level scope checks, DPoP token support in auth extractors, token revocation on re-authorization, response_mode support (query/fragment).

App endpoints: getPreferences, putPreferences, getProfile, getProfiles, getTimeline, getAuthorFeed, getActorLikes, getPostThread, getFeed, registerPush (all with local-first + proxy fallback).

Infrastructure: Sequencer with cursor replay, postgres repo storage with atomic transactions, valkey DID cache, debounced crawler notifications with circuit breakers, multi-channel notifications (email/Discord/Telegram/Signal), image processing, distributed rate limiting, security hardening.

Web UI: OAuth login, registration, email verification, password reset, multi-account selector, dashboard, sessions, app passwords, invites, notification preferences, repo browser, CAR export, admin panel, OAuth consent screen with scope selection.

Auth: ES256K + HS256 dual support, JTI-only token storage, refresh token family tracking, encrypted signing keys (AES-256-GCM), DPoP replay protection, constant-time comparisons.

Passkeys and 2FA: WebAuthn/FIDO2 passkey registration and authentication, TOTP with QR setup, backup codes (hashed, one-time use), passkey-only account creation, trusted devices (remember this browser), re-auth for sensitive actions, rate-limited 2FA attempts, settings UI for managing all auth methods.

App password scopes: Granular permissions for app passwords using the same scope system as OAuth. Preset buttons for common use cases (full access, read-only, post-only), scope stored in session and preserved across token refresh, explicit RPC/repo/blob scope enforcement for restricted passwords.
