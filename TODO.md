# Lewis' Big Boy TODO list

## Active development

### OAuth scope authorization UI
Display and manage OAuth scopes during authorization flows.

- [ ] Parse and display requested scopes from authorization request
- [ ] Human-readable scope descriptions (e.g., "Read your posts" not "app.bsky.feed.read")
- [ ] Group scopes by category (read, write, admin, etc.)
- [ ] Allow users to uncheck optional scopes before authorizing
- [ ] Distinguish required vs optional scopes in UI
- [ ] Remember scope preferences per client (don't ask again for same scopes)
- [ ] Token endpoint respects user's scope selections
- [ ] Protected endpoints check token scopes before allowing operations

### Frontend
So like... make the thing unique, make it cool.

- [ ] Frontpage that explains what this thing is
- [ ] Unique "brand" style both unauthed and authed
- [ ] Better documentation on how to sub out the entire frontend for whatever the users want

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

### Passkey support
Modern passwordless authentication using WebAuthn/FIDO2, alongside or instead of passwords.

- [ ] passkeys table (id, did, credential_id, public_key, sign_count, created_at, last_used, friendly_name)
- [ ] Generate WebAuthn registration challenge
- [ ] Verify attestation response and store credential
- [ ] UI for registering new passkey from settings
- [ ] Detect if account has passkeys during OAuth authorize
- [ ] Offer passkey option alongside password
- [ ] Generate authentication challenge and verify assertion
- [ ] Update sign count (replay protection)
- [ ] Allow creating account with passkey instead of password
- [ ] List/rename/remove passkeys in settings

### Private/encrypted data
Records that only authorized parties can see and decrypt. Requires key federation between PDSes.

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

Core ATProto: Health, describeServer, all session endpoints, full repo CRUD, applyWrites, blob upload, importRepo, firehose with cursor replay, CAR export, blob sync, crawler notifications, handle resolution, PLC operations, did:web, full admin API, moderation reports.

OAuth 2.1: Authorization server metadata, JWKS, PAR, authorize endpoint with login UI, token endpoint (auth code + refresh), revocation, introspection, DPoP, PKCE S256, client metadata validation, private_key_jwt verification.

App endpoints: getPreferences, putPreferences, getProfile, getProfiles, getTimeline, getAuthorFeed, getActorLikes, getPostThread, getFeed, registerPush (all with local-first + proxy fallback).

Infrastructure: Sequencer with cursor replay, postgres repo storage with atomic transactions, valkey DID cache, debounced crawler notifications with circuit breakers, multi-channel notifications (email/Discord/Telegram/Signal), image processing, distributed rate limiting, security hardening.

Web UI: OAuth login, registration, email verification, password reset, multi-account selector, dashboard, sessions, app passwords, invites, notification preferences, repo browser, CAR export, admin panel.

Auth: ES256K + HS256 dual support, JTI-only token storage, refresh token family tracking, encrypted signing keys (AES-256-GCM), DPoP replay protection, constant-time comparisons.
