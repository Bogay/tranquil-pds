# PDS Implementation TODOs

Lewis' corrected big boy todofile

## Server Infrastructure & Proxying
- [x] Health Check
    - [x] Implement `GET /health` endpoint (returns "OK").
    - [x] Implement `GET /xrpc/_health` endpoint (returns "OK").
- [x] Server Description
    - [x] Implement `com.atproto.server.describeServer` (returns available user domains).
- [x] XRPC Proxying
    - [x] Implement strict forwarding for all `app.bsky.*` and `chat.bsky.*` requests to an appview.
    - [x] Forward auth headers correctly.
    - [x] Handle appview errors/timeouts gracefully.

## Authentication & Account Management (`com.atproto.server`)
- [x] Account Creation
    - [x] Implement `com.atproto.server.createAccount`.
    - [x] Validate handle format (reject invalid characters).
    - [x] Create DID for new user (PLC directory).
    - [x] Initialize user repository (Root commit).
    - [x] Return access JWT and DID.
    - [x] Create DID for new user (did:web).
- [x] Session Management
    - [x] Implement `com.atproto.server.createSession` (Login).
    - [x] Implement `com.atproto.server.getSession`.
    - [x] Implement `com.atproto.server.refreshSession`.
    - [x] Implement `com.atproto.server.deleteSession` (Logout).
    - [x] Implement `com.atproto.server.activateAccount`.
    - [x] Implement `com.atproto.server.checkAccountStatus`.
    - [x] Implement `com.atproto.server.createAppPassword`.
    - [x] Implement `com.atproto.server.createInviteCode`.
    - [x] Implement `com.atproto.server.createInviteCodes`.
    - [x] Implement `com.atproto.server.deactivateAccount`.
    - [x] Implement `com.atproto.server.deleteAccount` (user-initiated, requires password + email token).
    - [x] Implement `com.atproto.server.getAccountInviteCodes`.
    - [x] Implement `com.atproto.server.getServiceAuth` (Cross-service auth).
    - [x] Implement `com.atproto.server.listAppPasswords`.
    - [x] Implement `com.atproto.server.requestAccountDelete`.
    - [x] Implement `com.atproto.server.requestEmailConfirmation` / `requestEmailUpdate`.
    - [x] Implement `com.atproto.server.requestPasswordReset` / `resetPassword`.
    - [x] Implement `com.atproto.server.reserveSigningKey`.
    - [x] Implement `com.atproto.server.revokeAppPassword`.
    - [x] Implement `com.atproto.server.updateEmail`.
    - [x] Implement `com.atproto.server.confirmEmail`.

## Repository Operations (`com.atproto.repo`)
- [x] Record CRUD
    - [x] Implement `com.atproto.repo.createRecord`.
        - [x] Generate `rkey` (TID) if not provided.
        - [x] Handle MST (Merkle Search Tree) insertion.
        - [x] **Trigger Firehose Event**.
    - [x] Implement `com.atproto.repo.putRecord`.
    - [x] Implement `com.atproto.repo.getRecord`.
    - [x] Implement `com.atproto.repo.deleteRecord`.
    - [x] Implement `com.atproto.repo.listRecords`.
    - [x] Implement `com.atproto.repo.describeRepo`.
    - [x] Implement `com.atproto.repo.applyWrites` (Batch writes).
    - [x] Implement `com.atproto.repo.importRepo` (Migration).
    - [x] Implement `com.atproto.repo.listMissingBlobs`.
- [x] Blob Management
    - [x] Implement `com.atproto.repo.uploadBlob`.
        - [x] Store blob (S3).
        - [x] return `blob` ref (CID + MimeType).

## Sync & Federation (`com.atproto.sync`)
- [x] The Firehose (WebSocket)
    - [x] Implement `com.atproto.sync.subscribeRepos`.
        - [x] Broadcast real-time commit events.
        - [x] Handle cursor replay (backfill).
- [x] Bulk Export
    - [x] Implement `com.atproto.sync.getRepo` (Return full CAR file of repo).
    - [x] Implement `com.atproto.sync.getBlocks` (Return specific blocks via CIDs).
    - [x] Implement `com.atproto.sync.getLatestCommit`.
    - [x] Implement `com.atproto.sync.getRecord` (Sync version, distinct from repo.getRecord).
    - [x] Implement `com.atproto.sync.getRepoStatus`.
    - [x] Implement `com.atproto.sync.listRepos`.
    - [x] Implement `com.atproto.sync.notifyOfUpdate`.
- [x] Blob Sync
    - [x] Implement `com.atproto.sync.getBlob`.
    - [x] Implement `com.atproto.sync.listBlobs`.
- [x] Crawler Interaction
    - [x] Implement `com.atproto.sync.requestCrawl` (Notify relays to index us).
- [x] Deprecated Sync Endpoints (for compatibility)
    - [x] Implement `com.atproto.sync.getCheckout` (deprecated).
    - [x] Implement `com.atproto.sync.getHead` (deprecated).

## Identity (`com.atproto.identity`)
- [x] Resolution
    - [x] Implement `com.atproto.identity.resolveHandle` (Can be internal or proxy to PLC).
    - [x] Implement `com.atproto.identity.updateHandle`.
    - [x] Implement `com.atproto.identity.submitPlcOperation` / `signPlcOperation` / `requestPlcOperationSignature`.
    - [x] Implement `com.atproto.identity.getRecommendedDidCredentials`.
    - [x] Implement `/.well-known/did.json` (Depends on supporting did:web).

## Admin Management (`com.atproto.admin`)
- [x] Implement `com.atproto.admin.deleteAccount`.
- [x] Implement `com.atproto.admin.disableAccountInvites`.
- [x] Implement `com.atproto.admin.disableInviteCodes`.
- [x] Implement `com.atproto.admin.enableAccountInvites`.
- [x] Implement `com.atproto.admin.getAccountInfo` / `getAccountInfos`.
- [x] Implement `com.atproto.admin.getInviteCodes`.
- [x] Implement `com.atproto.admin.getSubjectStatus`.
- [x] Implement `com.atproto.admin.sendEmail`.
- [x] Implement `com.atproto.admin.updateAccountEmail`.
- [x] Implement `com.atproto.admin.updateAccountHandle`.
- [x] Implement `com.atproto.admin.updateAccountPassword`.
- [x] Implement `com.atproto.admin.updateSubjectStatus`.

## Moderation (`com.atproto.moderation`)
- [x] Implement `com.atproto.moderation.createReport`.

## Temp Namespace (`com.atproto.temp`)
- [x] Implement `com.atproto.temp.checkSignupQueue` (signup queue status for gated signups).

## Misc HTTP Endpoints
- [x] Implement `/robots.txt` endpoint.

## OAuth 2.1 Support
Full OAuth 2.1 provider for ATProto native app authentication.
- [x] OAuth Provider Core
    - [x] Implement `/.well-known/oauth-protected-resource` metadata endpoint.
    - [x] Implement `/.well-known/oauth-authorization-server` metadata endpoint.
    - [x] Implement `/oauth/authorize` authorization endpoint (with login UI).
    - [x] Implement `/oauth/par` Pushed Authorization Request endpoint.
    - [x] Implement `/oauth/token` token endpoint (authorization_code + refresh_token grants).
    - [x] Implement `/oauth/jwks` JSON Web Key Set endpoint.
    - [x] Implement `/oauth/revoke` token revocation endpoint.
    - [x] Implement `/oauth/introspect` token introspection endpoint.
- [x] OAuth Database Tables
    - [x] Device table for tracking authorized devices.
    - [x] Authorization request table.
    - [x] Authorized client table.
    - [x] Token table for OAuth tokens.
    - [x] Used refresh token table (replay protection).
    - [x] DPoP JTI tracking table.
- [x] DPoP (Demonstrating Proof-of-Possession) support.
- [x] Client metadata fetching and validation.
- [x] PKCE (S256) enforcement.
- [x] OAuth token verification extractor for protected resources.
- [x] Authorization UI templates (HTML login form).
- [x] Implement `private_key_jwt` signature verification with async JWKS fetching.
- [x] HS256 JWT support (matches reference PDS).

## OAuth Security Notes

Security measures implemented:

- Constant-time comparison for signature verification (prevents timing attacks)
- HMAC-SHA256 for access token signing with configurable secret
- Production secrets require 32+ character minimum
- DPoP JTI replay protection via database
- DPoP nonce validation with HMAC-based timestamps (5 min validity)
- Refresh token rotation with reuse detection (revokes token family on reuse)
- PKCE S256 enforced (plain not allowed)
- Authorization code single-use enforcement
- URL encoding for redirect parameters (prevents injection)
- All database queries use parameterized statements (no SQL injection)
- Deactivated/taken-down accounts blocked from OAuth authorization
- Client ID validation on token exchange (defense-in-depth against cross-client attacks)
- HTML escaping in OAuth templates (XSS prevention)

### Auth Notes
- Dual algorithm support: ES256K (secp256k1 ECDSA) with per-user keys AND HS256 (HMAC) for compatibility with reference PDS.
- Token storage: Storing only token JTIs in session_tokens table (defense in depth against DB breaches). Refresh token family tracking enables detection of token reuse attacks.
- Key encryption: User signing keys encrypted at rest using AES-256-GCM with keys derived via HKDF from KEY_ENCRYPTION_KEY environment variable.

## PDS-Level App Endpoints
These endpoints need to be implemented at the PDS level (not just proxied to appview).

### Actor (`app.bsky.actor`)
- [x] Implement `app.bsky.actor.getPreferences` (user preferences storage).
- [x] Implement `app.bsky.actor.putPreferences` (update user preferences).
- [x] Implement `app.bsky.actor.getProfile` (PDS-level with proxy fallback).
- [x] Implement `app.bsky.actor.getProfiles` (PDS-level with proxy fallback).

### Feed (`app.bsky.feed`)
These are implemented at PDS level to enable local-first reads (read-after-write pattern):
- [x] Implement `app.bsky.feed.getTimeline` (PDS-level with proxy + RAW).
- [x] Implement `app.bsky.feed.getAuthorFeed` (PDS-level with proxy + RAW).
- [x] Implement `app.bsky.feed.getActorLikes` (PDS-level with proxy + RAW).
- [x] Implement `app.bsky.feed.getPostThread` (PDS-level with proxy + RAW + NotFound handling).
- [x] Implement `app.bsky.feed.getFeed` (proxy to feed generator).

### Notification (`app.bsky.notification`)
- [x] Implement `app.bsky.notification.registerPush` (push notification registration, proxied).

## Infrastructure & Core Components
- [x] Sequencer (Event Log)
    - [x] Implement a `Sequencer` (backed by `repo_seq` table).
    - [x] Implement event formatting (`commit`, `handle`, `identity`, `account`).
    - [x] Implement database polling / event emission mechanism.
    - [x] Implement cursor-based event replay (`requestSeqRange`).
- [x] Repo Storage & Consistency (in postgres)
    - [x] Implement `RepoStorage` for postgres (replaces per-user SQLite).
        - [x] Read/Write IPLD blocks to `blocks` table (global deduplication).
        - [x] Manage Repo Root in `repos` table.
    - [x] Implement Atomic Repo Transactions.
        - [x] Ensure `blocks` write, `repo_root` update, `records` index update, and `sequencer` event are committed in a single transaction.
    - [x] Implement concurrency control (row-level locking via FOR UPDATE).
- [ ] DID Cache
    - [ ] Implement caching layer for DID resolution (Redis or in-memory).
    - [ ] Handle cache invalidation/expiry.
- [x] Crawlers Service
    - [x] Implement `Crawlers` service (debounce notifications to relays).
    - [x] 20-minute notification debounce.
    - [x] Circuit breaker for relay failures.
- [x] Notification Service
    - [x] Queue-based notification system with database table
    - [x] Background worker polling for pending notifications
    - [x] Extensible sender trait for multiple channels
    - [x] Email sender via OS sendmail/msmtp
    - [x] Discord webhook sender
    - [x] Telegram bot sender
    - [x] Signal CLI sender
    - [x] Helper functions for common notification types (welcome, password reset, email verification, etc.)
    - [x] Respect user's `preferred_notification_channel` setting for non-email-specific notifications
- [x] Image Processing
    - [x] Implement image resize/formatting pipeline (for blob uploads).
    - [x] WebP conversion for thumbnails.
    - [x] EXIF stripping.
    - [x] File size limits (10MB default).
- [x] IPLD & MST
    - [x] Implement Merkle Search Tree logic for repo signing.
    - [x] Implement CAR (Content Addressable Archive) encoding/decoding.
    - [x] Cycle detection in CAR export.
- [x] Rate Limiting
    - [x] Per-IP rate limiting on login (10/min).
    - [x] Per-IP rate limiting on OAuth token endpoint (30/min).
    - [x] Per-IP rate limiting on password reset (5/hour).
    - [x] Per-IP rate limiting on account creation (10/hour).
- [x] Circuit Breakers
    - [x] PLC directory circuit breaker (5 failures → open, 60s timeout).
    - [x] Relay notification circuit breaker (10 failures → open, 30s timeout).
- [x] Security Hardening
    - [x] Email header injection prevention (CRLF sanitization).
    - [x] Signal command injection prevention (phone number validation).
    - [x] Constant-time signature comparison.
    - [x] SSRF protection for outbound requests.

## Lewis' fabulous mini-list of remaining TODOs
- [ ] DID resolution caching (valkey).
- [ ] Record schema validation (generic validation framework).
- [ ] Fix any remaining TODOs in the code.

## Future: Web Management UI
A single-page web app for account management. The frontend (JS framework) calls existing ATProto XRPC endpoints - no server-side rendering or bespoke HTML form handlers.

### Architecture
- [ ] Static SPA served from PDS (or separate static host)
- [ ] Frontend authenticates via OAuth 2.1 flow (same as any ATProto client)
- [ ] All operations use standard XRPC endpoints (existing + new PDS-specific ones below)
- [ ] No server-side sessions or CSRF - pure API client

### PDS-Specific XRPC Endpoints (new)
Absolutely subject to change, "bspds" isn't even the real name of this pds thus far :D
Anyway... endpoints for PDS settings not covered by standard ATProto:
- [ ] `com.bspds.account.getNotificationPrefs` - get preferred channel, verified channels
- [ ] `com.bspds.account.updateNotificationPrefs` - set preferred channel
- [ ] `com.bspds.account.getNotificationHistory` - list past notifications
- [ ] `com.bspds.account.verifyChannel` - initiate verification for Discord/Telegram/Signal
- [ ] `com.bspds.account.confirmChannelVerification` - confirm with code
- [ ] `com.bspds.admin.getServerStats` - user count, storage usage, etc.

### Frontend Views
Uses existing ATProto endpoints where possible:

User Dashboard
- [ ] Account overview (uses `com.atproto.server.getSession`, `com.atproto.admin.getAccountInfo`)
- [ ] Active sessions view (needs new endpoint or extend existing)
- [ ] App passwords (uses `com.atproto.server.listAppPasswords`, `createAppPassword`, `revokeAppPassword`)
- [ ] Invite codes (uses `com.atproto.server.getAccountInviteCodes`, `createInviteCode`)

Notification Preferences
- [ ] Channel selector (uses `com.bspds.account.*` endpoints above)
- [ ] Verification flows for Discord/Telegram/Signal
- [ ] Notification history view

Account Settings
- [ ] Email change (uses `com.atproto.server.requestEmailUpdate`, `updateEmail`)
- [ ] Password change (uses `com.atproto.server.requestPasswordReset`, `resetPassword`)
- [ ] Handle change (uses `com.atproto.identity.updateHandle`)
- [ ] Account deletion (uses `com.atproto.server.requestAccountDelete`, `deleteAccount`)
- [ ] Data export (uses `com.atproto.sync.getRepo`)

Admin Dashboard (privileged users only)
- [ ] User list (uses `com.atproto.admin.getAccountInfos` with pagination)
- [ ] User detail/actions (uses `com.atproto.admin.*` endpoints)
- [ ] Invite management (uses `com.atproto.admin.getInviteCodes`, `disableInviteCodes`)
- [ ] Server stats (uses `com.bspds.admin.getServerStats`)

