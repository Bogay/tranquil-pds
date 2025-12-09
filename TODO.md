# PDS Implementation TODOs

Lewis' corrected big boy todofile

## Server Infrastructure & Proxying
- [x] Health Check
    - [x] Implement `GET /health` endpoint (returns "OK").
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
    - [x] Implement `com.atproto.server.deactivateAccount` / `deleteAccount`.
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
- [ ] Record CRUD
    - [x] Implement `com.atproto.repo.createRecord`.
        - [ ] Validate schema against Lexicon (just structure, not complex logic).
        - [x] Generate `rkey` (TID) if not provided.
        - [x] Handle MST (Merkle Search Tree) insertion.
        - [ ] **Trigger Firehose Event**.
    - [x] Implement `com.atproto.repo.putRecord`.
    - [x] Implement `com.atproto.repo.getRecord`.
    - [x] Implement `com.atproto.repo.deleteRecord`.
    - [x] Implement `com.atproto.repo.listRecords`.
    - [x] Implement `com.atproto.repo.describeRepo`.
    - [x] Implement `com.atproto.repo.applyWrites` (Batch writes).
    - [ ] Implement `com.atproto.repo.importRepo` (Migration).
    - [x] Implement `com.atproto.repo.listMissingBlobs`.
- [ ] Blob Management
    - [x] Implement `com.atproto.repo.uploadBlob`.
        - [x] Store blob (S3).
        - [x] return `blob` ref (CID + MimeType).

## Sync & Federation (`com.atproto.sync`)
- [ ] The Firehose (WebSocket)
    - [ ] Implement `com.atproto.sync.subscribeRepos`.
        - [ ] Broadcast real-time commit events.
        - [ ] Handle cursor replay (backfill).
- [ ] Bulk Export
    - [x] Implement `com.atproto.sync.getRepo` (Return full CAR file of repo).
    - [x] Implement `com.atproto.sync.getBlocks` (Return specific blocks via CIDs).
    - [x] Implement `com.atproto.sync.getLatestCommit`.
    - [x] Implement `com.atproto.sync.getRecord` (Sync version, distinct from repo.getRecord).
    - [x] Implement `com.atproto.sync.getRepoStatus`.
    - [x] Implement `com.atproto.sync.listRepos`.
    - [x] Implement `com.atproto.sync.notifyOfUpdate`.
- [ ] Blob Sync
    - [x] Implement `com.atproto.sync.getBlob`.
    - [x] Implement `com.atproto.sync.listBlobs`.
- [x] Crawler Interaction
    - [x] Implement `com.atproto.sync.requestCrawl` (Notify relays to index us).

## Identity (`com.atproto.identity`)
- [ ] Resolution
    - [x] Implement `com.atproto.identity.resolveHandle` (Can be internal or proxy to PLC).
    - [x] Implement `com.atproto.identity.updateHandle`.
    - [ ] Implement `com.atproto.identity.submitPlcOperation` / `signPlcOperation` / `requestPlcOperationSignature`.
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

## Record Schema Validation
- [ ] Handle this generically.

## Infrastructure & Core Components
- [ ] Sequencer (Event Log)
    - [ ] Implement a `Sequencer` (backed by `repo_seq` table? Like in ref impl).
    - [ ] Implement event formatting (`commit`, `handle`, `identity`, `account`).
    - [ ] Implement database polling / event emission mechanism.
    - [ ] Implement cursor-based event replay (`requestSeqRange`).
- [ ] Repo Storage & Consistency (in postgres)
    - [ ] Implement `RepoStorage` for postgres (replaces per-user SQLite).
        - [ ] Read/Write IPLD blocks to `blocks` table (global deduplication).
        - [ ] Manage Repo Root in `repos` table.
    - [ ] Implement Atomic Repo Transactions.
        - [ ] Ensure `blocks` write, `repo_root` update, `records` index update, and `sequencer` event are committed in a single transaction.
    - [ ] Implement concurrency control (row-level locking on `repos` table) to prevent concurrent writes to the same repo.
- [ ] DID Cache
    - [ ] Implement caching layer for DID resolution (Redis or in-memory).
    - [ ] Handle cache invalidation/expiry.
- [ ] Background Jobs
    - [ ] Implement `Crawlers` service (debounce notifications to relays).
- [x] Notification Service
    - [x] Queue-based notification system with database table
    - [x] Background worker polling for pending notifications
    - [x] Extensible sender trait for multiple channels
    - [x] Email sender via OS sendmail/msmtp
    - [ ] Discord bot sender
    - [ ] Telegram bot sender
    - [ ] Signal bot sender
    - [x] Helper functions for common notification types (welcome, password reset, email verification, etc.)
- [ ] Image Processing
    - [ ] Implement image resize/formatting pipeline (for blob uploads).
- [ ] IPLD & MST
    - [ ] Implement Merkle Search Tree logic for repo signing.
    - [ ] Implement CAR (Content Addressable Archive) encoding/decoding.
- [ ] Validation
    - [ ] DID PLC Operations (Sign rotation keys).
- [ ] Fix any remaining TODOs in the code, everywhere, full stop.

