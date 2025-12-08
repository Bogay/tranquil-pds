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
    - [ ] Implement `com.atproto.server.activateAccount`.
    - [ ] Implement `com.atproto.server.checkAccountStatus`.
    - [ ] Implement `com.atproto.server.confirmEmail`.
    - [ ] Implement `com.atproto.server.createAppPassword`.
    - [ ] Implement `com.atproto.server.createInviteCode`.
    - [ ] Implement `com.atproto.server.createInviteCodes`.
    - [ ] Implement `com.atproto.server.deactivateAccount` / `deleteAccount`.
    - [ ] Implement `com.atproto.server.getAccountInviteCodes`.
    - [x] Implement `com.atproto.server.getServiceAuth` (Cross-service auth).
    - [ ] Implement `com.atproto.server.listAppPasswords`.
    - [ ] Implement `com.atproto.server.requestAccountDelete`.
    - [ ] Implement `com.atproto.server.requestEmailConfirmation` / `requestEmailUpdate`.
    - [ ] Implement `com.atproto.server.requestPasswordReset` / `resetPassword`.
    - [ ] Implement `com.atproto.server.reserveSigningKey`.
    - [ ] Implement `com.atproto.server.revokeAppPassword`.
    - [ ] Implement `com.atproto.server.updateEmail`.

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
    - [ ] Implement `com.atproto.repo.listMissingBlobs`.
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
    - [ ] Implement `com.atproto.sync.getRepo` (Return full CAR file of repo).
    - [ ] Implement `com.atproto.sync.getBlocks` (Return specific blocks via CIDs).
    - [x] Implement `com.atproto.sync.getLatestCommit`.
    - [ ] Implement `com.atproto.sync.getRecord` (Sync version, distinct from repo.getRecord).
    - [ ] Implement `com.atproto.sync.getRepoStatus`.
    - [x] Implement `com.atproto.sync.listRepos`.
    - [ ] Implement `com.atproto.sync.notifyOfUpdate`.
- [ ] Blob Sync
    - [ ] Implement `com.atproto.sync.getBlob`.
    - [ ] Implement `com.atproto.sync.listBlobs`.
- [ ] Crawler Interaction
    - [ ] Implement `com.atproto.sync.requestCrawl` (Notify relays to index us).

## Identity (`com.atproto.identity`)
- [ ] Resolution
    - [x] Implement `com.atproto.identity.resolveHandle` (Can be internal or proxy to PLC).
    - [ ] Implement `com.atproto.identity.updateHandle`.
    - [ ] Implement `com.atproto.identity.submitPlcOperation` / `signPlcOperation` / `requestPlcOperationSignature`.
    - [ ] Implement `com.atproto.identity.getRecommendedDidCredentials`.
    - [x] Implement `/.well-known/did.json` (Depends on supporting did:web).

## Admin Management (`com.atproto.admin`)
- [ ] Implement `com.atproto.admin.deleteAccount`.
- [ ] Implement `com.atproto.admin.disableAccountInvites`.
- [ ] Implement `com.atproto.admin.disableInviteCodes`.
- [ ] Implement `com.atproto.admin.enableAccountInvites`.
- [ ] Implement `com.atproto.admin.getAccountInfo` / `getAccountInfos`.
- [ ] Implement `com.atproto.admin.getInviteCodes`.
- [ ] Implement `com.atproto.admin.getSubjectStatus`.
- [ ] Implement `com.atproto.admin.sendEmail`.
- [ ] Implement `com.atproto.admin.updateAccountEmail`.
- [ ] Implement `com.atproto.admin.updateAccountHandle`.
- [ ] Implement `com.atproto.admin.updateAccountPassword`.
- [ ] Implement `com.atproto.admin.updateSubjectStatus`.

## Moderation (`com.atproto.moderation`)
- [ ] Implement `com.atproto.moderation.createReport`.

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
    - [ ] Implement background queue for async tasks (crawler notifications, discord/telegram 2FA sending instead of email).
    - [ ] Implement `Crawlers` service (debounce notifications to relays).
- [ ] Mailer equivalent
    - [ ] Implement code/notification sending service as a replacement for the mailer because there's no way I'm starting with email. :D
- [ ] Image Processing
    - [ ] Implement image resize/formatting pipeline (for blob uploads).
- [ ] IPLD & MST
    - [ ] Implement Merkle Search Tree logic for repo signing.
    - [ ] Implement CAR (Content Addressable Archive) encoding/decoding.
- [ ] Validation
    - [ ] DID PLC Operations (Sign rotation keys).
- [ ] Fix any remaining TODOs in the code, everywhere, full stop.

