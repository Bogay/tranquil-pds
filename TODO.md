# PDS Implementation TODOs

Lewis' corrected big boy todofile

## 1. Server Infrastructure & Proxying
- [x] Health Check
    - [x] Implement `GET /health` endpoint (returns "OK").
- [x] Server Description
    - [x] Implement `com.atproto.server.describeServer` (returns available user domains).
- [x] XRPC Proxying
    - [x] Implement strict forwarding for all `app.bsky.*` and `chat.bsky.*` requests to an appview.
    - [x] Forward Auth headers correctly.
    - [x] Handle AppView errors/timeouts gracefully.

## 2. Authentication & Account Management (`com.atproto.server`)
- [x] Account Creation
    - [x] Implement `com.atproto.server.createAccount`.
    - [x] Validate handle format (reject invalid characters).
    - [x] Create DID for new user (PLC directory).
    - [x] Initialize user repository (Root commit).
    - [x] Return access JWT and DID.
    - [ ] Create DID for new user (did:web).
- [x] Session Management
    - [x] Implement `com.atproto.server.createSession` (Login).
    - [x] Implement `com.atproto.server.getSession`.
    - [x] Implement `com.atproto.server.refreshSession`.
    - [x] Implement `com.atproto.server.deleteSession` (Logout).

## 3. Repository Operations (`com.atproto.repo`)
- [ ] Record CRUD
    - [ ] Implement `com.atproto.repo.createRecord`.
        - [ ] Validate schema against Lexicon (just structure, not complex logic).
        - [ ] Generate `rkey` (TID) if not provided.
        - [ ] Handle MST (Merkle Search Tree) insertion.
        - [ ] **Trigger Firehose Event**.
    - [ ] Implement `com.atproto.repo.putRecord`.
    - [ ] Implement `com.atproto.repo.getRecord`.
    - [ ] Implement `com.atproto.repo.deleteRecord`.
    - [ ] Implement `com.atproto.repo.listRecords`.
    - [ ] Implement `com.atproto.repo.describeRepo`.
- [ ] Blob Management
    - [ ] Implement `com.atproto.repo.uploadBlob`.
        - [ ] Store blob (S3).
        - [ ] return `blob` ref (CID + MimeType).

## 4. Sync & Federation (`com.atproto.sync`)
- [ ] The Firehose (WebSocket)
    - [ ] Implement `com.atproto.sync.subscribeRepos`.
        - [ ] Broadcast real-time commit events.
        - [ ] Handle cursor replay (backfill).
- [ ] Bulk Export
    - [ ] Implement `com.atproto.sync.getRepo` (Return full CAR file of repo).
    - [ ] Implement `com.atproto.sync.getBlocks` (Return specific blocks via CIDs).
    - [ ] Implement `com.atproto.sync.getLatestCommit`.
    - [ ] Implement `com.atproto.sync.getRecord` (Sync version, distinct from repo.getRecord).
- [ ] Blob Sync
    - [ ] Implement `com.atproto.sync.getBlob`.
    - [ ] Implement `com.atproto.sync.listBlobs`.
- [ ] Crawler Interaction
    - [ ] Implement `com.atproto.sync.requestCrawl` (Notify relays to index us).

## 5. Identity (`com.atproto.identity`)
- [ ] Resolution
    - [ ] Implement `com.atproto.identity.resolveHandle` (Can be internal or proxy to PLC).
    - [ ] Implement `/.well-known/did.json` (Depends on supporting did:web).

## 6. Record Schema Validation
- [ ] `app.bsky.feed.post`
- [ ] `app.bsky.feed.like`
- [ ] `app.bsky.feed.repost`
- [ ] `app.bsky.graph.follow`
- [ ] `app.bsky.graph.block`
- [ ] `app.bsky.actor.profile`
- [ ] Other app(view) validation too!!!

## 7. General Requirements
- [ ] IPLD & MST
    - [ ] Implement Merkle Search Tree (MST) logic for repo signing.
    - [ ] Implement CAR (Content Addressable Archives) encoding/decoding.
- [ ] Validation
    - [ ] DID PLC Operations (Sign rotation keys).
