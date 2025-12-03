# Implementation TODOs

Lewis' special big boy todofile

## 1. Server Infrastructure & Health
- [x] Health Check
    - [x] Implement `GET /health` endpoint (returns "OK").
- [x] Server Description
    - [x] Implement `com.atproto.server.describeServer` (returns available user domains).

## 2. Authentication & Account Management (`com.atproto.server`)
- [x] Account Creation
    - [x] Implement `com.atproto.server.createAccount`.
    - [x] Validate handle format (reject invalid characters).
    - [x] Create DID for new user.
    - [x] Initialize user repository.
    - [x] Return access JWT and DID.
    - [x] MST stuff I think...

- [x] Session Management
    - [x] Implement `com.atproto.server.createSession` (Login).
        - [x] Validate identifier (handle/email) and password.
        - [x] Return access JWT, refresh JWT, and DID.
    - [x] Implement `com.atproto.server.getSession`.
        - [x] Verify JWT validity.
    - [x] Implement `com.atproto.server.refreshSession`.
    - [x] Implement `com.atproto.server.deleteSession` (Logout).
        - [x] Invalidate current session/token.

## 3. Repository Operations (`com.atproto.repo`)
- [ ] Record CRUD
    - [ ] Implement `com.atproto.repo.createRecord`.
        - [ ] Generate `rkey` if not provided.
        - [ ] Validate schema against Lexicon.
        - [ ] Handle `swapCommit` for optimistic locking.
    - [ ] Implement `com.atproto.repo.putRecord`.
        - [ ] Handle create vs update logic.
        - [ ] Validate `repo` matches authenticated user.
        - [ ] Validate record schema (e.g., missing required fields).
    - [ ] Implement `com.atproto.repo.getRecord`.
        - [ ] Handle missing params (400 Bad Request).
        - [ ] Handle non-existent record (404 Not Found).
    - [ ] Implement `com.atproto.repo.deleteRecord`.
    - [ ] Implement `com.atproto.repo.listRecords`.
        - [ ] Support pagination (`limit`, `cursor`).
- [ ] Blob Management
    - [ ] Implement `com.atproto.repo.uploadBlob`.
        - [ ] Enforce authentication.
        - [ ] Validate MIME types (reject unsupported).
        - [ ] Return blob reference (`$link`).
- [ ] Repo Meta
    - [ ] Implement `com.atproto.repo.describeRepo`.

## 4. Actor & Profile (`app.bsky.actor`)
- [ ] Profile Management
    - [ ] Implement `app.bsky.actor.getProfile`.
        - [ ] Resolve handle to DID.
        - [ ] Return profile record data.
- [ ] Discovery
    - [ ] Implement `app.bsky.actor.searchActors`.

## 5. Feed & Timeline (`app.bsky.feed`)
- [ ] Feed Retrieval
    - [ ] Implement `app.bsky.feed.getTimeline`.
    - [ ] Implement `app.bsky.feed.getAuthorFeed`.
        - [ ] Filter by actor.
        - [ ] Respect mutes (if viewer is authenticated).
    - [ ] Implement `app.bsky.feed.getPostThread`.
        - [ ] Construct thread tree (parents, replies).
        - [ ] Handle deleted posts (return `notFoundPost` view).
- [ ] Record Types
    - [ ] Support `app.bsky.feed.post` record type.
    - [ ] Support `app.bsky.feed.like` record type.
    - [ ] Support `app.bsky.embed.images` in posts.

## 6. Social Graph (`app.bsky.graph`)
- [ ] Relationships
    - [ ] Implement `app.bsky.graph.getFollows`.
    - [ ] Implement `app.bsky.graph.getFollowers`.
    - [ ] Implement `app.bsky.graph.getMutes`.
    - [ ] Implement `app.bsky.graph.getBlocks`.
- [ ] Record Types
    - [ ] Support `app.bsky.graph.follow` record type.
    - [ ] Support `app.bsky.graph.mute` record type.

## 7. Notifications (`app.bsky.notification`)
- [ ] Notification Management
    - [ ] Implement `app.bsky.notification.listNotifications`.
        - [ ] Aggregate notifications (likes, follows, replies).
    - [ ] Implement `app.bsky.notification.getUnreadCount`.
        - [ ] Track read state.
        - [ ] Reset count on list/read.

## 8. Identity (`com.atproto.identity`)
- [ ] Resolution
    - [ ] Implement `com.atproto.identity.resolveHandle`.

## 9. Sync & Federation (`com.atproto.sync`)
- [ ] Data Export
    - [ ] Implement `com.atproto.sync.getRepo` (Export CAR file).
    - [ ] Implement `com.atproto.sync.getBlocks`.

## 10. General Requirements
- [ ] Validation
    - [ ] Ensure all endpoints validate input parameters.
    - [ ] Ensure proper error codes (400, 401, 404, 409).
- [ ] Concurrency
    - [ ] Ensure thread safety for repo updates.
