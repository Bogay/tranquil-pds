# Lewis' BS PDS Sandbox

When I'm actually done then yeah let's make this into a proper official-looking repo perhaps under an official-looking account or something.

This project implements a Personal Data Server (PDS) implementation for the AT Protocol.

Uses PostgreSQL instead of SQLite, S3-compatible blob storage, and aims to be a complete drop-in replacement for Bluesky's reference PDS implementation.

In fact I aim to also implement a plugin system soon, so that we can add things onto our own PDSes on top of the default BS.

I'm also taking ideas on what other PDSes lack, such as an on-PDS webpage that users can access to manage their records and preferences.

:3

# Running locally

The reader will need rust installed locally.

I personally run the postgres db, and an S3-compatible object store with podman compose up db objsto -d.

Run the PDS directly:

    just run

Configuration is via environment variables:

    DATABASE_URL          postgres connection string
    S3_BUCKET             blob storage bucket name
    S3_ENDPOINT           S3 endpoint URL (for MinIO etc)
    AWS_ACCESS_KEY_ID     S3 credentials
    AWS_SECRET_ACCESS_KEY
    AWS_REGION
    PDS_HOSTNAME          public hostname of this PDS
    APPVIEW_URL           appview to proxy unimplemented endpoints to
    RELAYS                comma-separated list of relay WebSocket URLs

Optional email stuff:

    MAIL_FROM_ADDRESS     sender address (enables email notifications)
    MAIL_FROM_NAME        sender name (default: BSPDS)
    SENDMAIL_PATH         path to sendmail binary

Development

    just              shows available commands
    just test         run tests (spins up postgres and minio via testcontainers)
    just lint         clippy + fmt check
    just db-reset     drop and recreate local database

The test suite uses testcontainers so you don't need to set up anything manually for running tests.

## What's implemented

Most of the com.atproto.* namespace is done. Server endpoints, repo operations, sync, identity, admin, moderation. The firehose websocket works. OAuth is not done yet.

See TODO.md for the full breakdown of what's done and what's left.

Structure

    src/
      main.rs           server entrypoint
      lib.rs            router setup
      state.rs          app state (db pool, stores)
      api/              XRPC handlers organized by namespace
      auth/             JWT handling
      repo/             postgres block store
      storage/          S3 blob storage
      sync/             firehose, relay clients
      notifications/    email service
    tests/              integration tests
    migrations/         sqlx migrations

License

idk
