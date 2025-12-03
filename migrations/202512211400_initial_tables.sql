-- A very basic schema to get started.
-- TODO: PRODUCTIONIZE BABY

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    handle TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    did TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS invite_codes (
    code TEXT PRIMARY KEY,
    available_uses INT NOT NULL DEFAULT 1,
    created_by_user UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS invite_code_uses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code TEXT NOT NULL REFERENCES invite_codes(code),
    used_by_user UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    used_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(code, used_by_user)
);

-- OIII THIS TABLE CONTAINS PLAINTEXT PRIVATE KEYS, TODO: encrypt at rest!
CREATE TABLE IF NOT EXISTS user_keys (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    -- Storing as raw bytes
    -- secp256k1 is 32 bytes
    key_bytes BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS repos (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    repo_root_cid TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS blocks (
    cid BYTEA PRIMARY KEY,
    data BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- A denormalized table to quickly query for records
-- TODO: Do I actually need this?
CREATE TABLE IF NOT EXISTS records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repo_id UUID NOT NULL REFERENCES repos(user_id) ON DELETE CASCADE,
    collection TEXT NOT NULL,
    rkey TEXT NOT NULL,
    record_cid TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(repo_id, collection, rkey)
);

CREATE TABLE IF NOT EXISTS blobs (
    cid TEXT PRIMARY KEY,
    mime_type TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    created_by_user UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- The key/path in the S3 bucket
    storage_key TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    access_jwt TEXT PRIMARY KEY,
    refresh_jwt TEXT NOT NULL UNIQUE,
    did TEXT NOT NULL REFERENCES users(did) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

