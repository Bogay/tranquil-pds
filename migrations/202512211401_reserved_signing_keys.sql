CREATE TABLE IF NOT EXISTS reserved_signing_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    did TEXT,
    public_key_did_key TEXT NOT NULL,
    private_key_bytes BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '24 hours',
    used_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_reserved_signing_keys_did ON reserved_signing_keys(did) WHERE did IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_reserved_signing_keys_expires ON reserved_signing_keys(expires_at) WHERE used_at IS NULL;
