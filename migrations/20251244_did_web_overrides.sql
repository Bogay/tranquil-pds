CREATE TABLE IF NOT EXISTS did_web_overrides (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    verification_methods JSONB NOT NULL DEFAULT '[]',
    also_known_as TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
