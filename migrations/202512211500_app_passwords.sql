CREATE TABLE IF NOT EXISTS app_passwords (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    privileged BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE(user_id, name)
);
