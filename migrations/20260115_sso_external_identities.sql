CREATE TYPE sso_provider_type AS ENUM ('github', 'discord', 'google', 'gitlab', 'oidc');

CREATE TABLE external_identities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    did TEXT NOT NULL REFERENCES users(did) ON DELETE CASCADE,
    provider sso_provider_type NOT NULL,
    provider_user_id TEXT NOT NULL,
    provider_username TEXT,
    provider_email TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ,
    UNIQUE(provider, provider_user_id),
    UNIQUE(did, provider)
);

CREATE INDEX idx_external_identities_did ON external_identities(did);
CREATE INDEX idx_external_identities_provider_user ON external_identities(provider, provider_user_id);

CREATE TABLE sso_auth_state (
    state TEXT PRIMARY KEY,
    request_uri TEXT NOT NULL,
    provider sso_provider_type NOT NULL,
    action TEXT NOT NULL,
    nonce TEXT,
    code_verifier TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '10 minutes'
);

CREATE INDEX idx_sso_auth_state_expires ON sso_auth_state(expires_at);

CREATE TABLE sso_pending_registration (
    token TEXT PRIMARY KEY,
    request_uri TEXT NOT NULL,
    provider sso_provider_type NOT NULL,
    provider_user_id TEXT NOT NULL,
    provider_username TEXT,
    provider_email TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '10 minutes'
);

CREATE INDEX idx_sso_pending_registration_expires ON sso_pending_registration(expires_at);
