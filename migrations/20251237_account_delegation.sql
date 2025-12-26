CREATE TYPE account_type AS ENUM ('personal', 'delegated');

ALTER TABLE users ADD COLUMN account_type account_type NOT NULL DEFAULT 'personal';

CREATE TYPE delegation_action_type AS ENUM (
    'grant_created',
    'grant_revoked',
    'scopes_modified',
    'token_issued',
    'repo_write',
    'blob_upload',
    'account_action'
);

CREATE TABLE account_delegations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    delegated_did TEXT NOT NULL REFERENCES users(did) ON DELETE CASCADE,
    controller_did TEXT NOT NULL REFERENCES users(did) ON DELETE CASCADE,
    granted_scopes TEXT NOT NULL,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    granted_by TEXT NOT NULL REFERENCES users(did),
    revoked_at TIMESTAMPTZ,
    revoked_by TEXT REFERENCES users(did),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX unique_active_delegation ON account_delegations(delegated_did, controller_did)
    WHERE revoked_at IS NULL;
CREATE INDEX idx_delegations_delegated ON account_delegations(delegated_did) WHERE revoked_at IS NULL;
CREATE INDEX idx_delegations_controller ON account_delegations(controller_did) WHERE revoked_at IS NULL;

CREATE TABLE delegation_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    delegated_did TEXT NOT NULL,
    actor_did TEXT NOT NULL,
    controller_did TEXT,
    action_type delegation_action_type NOT NULL,
    action_details JSONB,
    ip_address TEXT,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_delegation_audit_delegated ON delegation_audit_log(delegated_did, created_at DESC);
CREATE INDEX idx_delegation_audit_controller ON delegation_audit_log(controller_did, created_at DESC) WHERE controller_did IS NOT NULL;

ALTER TABLE oauth_authorization_request ADD COLUMN controller_did TEXT;

ALTER TABLE oauth_token ADD COLUMN controller_did TEXT;
CREATE INDEX idx_oauth_token_controller ON oauth_token(controller_did) WHERE controller_did IS NOT NULL;

ALTER TABLE app_passwords ADD COLUMN created_by_controller_did TEXT REFERENCES users(did) ON DELETE SET NULL;
CREATE INDEX idx_app_passwords_controller ON app_passwords(created_by_controller_did) WHERE created_by_controller_did IS NOT NULL;

ALTER TABLE session_tokens ADD COLUMN controller_did TEXT;
