ALTER TABLE external_identities ADD COLUMN provider_email_verified BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE sso_pending_registration ADD COLUMN provider_email_verified BOOLEAN NOT NULL DEFAULT FALSE;
