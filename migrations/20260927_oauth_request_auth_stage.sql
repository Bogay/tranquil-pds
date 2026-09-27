ALTER TABLE oauth_authorization_request
    ADD COLUMN auth_stage TEXT NOT NULL DEFAULT 'none',
    ADD CONSTRAINT oauth_authorization_request_auth_stage_check
        CHECK (auth_stage IN ('none', 'first_factor', 'registered', 'complete'));
