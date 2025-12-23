CREATE TABLE IF NOT EXISTS server_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO server_config (key, value) VALUES ('server_name', 'Tranquil PDS') ON CONFLICT DO NOTHING;
