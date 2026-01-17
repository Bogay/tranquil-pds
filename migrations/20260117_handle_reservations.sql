CREATE TABLE handle_reservations (
    handle TEXT PRIMARY KEY,
    reserved_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '5 minutes'
);

CREATE INDEX idx_handle_reservations_expires ON handle_reservations(expires_at);
