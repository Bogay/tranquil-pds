CREATE TABLE signal_kv (
    key TEXT PRIMARY KEY,
    value BYTEA NOT NULL
);

CREATE TABLE signal_sessions (
    address TEXT NOT NULL,
    device_id INTEGER NOT NULL CHECK (device_id BETWEEN 0 AND 127),
    identity TEXT NOT NULL CHECK (identity IN ('aci', 'pni')),
    record BYTEA NOT NULL,
    PRIMARY KEY (address, device_id, identity)
);

CREATE TABLE signal_identities (
    address TEXT NOT NULL,
    identity TEXT NOT NULL CHECK (identity IN ('aci', 'pni')),
    record BYTEA NOT NULL,
    PRIMARY KEY (address, identity)
);

CREATE TABLE signal_pre_keys (
    id INTEGER NOT NULL CHECK (id >= 0),
    identity TEXT NOT NULL CHECK (identity IN ('aci', 'pni')),
    record BYTEA NOT NULL,
    PRIMARY KEY (id, identity)
);

CREATE TABLE signal_signed_pre_keys (
    id INTEGER NOT NULL CHECK (id >= 0),
    identity TEXT NOT NULL CHECK (identity IN ('aci', 'pni')),
    record BYTEA NOT NULL,
    PRIMARY KEY (id, identity)
);

CREATE TABLE signal_kyber_pre_keys (
    id INTEGER NOT NULL CHECK (id >= 0),
    identity TEXT NOT NULL CHECK (identity IN ('aci', 'pni')),
    record BYTEA NOT NULL,
    is_last_resort BOOLEAN NOT NULL DEFAULT FALSE,
    stale_at TIMESTAMPTZ,
    PRIMARY KEY (id, identity)
);

CREATE TABLE signal_sender_keys (
    address TEXT NOT NULL,
    device_id INTEGER NOT NULL CHECK (device_id BETWEEN 0 AND 127),
    identity TEXT NOT NULL CHECK (identity IN ('aci', 'pni')),
    distribution_id UUID NOT NULL,
    record BYTEA NOT NULL,
    PRIMARY KEY (address, device_id, identity, distribution_id)
);

CREATE TABLE signal_base_keys_seen (
    kyber_pre_key_id INTEGER NOT NULL CHECK (kyber_pre_key_id >= 0),
    signed_pre_key_id INTEGER NOT NULL CHECK (signed_pre_key_id >= 0),
    identity TEXT NOT NULL CHECK (identity IN ('aci', 'pni')),
    base_key BYTEA NOT NULL,
    PRIMARY KEY (identity, kyber_pre_key_id, signed_pre_key_id, base_key)
);

CREATE TABLE signal_profile_keys (
    uuid UUID PRIMARY KEY,
    key BYTEA NOT NULL
);
