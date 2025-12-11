CREATE TABLE plc_operation_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_plc_op_tokens_user ON plc_operation_tokens(user_id);
CREATE INDEX idx_plc_op_tokens_expires ON plc_operation_tokens(expires_at);
