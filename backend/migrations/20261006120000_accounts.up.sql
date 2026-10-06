CREATE TABLE account_user (
    id UUID PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    totp_secret BYTEA,
    totp_last_step BIGINT NOT NULL DEFAULT -1,
    pending_secret BYTEA,
    pending_until TIMESTAMPTZ,
    pending_session TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE account_session (
    token_hash TEXT PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES account_user(id) ON DELETE CASCADE,
    verified BOOLEAN NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX account_session_user ON account_session(user_id);
CREATE INDEX account_session_expiry ON account_session(expires_at);
CREATE TABLE account_recovery_code (
    user_id UUID NOT NULL REFERENCES account_user(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    PRIMARY KEY (user_id, code_hash)
);
-- Database-backed admission limits work across multiple backend processes.
CREATE TABLE account_rate_limit (
    key TEXT PRIMARY KEY,
    attempts INTEGER NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);
ALTER TABLE v1_bulk_job ADD COLUMN owner_id UUID REFERENCES account_user(id);
CREATE INDEX v1_bulk_job_owner ON v1_bulk_job(owner_id);
