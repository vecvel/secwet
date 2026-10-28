-- Relay Database Schema Migration 0001
-- Section 8.3 & Zero-Knowledge Invariants

CREATE TABLE IF NOT EXISTS secwets (
    id UUID PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    current_epoch INT NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS entitlements (
    secwet_id UUID PRIMARY KEY REFERENCES secwets ON DELETE CASCADE,
    plan TEXT NOT NULL,
    device_limit INT NOT NULL,
    expires_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    secwet_id UUID NOT NULL REFERENCES secwets ON DELETE CASCADE,
    sign_pub BYTEA NOT NULL,
    enc_pub BYTEA NOT NULL,
    added_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    last_seen_at TIMESTAMPTZ,
    ack_seq BIGINT NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS devices_secwet_id ON devices (secwet_id);

CREATE TABLE IF NOT EXISTS wrapped_keys (
    secwet_id UUID NOT NULL REFERENCES secwets ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    epoch INT NOT NULL,
    enc BYTEA NOT NULL,
    ciphertext BYTEA NOT NULL,
    PRIMARY KEY (secwet_id, device_id, epoch)
);

CREATE TABLE IF NOT EXISTS events (
    server_seq BIGSERIAL PRIMARY KEY,
    secwet_id UUID NOT NULL REFERENCES secwets ON DELETE CASCADE,
    event_id BYTEA NOT NULL UNIQUE,
    device_id TEXT NOT NULL,
    device_seq BIGINT NOT NULL,
    envelope BYTEA NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (device_id, device_seq)
);

CREATE INDEX IF NOT EXISTS events_secwet_seq ON events (secwet_id, server_seq);

CREATE TABLE IF NOT EXISTS snapshots (
    secwet_id UUID PRIMARY KEY REFERENCES secwets ON DELETE CASCADE,
    server_seq BIGINT NOT NULL,
    key_epoch INT NOT NULL,
    nonce BYTEA NOT NULL,
    ciphertext BYTEA NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS recovery_blobs (
    secwet_id UUID PRIMARY KEY REFERENCES secwets ON DELETE CASCADE,
    ciphertext BYTEA NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS pairing_sessions (
    id UUID PRIMARY KEY,
    secwet_id UUID NOT NULL REFERENCES secwets ON DELETE CASCADE,
    created_by TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    a_eph_pub BYTEA,
    join_payload BYTEA,
    approved BOOLEAN NOT NULL DEFAULT false,
    wrapped_keys BYTEA,
    new_device_id TEXT
);

ALTER TABLE pairing_sessions ADD COLUMN IF NOT EXISTS a_eph_pub BYTEA;
ALTER TABLE pairing_sessions ADD COLUMN IF NOT EXISTS wrapped_keys BYTEA;
ALTER TABLE pairing_sessions ADD COLUMN IF NOT EXISTS new_device_id TEXT;

CREATE INDEX IF NOT EXISTS pairing_sessions_expires_at ON pairing_sessions (expires_at);

CREATE TABLE IF NOT EXISTS seen_nonces (
    device_id TEXT NOT NULL,
    nonce BYTEA NOT NULL,
    seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, nonce)
);

CREATE INDEX IF NOT EXISTS seen_nonces_seen_at ON seen_nonces (seen_at);
