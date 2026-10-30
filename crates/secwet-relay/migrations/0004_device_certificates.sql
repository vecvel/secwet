-- Relay Database Schema Migration 0004
-- Device certificates: a device's public keys signed by a device that
-- vouches for it. Public data only; never pruned by retention.
--
-- Idempotent: safe to run on every start.

CREATE TABLE IF NOT EXISTS device_certificates (
    secwet_id UUID NOT NULL REFERENCES secwets ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    certifier_device_id TEXT NOT NULL,
    issued_at BIGINT NOT NULL,
    -- postcard `SignedDeviceCertificate`
    certificate BYTEA NOT NULL,
    PRIMARY KEY (secwet_id, device_id, certifier_device_id)
);
