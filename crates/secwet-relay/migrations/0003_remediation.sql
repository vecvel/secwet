-- Relay Database Schema Migration 0003
-- M7/M8 remediation: signed rotation statements, signed branch publishes,
-- revocation cut-off, per-space pruning watermarks.
--
-- Idempotent: safe to run on every start. No plaintext columns.

-- Highest server_seq of the workspace when the device was revoked.
ALTER TABLE devices ADD COLUMN IF NOT EXISTS revoked_seq BIGINT;

-- Signed `KeyRotationStatement` per opened epoch (postcard
-- `SignedRotationStatement`), returned to devices catching up.
CREATE TABLE IF NOT EXISTS rotation_statements (
    secwet_id UUID NOT NULL REFERENCES secwets ON DELETE CASCADE,
    epoch INT NOT NULL,
    statement BYTEA NOT NULL,
    PRIMARY KEY (secwet_id, epoch)
);

-- The signed publish (postcard `SignedBranchStatement`) a bundle came from.
ALTER TABLE branch_keys ADD COLUMN IF NOT EXISTS statement BYTEA;

-- Highest pruned server_seq per routing space, so a member device only gets
-- 410 cursor_expired when an event it could see was pruned.
CREATE TABLE IF NOT EXISTS scope_pruned (
    secwet_id UUID NOT NULL REFERENCES secwets ON DELETE CASCADE,
    scope_space UUID NOT NULL,
    pruned_seq BIGINT NOT NULL,
    PRIMARY KEY (secwet_id, scope_space)
);
