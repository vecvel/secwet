-- Relay Database Schema Migration 0002
-- M7 (device revocation, master key rotation) and M8 (collaboration,
-- tree-wise RBAC, branch keys, invitations). docs/m7-m8-architecture.md §8.
--
-- Zero-knowledge invariant: no column holds names, emails, values or keys in
-- plaintext. Emails and invite tokens are stored as SHA-256 hashes only; key
-- material is HPKE-wrapped or sealed by the clients.
--
-- Idempotent: safe to run on every start.

-- ---------------------------------------------------------------------------
-- Devices: membership, revocation directive, persistent device_seq cursor
-- ---------------------------------------------------------------------------
ALTER TABLE devices ADD COLUMN IF NOT EXISTS member_id UUID;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS wipe_requested BOOLEAN NOT NULL DEFAULT false;
-- postcard `SignedRevocation` (public, signed statement)
ALTER TABLE devices ADD COLUMN IF NOT EXISTS revocation BYTEA;
-- Highest device_seq consumed for this device. Survives retention pruning and
-- covers events consumed without being stored (rejected member events).
ALTER TABLE devices ADD COLUMN IF NOT EXISTS last_device_seq BIGINT NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS devices_secwet_member ON devices (secwet_id, member_id);

-- ---------------------------------------------------------------------------
-- Workspaces: highest server_seq removed by retention. A pull cursor below it
-- has lost events (410 cursor_expired). server_seq is global across
-- workspaces, so gaps between one workspace's events are normal and must not
-- be mistaken for pruning.
-- ---------------------------------------------------------------------------
ALTER TABLE secwets ADD COLUMN IF NOT EXISTS pruned_seq BIGINT NOT NULL DEFAULT 0;

-- ---------------------------------------------------------------------------
-- Events: clear routing scope (space id only)
-- ---------------------------------------------------------------------------
ALTER TABLE events ADD COLUMN IF NOT EXISTS scope_space UUID;

CREATE INDEX IF NOT EXISTS events_secwet_scope_seq ON events (secwet_id, scope_space, server_seq);

-- ---------------------------------------------------------------------------
-- Members
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS workspace_members (
    secwet_id UUID NOT NULL REFERENCES secwets ON DELETE CASCADE,
    member_id UUID NOT NULL,
    email_hash BYTEA NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('invited', 'active', 'removed')),
    -- postcard `SignedGrantSet` (identifiers and roles only, signed by an admin)
    grants BYTEA NOT NULL,
    grants_version BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    removed_at TIMESTAMPTZ,
    PRIMARY KEY (secwet_id, member_id)
);

-- Clear role rows used for enforcement. Rebuilt from the signed set on every
-- update; never edited independently.
CREATE TABLE IF NOT EXISTS member_grants (
    secwet_id UUID NOT NULL,
    member_id UUID NOT NULL,
    node_kind TEXT NOT NULL CHECK (node_kind IN ('workspace', 'space', 'group', 'item', 'general', 'environment')),
    node_id UUID,
    space_id UUID,
    role TEXT NOT NULL CHECK (role IN ('no_access', 'viewer', 'editor', 'admin')),
    FOREIGN KEY (secwet_id, member_id) REFERENCES workspace_members (secwet_id, member_id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS member_grants_node
    ON member_grants (secwet_id, member_id, node_kind, COALESCE(node_id, '00000000-0000-0000-0000-000000000000'::uuid));

-- ---------------------------------------------------------------------------
-- Invitations
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS invitations (
    id UUID PRIMARY KEY,
    secwet_id UUID NOT NULL REFERENCES secwets ON DELETE CASCADE,
    member_id UUID NOT NULL,
    email_hash BYTEA NOT NULL,
    token_hash BYTEA NOT NULL,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'accepted', 'active', 'revoked', 'expired')),
    -- postcard `InviteAcceptance` (public keys and HKDF binding only)
    acceptance BYTEA,
    accepted_device_id TEXT
);

CREATE INDEX IF NOT EXISTS invitations_secwet ON invitations (secwet_id);
-- At most one pending invitation per email hash and workspace.
CREATE UNIQUE INDEX IF NOT EXISTS invitations_pending_email
    ON invitations (secwet_id, email_hash) WHERE status = 'pending';

-- ---------------------------------------------------------------------------
-- Branch keys (per shared space, per branch epoch, per device)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS branch_scopes (
    secwet_id UUID NOT NULL REFERENCES secwets ON DELETE CASCADE,
    space_id UUID NOT NULL,
    current_epoch INT NOT NULL,
    PRIMARY KEY (secwet_id, space_id)
);

CREATE TABLE IF NOT EXISTS branch_keys (
    secwet_id UUID NOT NULL REFERENCES secwets ON DELETE CASCADE,
    space_id UUID NOT NULL,
    epoch INT NOT NULL,
    device_id TEXT NOT NULL,
    -- postcard `WrappedKey` (HPKE-wrapped bundle key)
    wrapped BYTEA NOT NULL,
    -- XChaCha20-Poly1305 sealed `BranchKeyBundle`
    sealed_bundle BYTEA NOT NULL,
    PRIMARY KEY (secwet_id, space_id, epoch, device_id)
);

CREATE INDEX IF NOT EXISTS branch_keys_device ON branch_keys (secwet_id, device_id);
