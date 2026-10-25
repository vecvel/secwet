-- Non-secret vault metadata
CREATE TABLE meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- Master table for all projects, environments, and secrets
CREATE TABLE records (
  id BLOB PRIMARY KEY,          -- 16-byte UUID v7
  record_type INTEGER NOT NULL, -- 1 = project, 2 = environment, 3 = secret
  parent_id BLOB,               -- project_id for environments; environment_id for secrets; NULL for projects
  key_epoch INTEGER NOT NULL,
  blob BLOB,                    -- Sealed body: version (1) || nonce (24) || ciphertext; NULL when deleted
  lamport INTEGER NOT NULL,
  origin_device TEXT NOT NULL,
  updated_at INTEGER NOT NULL,  -- Unix epoch ms, informational
  deleted INTEGER NOT NULL DEFAULT 0
);

-- Indices for fast tree traversal without decrypting unrelated records
CREATE INDEX records_parent ON records(parent_id);
CREATE INDEX records_type ON records(record_type);

-- Devices authorized in this vault
CREATE TABLE devices (
  device_id TEXT PRIMARY KEY,
  name_blob BLOB NOT NULL,      -- Sealed device name
  sign_pub BLOB NOT NULL,       -- 32-byte Ed25519 public key
  enc_pub BLOB NOT NULL,        -- 32-byte X25519 public key
  added_at INTEGER NOT NULL,
  revoked_at INTEGER,
  last_seen_at INTEGER
);

-- Outbox for local mutations waiting for relay ack (Pro)
CREATE TABLE outbox (
  event_id BLOB PRIMARY KEY,
  device_seq INTEGER NOT NULL UNIQUE,
  envelope BLOB NOT NULL        -- postcard(SignedEvent)
);

-- Applied events for deduplication
CREATE TABLE applied_events (
  event_id BLOB PRIMARY KEY,
  server_seq INTEGER NOT NULL
);

-- Sync state
CREATE TABLE sync_state (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- Settings (appearance, auto-lock time)
CREATE TABLE settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
