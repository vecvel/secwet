-- Migration 0002: Flexible Organization Schema Upgrade
-- Authoritative source: docs/IMPLEMENTATION.md §5.2
--
-- Adds the user-defined labels table and indexes for flexible organization.
-- Invariant: Sensitive names exist only inside encrypted `name_blob` columns.

-- 1. Create labels table for user-defined organizational categories
CREATE TABLE IF NOT EXISTS labels (
  id BLOB PRIMARY KEY,         -- 16-byte UUID v7
  name_blob BLOB NOT NULL,     -- sealed with K_rec
  position INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL, -- Unix epoch ms
  updated_at INTEGER NOT NULL, -- Unix epoch ms
  deleted INTEGER NOT NULL DEFAULT 0
);

-- 2. Index for ordering and filtering active labels by position
CREATE INDEX IF NOT EXISTS idx_labels_position ON labels(position);
CREATE INDEX IF NOT EXISTS labels_position ON labels(position);

-- 3. Verify and ensure indexes on records table for parent traversal and type filtering
CREATE INDEX IF NOT EXISTS records_parent ON records(parent_id);
CREATE INDEX IF NOT EXISTS records_type ON records(record_type);
