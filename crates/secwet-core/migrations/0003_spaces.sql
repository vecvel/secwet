-- Migration 0003: Spaces Architecture
--
-- Adds the spaces table and index for multi-space support.
-- Invariant: Sensitive names and icons exist only inside encrypted `name_blob` columns.

CREATE TABLE IF NOT EXISTS spaces (
  id BLOB PRIMARY KEY,         -- 16-byte UUID v7
  name_blob BLOB NOT NULL,     -- sealed with K_rec (postcard SpaceBody)
  position INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL, -- Unix epoch ms
  updated_at INTEGER NOT NULL, -- Unix epoch ms
  deleted INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_spaces_position ON spaces(position);
CREATE INDEX IF NOT EXISTS idx_spaces_deleted ON spaces(deleted);

