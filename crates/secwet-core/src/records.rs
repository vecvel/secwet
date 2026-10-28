//! SQLite local storage, migrations, and record operations.
//!
//! Authoritative source: `docs/IMPLEMENTATION.md` §5.2.
//!
//! Architectural Invariant: Sensitive data (label names, item names, descriptions, environment names,
//! secret names, secret values, secret notes, file data, note content) exists only inside encrypted
//! `blob` columns (in `records` or `labels`). The database schema holds only non-secret metadata
//! (UUIDs, record types, timestamps, Lamport clocks, positions, device IDs).

use crate::{Error, Result};
use rusqlite::{params, Connection, Row};
use secwet_proto::RecordType;
use std::path::Path;
use uuid::Uuid;

/// Initial schema migration SQL script embedded at compile time.
pub const INITIAL_SCHEMA_SQL: &str = include_str!("../migrations/0001_initial_schema.sql");

/// Migration 0002: Flexible organization schema script embedded at compile time.
pub const MIGRATION_0002_SQL: &str = include_str!("../migrations/0002_flexible_organization.sql");

/// Migration 0003: Spaces architecture schema script embedded at compile time.
pub const MIGRATION_0003_SQL: &str = include_str!("../migrations/0003_spaces.sql");

// ============================================================================
// 1. Connection Initializer & PRAGMA Settings
// ============================================================================

/// Configures mandatory SQLite PRAGMAs required by `docs/IMPLEMENTATION.md` §5.2:
/// - `PRAGMA journal_mode = WAL;` (Write-Ahead Logging for concurrency)
/// - `PRAGMA foreign_keys = ON;` (Referential integrity)
/// - `PRAGMA busy_timeout = 5000;` (5-second lock timeout for CLI & desktop coordination)
pub fn configure_connection(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;\n\
         PRAGMA foreign_keys = ON;\n\
         PRAGMA busy_timeout = 5000;",
    )
    .map_err(|_| Error::Storage)?;
    Ok(())
}

/// Opens a SQLite connection to a file on disk and applies mandatory PRAGMAs.
pub fn open_connection(path: impl AsRef<Path>) -> Result<Connection> {
    let conn = Connection::open(path).map_err(|_| Error::Storage)?;
    configure_connection(&conn)?;
    Ok(conn)
}

/// Opens an in-memory SQLite connection and applies mandatory PRAGMAs (for testing).
pub fn open_in_memory() -> Result<Connection> {
    let conn = Connection::open_in_memory().map_err(|_| Error::Storage)?;
    configure_connection(&conn)?;
    Ok(conn)
}

// ============================================================================
// 2. Schema Migrations Runner
// ============================================================================

/// Retrieves the current schema version using `PRAGMA user_version`.
pub fn get_schema_version(conn: &Connection) -> Result<u32> {
    let version: u32 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|_| Error::Storage)?;
    Ok(version)
}

/// Runs pending migrations up to the latest schema version (3).
///
/// Execution order:
/// - Version 0 -> 1: Executes `0001_initial_schema.sql`, sets `schema_version = 1`, bumps `user_version = 1`.
/// - Version 1 -> 2: Executes `0002_flexible_organization.sql`, sets `schema_version = 2`, bumps `user_version = 2`.
/// - Version 2 -> 3: Executes `0003_spaces.sql`, ensures `space_id` column on `labels`, sets `schema_version = 3`, bumps `user_version = 3`.
pub fn run_migrations(conn: &mut Connection) -> Result<()> {
    let mut version = get_schema_version(conn)?;
    if version < 1 {
        let tx = conn.transaction().map_err(|_| Error::Storage)?;
        tx.execute_batch(INITIAL_SCHEMA_SQL)
            .map_err(|_| Error::Storage)?;
        tx.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', '1')",
            [],
        )
        .map_err(|_| Error::Storage)?;
        tx.commit().map_err(|_| Error::Storage)?;
        conn.execute("PRAGMA user_version = 1", [])
            .map_err(|_| Error::Storage)?;
        version = 1;
    }
    if version < 2 {
        let tx = conn.transaction().map_err(|_| Error::Storage)?;
        tx.execute_batch(MIGRATION_0002_SQL)
            .map_err(|_| Error::Storage)?;
        tx.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', '2')",
            [],
        )
        .map_err(|_| Error::Storage)?;
        tx.commit().map_err(|_| Error::Storage)?;
        conn.execute("PRAGMA user_version = 2", [])
            .map_err(|_| Error::Storage)?;
        version = 2;
    }
    if version < 3 {
        let tx = conn.transaction().map_err(|_| Error::Storage)?;
        tx.execute_batch(MIGRATION_0003_SQL)
            .map_err(|_| Error::Storage)?;

        // Ensure space_id column exists on labels table (safe for upgrades & fresh inits)
        let has_space_id: bool = tx
            .prepare("PRAGMA table_info(labels)")
            .and_then(|mut stmt| {
                let mut rows = stmt.query([])?;
                let mut found = false;
                while let Some(row) = rows.next()? {
                    let col_name: String = row.get(1)?;
                    if col_name == "space_id" {
                        found = true;
                        break;
                    }
                }
                Ok(found)
            })
            .unwrap_or(false);

        if !has_space_id {
            tx.execute("ALTER TABLE labels ADD COLUMN space_id BLOB", [])
                .map_err(|_| Error::Storage)?;
            tx.execute(
                "CREATE INDEX IF NOT EXISTS idx_labels_space ON labels(space_id)",
                [],
            )
            .map_err(|_| Error::Storage)?;
        }

        tx.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', '3')",
            [],
        )
        .map_err(|_| Error::Storage)?;
        tx.commit().map_err(|_| Error::Storage)?;
        conn.execute("PRAGMA user_version = 3", [])
            .map_err(|_| Error::Storage)?;
    }
    crate::sessions::init_active_sessions_table(conn)?;
    crate::collab::init_collab_tables(conn)?;
    Ok(())
}

/// Opens a database file, applies PRAGMAs, and runs all migrations.
pub fn open_and_migrate(path: impl AsRef<Path>) -> Result<Connection> {
    let mut conn = open_connection(path)?;
    run_migrations(&mut conn)?;
    crate::sessions::init_active_sessions_table(&conn)?;
    Ok(conn)
}

// ============================================================================
// 3. Space, Label & Record Data Structures
// ============================================================================

/// In-memory representation of a row in the `spaces` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpaceRow {
    pub id: Uuid,
    pub name_blob: Vec<u8>,
    pub position: u32,
    pub created_at: i64,
    pub updated_at: i64,
    pub deleted: bool,
}

impl SpaceRow {
    /// Constructs an active (non-deleted) space row.
    pub fn new_active(id: Uuid, name_blob: Vec<u8>, position: u32, now_ms: i64) -> Self {
        Self {
            id,
            name_blob,
            position,
            created_at: now_ms,
            updated_at: now_ms,
            deleted: false,
        }
    }

    /// Constructs a soft-deleted space row.
    pub fn new_deleted(id: Uuid, position: u32, created_at: i64, now_ms: i64) -> Self {
        Self {
            id,
            name_blob: Vec::new(),
            position,
            created_at,
            updated_at: now_ms,
            deleted: true,
        }
    }
}

/// In-memory representation of a row in the `labels` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelRow {
    pub id: Uuid,
    pub space_id: Option<Uuid>,
    pub name_blob: Vec<u8>,
    pub position: u32,
    pub created_at: i64,
    pub updated_at: i64,
    pub deleted: bool,
}

impl LabelRow {
    /// Constructs an active (non-deleted) label row without explicit space.
    pub fn new_active(id: Uuid, name_blob: Vec<u8>, position: u32, now_ms: i64) -> Self {
        Self {
            id,
            space_id: None,
            name_blob,
            position,
            created_at: now_ms,
            updated_at: now_ms,
            deleted: false,
        }
    }

    /// Constructs an active (non-deleted) label row within a specific space.
    pub fn new_active_in_space(
        id: Uuid,
        space_id: Option<Uuid>,
        name_blob: Vec<u8>,
        position: u32,
        now_ms: i64,
    ) -> Self {
        Self {
            id,
            space_id,
            name_blob,
            position,
            created_at: now_ms,
            updated_at: now_ms,
            deleted: false,
        }
    }

    /// Sets the space ID for this label row.
    pub fn with_space(mut self, space_id: Option<Uuid>) -> Self {
        self.space_id = space_id;
        self
    }

    /// Constructs a soft-deleted label row.
    pub fn new_deleted(id: Uuid, position: u32, created_at: i64, now_ms: i64) -> Self {
        Self {
            id,
            space_id: None,
            name_blob: Vec::new(),
            position,
            created_at,
            updated_at: now_ms,
            deleted: true,
        }
    }
}

/// In-memory representation of a row in the `records` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordRow {
    pub id: Uuid,
    pub record_type: RecordType,
    pub parent_id: Option<Uuid>,
    pub key_epoch: u32,
    pub blob: Option<Vec<u8>>,
    pub lamport: u64,
    pub origin_device: String,
    pub updated_at: i64,
    pub deleted: bool,
}

impl RecordRow {
    /// Constructs an active (non-deleted) record row.
    #[allow(clippy::too_many_arguments)]
    pub fn new_active(
        id: Uuid,
        record_type: RecordType,
        parent_id: Option<Uuid>,
        key_epoch: u32,
        blob: Vec<u8>,
        lamport: u64,
        origin_device: impl Into<String>,
        updated_at: i64,
    ) -> Self {
        Self {
            id,
            record_type,
            parent_id,
            key_epoch,
            blob: Some(blob),
            lamport,
            origin_device: origin_device.into(),
            updated_at,
            deleted: false,
        }
    }

    /// Constructs a soft-deleted record row with `blob = None` and `deleted = true`.
    pub fn new_deleted(
        id: Uuid,
        record_type: RecordType,
        parent_id: Option<Uuid>,
        key_epoch: u32,
        lamport: u64,
        origin_device: impl Into<String>,
        updated_at: i64,
    ) -> Self {
        Self {
            id,
            record_type,
            parent_id,
            key_epoch,
            blob: None,
            lamport,
            origin_device: origin_device.into(),
            updated_at,
            deleted: true,
        }
    }
}

/// Summary of records affected by a cascade deletion of an item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CascadeDeleteItemSummary {
    pub item_id: Uuid,
    pub environments_deleted: usize,
    pub secrets_deleted: usize,
    pub files_deleted: usize,
    pub notes_deleted: usize,
    pub total_records_affected: usize,
}

/// Summary of records affected by a cascade deletion of a label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CascadeDeleteLabelSummary {
    pub label_id: Uuid,
    pub items_deleted: usize,
    pub environments_deleted: usize,
    pub secrets_deleted: usize,
    pub files_deleted: usize,
    pub notes_deleted: usize,
    pub total_records_affected: usize,
}

/// Summary of records affected by a cascade deletion operation (legacy compatibility).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CascadeDeleteSummary {
    pub id: Uuid,
    pub environments_deleted: usize,
    pub secrets_deleted: usize,
    pub total_records_affected: usize,
}

// ============================================================================
// 4. Lamport Clock Helpers
// ============================================================================

/// Returns the highest Lamport clock value currently present in the `records` table.
/// If table is empty, returns 0.
pub fn get_highest_lamport(conn: &Connection) -> Result<u64> {
    let max_lamport: i64 = conn
        .query_row("SELECT COALESCE(MAX(lamport), 0) FROM records", [], |row| {
            row.get(0)
        })
        .map_err(|_| Error::Storage)?;
    Ok(max_lamport as u64)
}

/// Generates the next monotonic Lamport clock value: `max(highest lamport) + 1`.
pub fn next_lamport(conn: &Connection) -> Result<u64> {
    let current = get_highest_lamport(conn)?;
    Ok(current + 1)
}

// ============================================================================
// 5. Spaces Table Operations
// ============================================================================

/// Inserts a new space row into the `spaces` table.
pub fn insert_space(conn: &Connection, space: &SpaceRow) -> Result<()> {
    conn.execute(
        "INSERT INTO spaces (
            id, name_blob, position, created_at, updated_at, deleted
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            space.id.as_bytes().as_slice(),
            &space.name_blob,
            space.position as i64,
            space.created_at,
            space.updated_at,
            if space.deleted { 1i64 } else { 0i64 },
        ],
    )
    .map_err(|_| Error::Storage)?;
    Ok(())
}

/// Fetches a single space by its UUID. Returns `Ok(None)` if space does not exist.
pub fn get_space(conn: &Connection, id: Uuid) -> Result<Option<SpaceRow>> {
    let mut stmt = conn
        .prepare(
            "SELECT id, name_blob, position, created_at, updated_at, deleted
             FROM spaces WHERE id = ?1",
        )
        .map_err(|_| Error::Storage)?;

    let mut rows = stmt
        .query(params![id.as_bytes().as_slice()])
        .map_err(|_| Error::Storage)?;

    if let Some(row) = rows.next().map_err(|_| Error::Storage)? {
        Ok(Some(parse_space_row(row)?))
    } else {
        Ok(None)
    }
}

/// Queries all active (non-deleted) spaces, ordered by `position ASC, created_at ASC`.
pub fn query_active_spaces(conn: &Connection) -> Result<Vec<SpaceRow>> {
    let mut stmt = conn
        .prepare(
            "SELECT id, name_blob, position, created_at, updated_at, deleted
             FROM spaces WHERE deleted = 0 ORDER BY position ASC, created_at ASC",
        )
        .map_err(|_| Error::Storage)?;

    let mut rows = stmt.query([]).map_err(|_| Error::Storage)?;
    let mut spaces = Vec::new();
    while let Some(row) = rows.next().map_err(|_| Error::Storage)? {
        spaces.push(parse_space_row(row)?);
    }
    Ok(spaces)
}

/// Updates the sealed name blob of an active space.
/// Returns `Error::NotFound` if the space does not exist or is deleted.
pub fn update_space_name(conn: &Connection, id: Uuid, name_blob: &[u8], now_ms: i64) -> Result<()> {
    let count = conn
        .execute(
            "UPDATE spaces
             SET name_blob = ?1, updated_at = ?2
             WHERE id = ?3 AND deleted = 0",
            params![name_blob, now_ms, id.as_bytes().as_slice()],
        )
        .map_err(|_| Error::Storage)?;

    if count == 0 {
        return Err(Error::NotFound);
    }
    Ok(())
}

/// Reorders active spaces according to the provided slice of UUIDs.
/// Updates positions sequentially (0..ids.len()) within a single transaction.
pub fn reorder_spaces(conn: &mut Connection, ids: &[Uuid], now_ms: i64) -> Result<()> {
    let tx = conn.transaction().map_err(|_| Error::Storage)?;
    for (pos, id) in ids.iter().enumerate() {
        let count = tx
            .execute(
                "UPDATE spaces SET position = ?1, updated_at = ?2 WHERE id = ?3 AND deleted = 0",
                params![pos as i64, now_ms, id.as_bytes().as_slice()],
            )
            .map_err(|_| Error::Storage)?;
        if count == 0 {
            return Err(Error::NotFound);
        }
    }
    tx.commit().map_err(|_| Error::Storage)?;
    Ok(())
}

/// Computes the next position for a new space (`max(position) + 1` or 0 if empty).
pub fn next_space_position(conn: &Connection) -> Result<u32> {
    let max_pos: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(position), -1) FROM spaces WHERE deleted = 0",
            [],
            |row| row.get(0),
        )
        .map_err(|_| Error::Storage)?;
    if max_pos < 0 {
        Ok(0)
    } else {
        Ok((max_pos + 1) as u32)
    }
}

/// Soft-deletes a space by marking `deleted = 1`.
pub fn soft_delete_space(conn: &Connection, id: Uuid, now_ms: i64) -> Result<()> {
    let count = conn
        .execute(
            "UPDATE spaces SET deleted = 1, updated_at = ?1 WHERE id = ?2 AND deleted = 0",
            params![now_ms, id.as_bytes().as_slice()],
        )
        .map_err(|_| Error::Storage)?;

    if count == 0 {
        return Err(Error::NotFound);
    }
    Ok(())
}

/// Counts the number of active labels belonging to a specific space.
pub fn count_active_labels_for_space(conn: &Connection, space_id: Uuid) -> Result<usize> {
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM labels WHERE space_id = ?1 AND deleted = 0",
            params![space_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .map_err(|_| Error::Storage)?;
    Ok(count as usize)
}

// ============================================================================
// 6. Labels Table Operations
// ============================================================================

/// Inserts a new label row into the `labels` table.
pub fn insert_label(conn: &Connection, label: &LabelRow) -> Result<()> {
    conn.execute(
        "INSERT INTO labels (
            id, space_id, name_blob, position, created_at, updated_at, deleted
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            label.id.as_bytes().as_slice(),
            label.space_id.as_ref().map(|u| u.as_bytes().as_slice()),
            &label.name_blob,
            label.position as i64,
            label.created_at,
            label.updated_at,
            if label.deleted { 1i64 } else { 0i64 },
        ],
    )
    .map_err(|_| Error::Storage)?;
    Ok(())
}

/// Fetches a single label by its UUID. Returns `Ok(None)` if label does not exist.
pub fn get_label(conn: &Connection, id: Uuid) -> Result<Option<LabelRow>> {
    let mut stmt = conn
        .prepare(
            "SELECT id, space_id, name_blob, position, created_at, updated_at, deleted
             FROM labels WHERE id = ?1",
        )
        .map_err(|_| Error::Storage)?;

    let mut rows = stmt
        .query(params![id.as_bytes().as_slice()])
        .map_err(|_| Error::Storage)?;

    if let Some(row) = rows.next().map_err(|_| Error::Storage)? {
        Ok(Some(parse_label_row(row)?))
    } else {
        Ok(None)
    }
}

/// Queries all active (non-deleted) labels, ordered by `position ASC, created_at ASC`.
pub fn query_active_labels(conn: &Connection) -> Result<Vec<LabelRow>> {
    let mut stmt = conn
        .prepare(
            "SELECT id, space_id, name_blob, position, created_at, updated_at, deleted
             FROM labels WHERE deleted = 0 ORDER BY position ASC, created_at ASC",
        )
        .map_err(|_| Error::Storage)?;

    let mut rows = stmt.query([]).map_err(|_| Error::Storage)?;
    let mut labels = Vec::new();
    while let Some(row) = rows.next().map_err(|_| Error::Storage)? {
        labels.push(parse_label_row(row)?);
    }
    Ok(labels)
}

/// Queries all active (non-deleted) labels belonging to a specific space.
pub fn query_active_labels_by_space(conn: &Connection, space_id: Uuid) -> Result<Vec<LabelRow>> {
    let mut stmt = conn
        .prepare(
            "SELECT id, space_id, name_blob, position, created_at, updated_at, deleted
             FROM labels WHERE space_id = ?1 AND deleted = 0 ORDER BY position ASC, created_at ASC",
        )
        .map_err(|_| Error::Storage)?;

    let mut rows = stmt
        .query(params![space_id.as_bytes().as_slice()])
        .map_err(|_| Error::Storage)?;

    let mut labels = Vec::new();
    while let Some(row) = rows.next().map_err(|_| Error::Storage)? {
        labels.push(parse_label_row(row)?);
    }
    Ok(labels)
}

/// Updates the space assignment of an active label.
pub fn update_label_space(
    conn: &Connection,
    id: Uuid,
    space_id: Option<Uuid>,
    now_ms: i64,
) -> Result<()> {
    let count = conn
        .execute(
            "UPDATE labels SET space_id = ?1, updated_at = ?2 WHERE id = ?3 AND deleted = 0",
            params![
                space_id.as_ref().map(|u| u.as_bytes().as_slice()),
                now_ms,
                id.as_bytes().as_slice(),
            ],
        )
        .map_err(|_| Error::Storage)?;

    if count == 0 {
        return Err(Error::NotFound);
    }
    Ok(())
}

/// Reassigns all active labels from one space to another space.
pub fn reassign_labels_to_space(
    conn: &Connection,
    from_space_id: Uuid,
    to_space_id: Uuid,
    now_ms: i64,
) -> Result<usize> {
    let count = conn
        .execute(
            "UPDATE labels SET space_id = ?1, updated_at = ?2 WHERE space_id = ?3 AND deleted = 0",
            params![
                to_space_id.as_bytes().as_slice(),
                now_ms,
                from_space_id.as_bytes().as_slice(),
            ],
        )
        .map_err(|_| Error::Storage)?;
    Ok(count)
}

/// Retrofits all unassigned active labels (`space_id IS NULL`) to point to the default space.
pub fn update_null_labels_space(
    conn: &Connection,
    default_space_id: Uuid,
    now_ms: i64,
) -> Result<usize> {
    let count = conn
        .execute(
            "UPDATE labels SET space_id = ?1, updated_at = ?2 WHERE space_id IS NULL AND deleted = 0",
            params![default_space_id.as_bytes().as_slice(), now_ms],
        )
        .map_err(|_| Error::Storage)?;
    Ok(count)
}

/// Updates the sealed name blob of an active label.
/// Returns `Error::NotFound` if the label does not exist or is deleted.
pub fn update_label_name(conn: &Connection, id: Uuid, name_blob: &[u8], now_ms: i64) -> Result<()> {
    let count = conn
        .execute(
            "UPDATE labels
             SET name_blob = ?1, updated_at = ?2
             WHERE id = ?3 AND deleted = 0",
            params![name_blob, now_ms, id.as_bytes().as_slice()],
        )
        .map_err(|_| Error::Storage)?;

    if count == 0 {
        return Err(Error::NotFound);
    }
    Ok(())
}

/// Reorders active labels according to the provided slice of UUIDs.
/// Updates positions sequentially (0..ids.len()) within a single transaction.
pub fn reorder_labels(conn: &mut Connection, ids: &[Uuid], now_ms: i64) -> Result<()> {
    let tx = conn.transaction().map_err(|_| Error::Storage)?;
    for (pos, id) in ids.iter().enumerate() {
        let count = tx
            .execute(
                "UPDATE labels SET position = ?1, updated_at = ?2 WHERE id = ?3 AND deleted = 0",
                params![pos as i64, now_ms, id.as_bytes().as_slice()],
            )
            .map_err(|_| Error::Storage)?;
        if count == 0 {
            return Err(Error::NotFound);
        }
    }
    tx.commit().map_err(|_| Error::Storage)?;
    Ok(())
}

/// Computes the next position for a new label (`max(position) + 1` or 0 if empty).
pub fn next_label_position(conn: &Connection) -> Result<u32> {
    let max_pos: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(position), -1) FROM labels WHERE deleted = 0",
            [],
            |row| row.get(0),
        )
        .map_err(|_| Error::Storage)?;
    if max_pos < 0 {
        Ok(0)
    } else {
        Ok((max_pos + 1) as u32)
    }
}

/// Soft-deletes a label by marking `deleted = 1`.
pub fn soft_delete_label(conn: &Connection, id: Uuid, now_ms: i64) -> Result<()> {
    let count = conn
        .execute(
            "UPDATE labels SET deleted = 1, updated_at = ?1 WHERE id = ?2 AND deleted = 0",
            params![now_ms, id.as_bytes().as_slice()],
        )
        .map_err(|_| Error::Storage)?;

    if count == 0 {
        return Err(Error::NotFound);
    }
    Ok(())
}

// ============================================================================
// 6. Record Storage Operations
// ============================================================================

/// Inserts a new record row into the `records` table.
pub fn insert_record(conn: &Connection, record: &RecordRow) -> Result<()> {
    conn.execute(
        "INSERT INTO records (
            id, record_type, parent_id, key_epoch, blob, lamport, origin_device, updated_at, deleted
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            record.id.as_bytes().as_slice(),
            record.record_type as u8,
            record.parent_id.as_ref().map(|u| u.as_bytes().as_slice()),
            record.key_epoch,
            record.blob.as_deref(),
            record.lamport as i64,
            &record.origin_device,
            record.updated_at,
            if record.deleted { 1i64 } else { 0i64 },
        ],
    )
    .map_err(|_| Error::Storage)?;
    Ok(())
}

/// Fetches a single record by its UUID. Returns `Ok(None)` if record does not exist.
pub fn get_record(conn: &Connection, id: Uuid) -> Result<Option<RecordRow>> {
    let mut stmt = conn
        .prepare(
            "SELECT id, record_type, parent_id, key_epoch, blob, lamport, origin_device, updated_at, deleted
             FROM records WHERE id = ?1",
        )
        .map_err(|_| Error::Storage)?;

    let mut rows = stmt
        .query(params![id.as_bytes().as_slice()])
        .map_err(|_| Error::Storage)?;

    if let Some(row) = rows.next().map_err(|_| Error::Storage)? {
        let record = parse_record_row(row)?;
        Ok(Some(record))
    } else {
        Ok(None)
    }
}

/// Queries records matching a specific `parent_id`.
/// If `parent_id` is `None`, queries top-level records (`parent_id IS NULL`).
/// If `include_deleted` is `false`, filters out rows with `deleted = 1`.
pub fn query_records_by_parent(
    conn: &Connection,
    parent_id: Option<Uuid>,
    include_deleted: bool,
) -> Result<Vec<RecordRow>> {
    let sql = match (parent_id, include_deleted) {
        (None, false) => {
            "SELECT id, record_type, parent_id, key_epoch, blob, lamport, origin_device, updated_at, deleted
             FROM records WHERE parent_id IS NULL AND deleted = 0 ORDER BY updated_at ASC"
        }
        (None, true) => {
            "SELECT id, record_type, parent_id, key_epoch, blob, lamport, origin_device, updated_at, deleted
             FROM records WHERE parent_id IS NULL ORDER BY updated_at ASC"
        }
        (Some(_), false) => {
            "SELECT id, record_type, parent_id, key_epoch, blob, lamport, origin_device, updated_at, deleted
             FROM records WHERE parent_id = ?1 AND deleted = 0 ORDER BY updated_at ASC"
        }
        (Some(_), true) => {
            "SELECT id, record_type, parent_id, key_epoch, blob, lamport, origin_device, updated_at, deleted
             FROM records WHERE parent_id = ?1 ORDER BY updated_at ASC"
        }
    };

    let mut stmt = conn.prepare(sql).map_err(|_| Error::Storage)?;
    let mut rows = match parent_id {
        Some(pid) => stmt
            .query(params![pid.as_bytes().as_slice()])
            .map_err(|_| Error::Storage)?,
        None => stmt.query([]).map_err(|_| Error::Storage)?,
    };

    let mut records = Vec::new();
    while let Some(row) = rows.next().map_err(|_| Error::Storage)? {
        records.push(parse_record_row(row)?);
    }
    Ok(records)
}

/// Queries all active (non-deleted) records of a given `RecordType`.
pub fn query_active_records_by_type(
    conn: &Connection,
    record_type: RecordType,
) -> Result<Vec<RecordRow>> {
    let mut stmt = conn
        .prepare(
            "SELECT id, record_type, parent_id, key_epoch, blob, lamport, origin_device, updated_at, deleted
             FROM records WHERE record_type = ?1 AND deleted = 0 ORDER BY updated_at ASC",
        )
        .map_err(|_| Error::Storage)?;

    let mut rows = stmt
        .query(params![record_type as u8])
        .map_err(|_| Error::Storage)?;

    let mut records = Vec::new();
    while let Some(row) = rows.next().map_err(|_| Error::Storage)? {
        records.push(parse_record_row(row)?);
    }
    Ok(records)
}

/// Queries active records matching both a specific `parent_id` and `RecordType`.
pub fn query_active_records_by_parent_and_type(
    conn: &Connection,
    parent_id: Option<Uuid>,
    record_type: RecordType,
) -> Result<Vec<RecordRow>> {
    let sql = match parent_id {
        Some(_) => {
            "SELECT id, record_type, parent_id, key_epoch, blob, lamport, origin_device, updated_at, deleted
             FROM records WHERE parent_id = ?1 AND record_type = ?2 AND deleted = 0 ORDER BY updated_at ASC"
        }
        None => {
            "SELECT id, record_type, parent_id, key_epoch, blob, lamport, origin_device, updated_at, deleted
             FROM records WHERE parent_id IS NULL AND record_type = ?1 AND deleted = 0 ORDER BY updated_at ASC"
        }
    };

    let mut stmt = conn.prepare(sql).map_err(|_| Error::Storage)?;
    let mut rows = match parent_id {
        Some(pid) => stmt
            .query(params![pid.as_bytes().as_slice(), record_type as u8])
            .map_err(|_| Error::Storage)?,
        None => stmt
            .query(params![record_type as u8])
            .map_err(|_| Error::Storage)?,
    };

    let mut records = Vec::new();
    while let Some(row) = rows.next().map_err(|_| Error::Storage)? {
        records.push(parse_record_row(row)?);
    }
    Ok(records)
}

/// Queries all active items under a label (`parent_id = label_id`, `record_type = Item`).
pub fn query_items_by_label(conn: &Connection, label_id: Uuid) -> Result<Vec<RecordRow>> {
    query_active_records_by_parent_and_type(conn, Some(label_id), RecordType::Item)
}

/// Queries all active environments under an item (`parent_id = item_id`, `record_type = Environment`).
pub fn query_environments_by_item(conn: &Connection, item_id: Uuid) -> Result<Vec<RecordRow>> {
    query_active_records_by_parent_and_type(conn, Some(item_id), RecordType::Environment)
}

/// Queries active content (Secret, File, Note) for an item:
/// - If `environment_id` is None, returns item-level records (`parent_id = item_id`).
/// - If `environment_id` is Some(env_id), returns env-level records (`parent_id = env_id`).
pub fn query_content_records(
    conn: &Connection,
    item_id: Uuid,
    environment_id: Option<Uuid>,
    record_type: RecordType,
) -> Result<Vec<RecordRow>> {
    let parent_id = environment_id.unwrap_or(item_id);
    query_active_records_by_parent_and_type(conn, Some(parent_id), record_type)
}

/// Queries all active content of a given type belonging to an item, across both item-level
/// and inside any of its child environments.
pub fn query_all_item_content_records(
    conn: &Connection,
    item_id: Uuid,
    record_type: RecordType,
) -> Result<Vec<RecordRow>> {
    let mut stmt = conn
        .prepare(
            "SELECT id, record_type, parent_id, key_epoch, blob, lamport, origin_device, updated_at, deleted
             FROM records
             WHERE record_type = ?1 AND deleted = 0 AND (
                 parent_id = ?2
                 OR parent_id IN (
                     SELECT id FROM records
                     WHERE record_type IN (2, 3) AND parent_id = ?2 AND deleted = 0
                 )
             )
             ORDER BY updated_at ASC",
        )
        .map_err(|_| Error::Storage)?;

    let mut rows = stmt
        .query(params![record_type as u8, item_id.as_bytes().as_slice()])
        .map_err(|_| Error::Storage)?;

    let mut records = Vec::new();
    while let Some(row) = rows.next().map_err(|_| Error::Storage)? {
        records.push(parse_record_row(row)?);
    }
    Ok(records)
}

/// Counts active items for a given label.
pub fn count_active_items_for_label(conn: &Connection, label_id: Uuid) -> Result<usize> {
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM records WHERE record_type = 2 AND parent_id = ?1 AND deleted = 0",
            params![label_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .map_err(|_| Error::Storage)?;
    Ok(count as usize)
}

/// Counts active child records matching a direct parent_id and record_type.
pub fn count_active_records_by_parent_and_type(
    conn: &Connection,
    parent_id: Uuid,
    record_type: RecordType,
) -> Result<usize> {
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM records WHERE parent_id = ?1 AND record_type = ?2 AND deleted = 0",
            params![parent_id.as_bytes().as_slice(), record_type as u8],
            |row| row.get(0),
        )
        .map_err(|_| Error::Storage)?;
    Ok(count as usize)
}

/// Recursively counts all active content (secrets, files, notes) belonging to an item,
/// including item-level content and content inside any of its child environments.
pub fn count_item_content_recursive(
    conn: &Connection,
    item_id: Uuid,
    record_type: RecordType,
) -> Result<usize> {
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM records
             WHERE record_type = ?1 AND deleted = 0 AND (
                 parent_id = ?2
                 OR parent_id IN (
                     SELECT id FROM records
                     WHERE record_type IN (2, 3) AND parent_id = ?2 AND deleted = 0
                 )
             )",
            params![record_type as u8, item_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .map_err(|_| Error::Storage)?;
    Ok(count as usize)
}

/// Updates the encrypted `blob` of an existing record, automatically bumping the Lamport
/// clock and refreshing the `updated_at` timestamp and `origin_device`.
///
/// Returns the newly assigned Lamport clock value. Returns `Error::NotFound` if no row was updated.
pub fn update_record_blob(
    conn: &Connection,
    record_id: Uuid,
    new_blob: &[u8],
    origin_device: &str,
    now_ms: i64,
) -> Result<u64> {
    let new_lamport = next_lamport(conn)?;
    let count = conn
        .execute(
            "UPDATE records
             SET blob = ?1, lamport = ?2, origin_device = ?3, updated_at = ?4, deleted = 0
             WHERE id = ?5",
            params![
                new_blob,
                new_lamport as i64,
                origin_device,
                now_ms,
                record_id.as_bytes().as_slice(),
            ],
        )
        .map_err(|_| Error::Storage)?;

    if count == 0 {
        return Err(Error::NotFound);
    }
    Ok(new_lamport)
}

/// Soft-deletes a record by setting `deleted = 1`, clearing `blob = NULL`,
/// bumping the Lamport clock, and updating `updated_at` and `origin_device`.
///
/// Returns the newly assigned Lamport clock value. Returns `Error::NotFound` if record doesn't exist.
pub fn soft_delete_record(
    conn: &Connection,
    record_id: Uuid,
    origin_device: &str,
    now_ms: i64,
) -> Result<u64> {
    let new_lamport = next_lamport(conn)?;
    let count = conn
        .execute(
            "UPDATE records
             SET deleted = 1, blob = NULL, lamport = ?1, origin_device = ?2, updated_at = ?3
             WHERE id = ?4 AND deleted = 0",
            params![
                new_lamport as i64,
                origin_device,
                now_ms,
                record_id.as_bytes().as_slice(),
            ],
        )
        .map_err(|_| Error::Storage)?;

    if count == 0 {
        let exists: bool = conn
            .query_row(
                "SELECT 1 FROM records WHERE id = ?1",
                params![record_id.as_bytes().as_slice()],
                |_| Ok(true),
            )
            .unwrap_or(false);
        if !exists {
            return Err(Error::NotFound);
        }
    }
    Ok(new_lamport)
}

// ============================================================================
// 7. Cascade Deletion Operations
// ============================================================================

/// Cascades deletion of an item and all its child environments, secrets, files, and notes.
///
/// Executes atomically in a single SQLite transaction:
/// 1. Marks item `deleted = 1, blob = NULL` with bumped Lamport clock.
/// 2. Marks child environments `deleted = 1, blob = NULL` with bumped Lamport clock.
/// 3. Marks all item-level and environment-level secrets, files, notes `deleted = 1, blob = NULL`.
///
/// Returns `Error::NotFound` if item does not exist or is already deleted.
pub fn cascade_delete_item(
    conn: &mut Connection,
    item_id: Uuid,
    origin_device: &str,
    now_ms: i64,
) -> Result<CascadeDeleteItemSummary> {
    // 1. Verify item exists and is active (type 2 or legacy project 1)
    let item_exists: bool = conn
        .query_row(
            "SELECT 1 FROM records WHERE id = ?1 AND record_type IN (1, 2) AND deleted = 0",
            params![item_id.as_bytes().as_slice()],
            |_| Ok(true),
        )
        .unwrap_or(false);

    if !item_exists {
        return Err(Error::NotFound);
    }

    // 2. Collect child environment IDs (type 3 or legacy env 2)
    let mut env_ids: Vec<Uuid> = Vec::new();
    {
        let mut stmt = conn
            .prepare(
                "SELECT id FROM records WHERE record_type IN (2, 3) AND parent_id = ?1 AND deleted = 0",
            )
            .map_err(|_| Error::Storage)?;
        let mut rows = stmt
            .query(params![item_id.as_bytes().as_slice()])
            .map_err(|_| Error::Storage)?;
        while let Some(row) = rows.next().map_err(|_| Error::Storage)? {
            let bytes: Vec<u8> = row.get(0).map_err(|_| Error::Storage)?;
            let id = Uuid::from_slice(&bytes).map_err(|_| Error::Storage)?;
            env_ids.push(id);
        }
    }

    let mut secret_ids: Vec<Uuid> = Vec::new();
    let mut file_ids: Vec<Uuid> = Vec::new();
    let mut note_ids: Vec<Uuid> = Vec::new();

    // 1) Item-level content: secrets (4), files (5), notes (6)
    {
        let mut stmt = conn
            .prepare(
                "SELECT id, record_type FROM records WHERE record_type IN (4, 5, 6) AND parent_id = ?1 AND deleted = 0",
            )
            .map_err(|_| Error::Storage)?;
        let mut rows = stmt
            .query(params![item_id.as_bytes().as_slice()])
            .map_err(|_| Error::Storage)?;
        while let Some(row) = rows.next().map_err(|_| Error::Storage)? {
            let bytes: Vec<u8> = row.get(0).map_err(|_| Error::Storage)?;
            let rtype: u8 = row.get(1).map_err(|_| Error::Storage)?;
            let id = Uuid::from_slice(&bytes).map_err(|_| Error::Storage)?;
            match rtype {
                4 => secret_ids.push(id),
                5 => file_ids.push(id),
                6 => note_ids.push(id),
                _ => {}
            }
        }
    }

    // 2) Environment-level content: legacy secrets (3), new secrets (4), files (5), notes (6)
    for env_id in &env_ids {
        let mut stmt = conn
            .prepare(
                "SELECT id, record_type FROM records WHERE record_type IN (3, 4, 5, 6) AND parent_id = ?1 AND deleted = 0",
            )
            .map_err(|_| Error::Storage)?;
        let mut rows = stmt
            .query(params![env_id.as_bytes().as_slice()])
            .map_err(|_| Error::Storage)?;
        while let Some(row) = rows.next().map_err(|_| Error::Storage)? {
            let bytes: Vec<u8> = row.get(0).map_err(|_| Error::Storage)?;
            let rtype: u8 = row.get(1).map_err(|_| Error::Storage)?;
            let id = Uuid::from_slice(&bytes).map_err(|_| Error::Storage)?;
            match rtype {
                3 | 4 => secret_ids.push(id),
                5 => file_ids.push(id),
                6 => note_ids.push(id),
                _ => {}
            }
        }
    }

    // 3. Atomically bump Lamport clocks and mark all deleted=1, blob=NULL
    let mut current_lamport = get_highest_lamport(conn)?;
    let tx = conn.transaction().map_err(|_| Error::Storage)?;

    let mut tombstone = |tx: &rusqlite::Transaction, id: Uuid| -> Result<()> {
        current_lamport += 1;
        tx.execute(
            "UPDATE records SET deleted = 1, blob = NULL, lamport = ?1, origin_device = ?2, updated_at = ?3 WHERE id = ?4",
            params![
                current_lamport as i64,
                origin_device,
                now_ms,
                id.as_bytes().as_slice(),
            ],
        )
        .map_err(|_| Error::Storage)?;
        Ok(())
    };

    tombstone(&tx, item_id)?;
    for env_id in &env_ids {
        tombstone(&tx, *env_id)?;
    }
    for s_id in &secret_ids {
        tombstone(&tx, *s_id)?;
    }
    for f_id in &file_ids {
        tombstone(&tx, *f_id)?;
    }
    for n_id in &note_ids {
        tombstone(&tx, *n_id)?;
    }

    tx.commit().map_err(|_| Error::Storage)?;

    Ok(CascadeDeleteItemSummary {
        item_id,
        environments_deleted: env_ids.len(),
        secrets_deleted: secret_ids.len(),
        files_deleted: file_ids.len(),
        notes_deleted: note_ids.len(),
        total_records_affected: 1
            + env_ids.len()
            + secret_ids.len()
            + file_ids.len()
            + note_ids.len(),
    })
}

/// Deletes an environment with optional content preservation.
///
/// Invariant: Unlike Milestone 0, does NOT reject deletion if it is the only remaining
/// environment; items require no environments.
///
/// If `preserve_content` is true:
/// - Child secrets, files, and notes are reparented to the parent `item_id` (migrated to item-level).
///
/// If `preserve_content` is false:
/// - Child secrets, files, and notes are soft-deleted (`deleted = 1, blob = NULL`).
///
/// Returns the number of child records affected.
pub fn delete_environment_records(
    conn: &mut Connection,
    env_id: Uuid,
    preserve_content: bool,
    origin_device: &str,
    now_ms: i64,
) -> Result<usize> {
    // 1. Verify environment exists and get its parent item_id (accepts record_type 2 or 3)
    let parent_id_bytes: Option<Vec<u8>> = conn
        .query_row(
            "SELECT parent_id FROM records WHERE id = ?1 AND record_type IN (2, 3) AND deleted = 0",
            params![env_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .map_err(|err| match err {
            rusqlite::Error::QueryReturnedNoRows => Error::NotFound,
            _ => Error::Storage,
        })?;

    let item_id_bytes = parent_id_bytes.ok_or(Error::NotFound)?;
    let item_id = Uuid::from_slice(&item_id_bytes).map_err(|_| Error::Storage)?;

    // 2. Collect child record IDs (secrets=3/4, files=5, notes=6)
    let mut child_ids: Vec<Uuid> = Vec::new();
    {
        let mut stmt = conn
            .prepare(
                "SELECT id FROM records WHERE parent_id = ?1 AND record_type IN (3, 4, 5, 6) AND deleted = 0",
            )
            .map_err(|_| Error::Storage)?;
        let mut rows = stmt
            .query(params![env_id.as_bytes().as_slice()])
            .map_err(|_| Error::Storage)?;
        while let Some(row) = rows.next().map_err(|_| Error::Storage)? {
            let bytes: Vec<u8> = row.get(0).map_err(|_| Error::Storage)?;
            child_ids.push(Uuid::from_slice(&bytes).map_err(|_| Error::Storage)?);
        }
    }

    // 3. Atomically execute update or tombstone
    let mut current_lamport = get_highest_lamport(conn)?;
    let tx = conn.transaction().map_err(|_| Error::Storage)?;

    // Soft-delete the environment record
    current_lamport += 1;
    tx.execute(
        "UPDATE records SET deleted = 1, blob = NULL, lamport = ?1, origin_device = ?2, updated_at = ?3 WHERE id = ?4",
        params![
            current_lamport as i64,
            origin_device,
            now_ms,
            env_id.as_bytes().as_slice(),
        ],
    )
    .map_err(|_| Error::Storage)?;

    if preserve_content {
        // Reparent children to item_id
        for child_id in &child_ids {
            current_lamport += 1;
            tx.execute(
                "UPDATE records SET parent_id = ?1, lamport = ?2, origin_device = ?3, updated_at = ?4 WHERE id = ?5",
                params![
                    item_id.as_bytes().as_slice(),
                    current_lamport as i64,
                    origin_device,
                    now_ms,
                    child_id.as_bytes().as_slice(),
                ],
            )
            .map_err(|_| Error::Storage)?;
        }
    } else {
        // Tombstone children
        for child_id in &child_ids {
            current_lamport += 1;
            tx.execute(
                "UPDATE records SET deleted = 1, blob = NULL, lamport = ?1, origin_device = ?2, updated_at = ?3 WHERE id = ?4",
                params![
                    current_lamport as i64,
                    origin_device,
                    now_ms,
                    child_id.as_bytes().as_slice(),
                ],
            )
            .map_err(|_| Error::Storage)?;
        }
    }

    tx.commit().map_err(|_| Error::Storage)?;
    Ok(child_ids.len())
}

/// Cascades deletion of a label and all its child items, environments, and content.
pub fn cascade_delete_label(
    conn: &mut Connection,
    label_id: Uuid,
    origin_device: &str,
    now_ms: i64,
) -> Result<CascadeDeleteLabelSummary> {
    // 1. Verify label exists
    let label = get_label(conn, label_id)?.ok_or(Error::NotFound)?;
    if label.deleted {
        return Err(Error::NotFound);
    }

    // 2. Collect child item IDs
    let child_items = query_items_by_label(conn, label_id)?;

    // 3. Delete each child item
    let mut total_envs = 0;
    let mut total_secrets = 0;
    let mut total_files = 0;
    let mut total_notes = 0;

    for item in &child_items {
        let summary = cascade_delete_item(conn, item.id, origin_device, now_ms)?;
        total_envs += summary.environments_deleted;
        total_secrets += summary.secrets_deleted;
        total_files += summary.files_deleted;
        total_notes += summary.notes_deleted;
    }

    // 4. Soft-delete the label row
    soft_delete_label(conn, label_id, now_ms)?;

    Ok(CascadeDeleteLabelSummary {
        label_id,
        items_deleted: child_items.len(),
        environments_deleted: total_envs,
        secrets_deleted: total_secrets,
        files_deleted: total_files,
        notes_deleted: total_notes,
        total_records_affected: 1
            + child_items.len()
            + total_envs
            + total_secrets
            + total_files
            + total_notes,
    })
}

/// Cascades deletion of a project and all its child environments and grandchild secrets.
/// Retained for backward compatibility with Milestone 0/1 tests.
pub fn cascade_delete_project(
    conn: &mut Connection,
    project_id: Uuid,
    origin_device: &str,
    now_ms: i64,
) -> Result<CascadeDeleteSummary> {
    // 1. Verify project/item exists and is active (accepts record_type 1 or 2)
    let proj_exists: bool = conn
        .query_row(
            "SELECT 1 FROM records WHERE id = ?1 AND record_type IN (1, 2) AND deleted = 0",
            params![project_id.as_bytes().as_slice()],
            |_| Ok(true),
        )
        .unwrap_or(false);

    if !proj_exists {
        return Err(Error::NotFound);
    }

    // 2. Collect child environment IDs (record_type 2 or 3)
    let mut env_ids: Vec<Uuid> = Vec::new();
    {
        let mut stmt = conn
            .prepare(
                "SELECT id FROM records WHERE record_type IN (2, 3) AND parent_id = ?1 AND deleted = 0",
            )
            .map_err(|_| Error::Storage)?;
        let mut rows = stmt
            .query(params![project_id.as_bytes().as_slice()])
            .map_err(|_| Error::Storage)?;
        while let Some(row) = rows.next().map_err(|_| Error::Storage)? {
            let bytes: Vec<u8> = row.get(0).map_err(|_| Error::Storage)?;
            let id = Uuid::from_slice(&bytes).map_err(|_| Error::Storage)?;
            env_ids.push(id);
        }
    }

    // 3. Collect child secret IDs under project or environments
    let mut secret_ids: Vec<Uuid> = Vec::new();
    // Direct children under project
    {
        let mut stmt = conn
            .prepare(
                "SELECT id FROM records WHERE record_type IN (4, 5, 6) AND parent_id = ?1 AND deleted = 0",
            )
            .map_err(|_| Error::Storage)?;
        let mut rows = stmt
            .query(params![project_id.as_bytes().as_slice()])
            .map_err(|_| Error::Storage)?;
        while let Some(row) = rows.next().map_err(|_| Error::Storage)? {
            let bytes: Vec<u8> = row.get(0).map_err(|_| Error::Storage)?;
            secret_ids.push(Uuid::from_slice(&bytes).map_err(|_| Error::Storage)?);
        }
    }
    // Grandchildren under environments
    for env_id in &env_ids {
        let mut stmt = conn
            .prepare(
                "SELECT id FROM records WHERE record_type IN (3, 4, 5, 6) AND parent_id = ?1 AND deleted = 0",
            )
            .map_err(|_| Error::Storage)?;
        let mut rows = stmt
            .query(params![env_id.as_bytes().as_slice()])
            .map_err(|_| Error::Storage)?;
        while let Some(row) = rows.next().map_err(|_| Error::Storage)? {
            let bytes: Vec<u8> = row.get(0).map_err(|_| Error::Storage)?;
            let id = Uuid::from_slice(&bytes).map_err(|_| Error::Storage)?;
            secret_ids.push(id);
        }
    }

    // 4. In a single transaction, bump lamport and mark all deleted=1, blob=NULL
    let mut current_lamport = get_highest_lamport(conn)?;
    let tx = conn.transaction().map_err(|_| Error::Storage)?;

    // Soft-delete project
    current_lamport += 1;
    tx.execute(
        "UPDATE records SET deleted = 1, blob = NULL, lamport = ?1, origin_device = ?2, updated_at = ?3 WHERE id = ?4",
        params![
            current_lamport as i64,
            origin_device,
            now_ms,
            project_id.as_bytes().as_slice(),
        ],
    )
    .map_err(|_| Error::Storage)?;

    // Soft-delete child environments
    for env_id in &env_ids {
        current_lamport += 1;
        tx.execute(
            "UPDATE records SET deleted = 1, blob = NULL, lamport = ?1, origin_device = ?2, updated_at = ?3 WHERE id = ?4",
            params![
                current_lamport as i64,
                origin_device,
                now_ms,
                env_id.as_bytes().as_slice(),
            ],
        )
        .map_err(|_| Error::Storage)?;
    }

    // Soft-delete child secrets
    for secret_id in &secret_ids {
        current_lamport += 1;
        tx.execute(
            "UPDATE records SET deleted = 1, blob = NULL, lamport = ?1, origin_device = ?2, updated_at = ?3 WHERE id = ?4",
            params![
                current_lamport as i64,
                origin_device,
                now_ms,
                secret_id.as_bytes().as_slice(),
            ],
        )
        .map_err(|_| Error::Storage)?;
    }

    tx.commit().map_err(|_| Error::Storage)?;

    Ok(CascadeDeleteSummary {
        id: project_id,
        environments_deleted: env_ids.len(),
        secrets_deleted: secret_ids.len(),
        total_records_affected: 1 + env_ids.len() + secret_ids.len(),
    })
}

/// Cascades deletion of an environment and all its child secrets.
///
/// Invariant: Refuses deletion if this is the last remaining active environment
/// in its parent project, returning `Error::LastEnvironment`.
pub fn cascade_delete_environment(
    conn: &mut Connection,
    env_id: Uuid,
    origin_device: &str,
    now_ms: i64,
) -> Result<CascadeDeleteSummary> {
    // 1. Verify environment exists and get its parent project_id (accepts record_type 2 or 3)
    let parent_id_bytes: Option<Vec<u8>> = conn
        .query_row(
            "SELECT parent_id FROM records WHERE id = ?1 AND record_type IN (2, 3) AND deleted = 0",
            params![env_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .map_err(|err| match err {
            rusqlite::Error::QueryReturnedNoRows => Error::NotFound,
            _ => Error::Storage,
        })?;

    let project_id_bytes = parent_id_bytes.ok_or(Error::NotFound)?;
    let project_id = Uuid::from_slice(&project_id_bytes).map_err(|_| Error::Storage)?;

    // 2. Check last environment protection: count active envs for this project
    let active_env_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM records WHERE record_type IN (2, 3) AND parent_id = ?1 AND deleted = 0",
            params![project_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .map_err(|_| Error::Storage)?;

    if active_env_count <= 1 {
        return Err(Error::LastEnvironment);
    }

    // 3. Collect child secret IDs under this environment
    let mut secret_ids: Vec<Uuid> = Vec::new();
    {
        let mut stmt = conn
            .prepare(
                "SELECT id FROM records WHERE record_type IN (3, 4, 5, 6) AND parent_id = ?1 AND deleted = 0",
            )
            .map_err(|_| Error::Storage)?;
        let mut rows = stmt
            .query(params![env_id.as_bytes().as_slice()])
            .map_err(|_| Error::Storage)?;
        while let Some(row) = rows.next().map_err(|_| Error::Storage)? {
            let bytes: Vec<u8> = row.get(0).map_err(|_| Error::Storage)?;
            let id = Uuid::from_slice(&bytes).map_err(|_| Error::Storage)?;
            secret_ids.push(id);
        }
    }

    // 4. In a transaction, bump lamport and mark environment and secrets deleted=1, blob=NULL
    let mut current_lamport = get_highest_lamport(conn)?;
    let tx = conn.transaction().map_err(|_| Error::Storage)?;

    // Soft-delete environment
    current_lamport += 1;
    tx.execute(
        "UPDATE records SET deleted = 1, blob = NULL, lamport = ?1, origin_device = ?2, updated_at = ?3 WHERE id = ?4",
        params![
            current_lamport as i64,
            origin_device,
            now_ms,
            env_id.as_bytes().as_slice(),
        ],
    )
    .map_err(|_| Error::Storage)?;

    // Soft-delete child secrets
    for secret_id in &secret_ids {
        current_lamport += 1;
        tx.execute(
            "UPDATE records SET deleted = 1, blob = NULL, lamport = ?1, origin_device = ?2, updated_at = ?3 WHERE id = ?4",
            params![
                current_lamport as i64,
                origin_device,
                now_ms,
                secret_id.as_bytes().as_slice(),
            ],
        )
        .map_err(|_| Error::Storage)?;
    }

    tx.commit().map_err(|_| Error::Storage)?;

    Ok(CascadeDeleteSummary {
        id: env_id,
        environments_deleted: 1,
        secrets_deleted: secret_ids.len(),
        total_records_affected: 1 + secret_ids.len(),
    })
}

// ============================================================================
// 8. Metadata Storage Helpers
// ============================================================================

/// Retrieves a value from the `meta` table by key.
pub fn get_meta(conn: &Connection, key: &str) -> Result<Option<String>> {
    let mut stmt = conn
        .prepare("SELECT value FROM meta WHERE key = ?1")
        .map_err(|_| Error::Storage)?;
    let mut rows = stmt.query(params![key]).map_err(|_| Error::Storage)?;
    if let Some(row) = rows.next().map_err(|_| Error::Storage)? {
        let val: String = row.get(0).map_err(|_| Error::Storage)?;
        Ok(Some(val))
    } else {
        Ok(None)
    }
}

/// Sets or updates a key-value pair in the `meta` table.
pub fn set_meta(conn: &Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
        params![key, value],
    )
    .map_err(|_| Error::Storage)?;
    Ok(())
}

// ============================================================================
// Internal Helpers
// ============================================================================

fn parse_space_row(row: &Row<'_>) -> Result<SpaceRow> {
    let id_bytes: Vec<u8> = row.get(0).map_err(|_| Error::Storage)?;
    let id = Uuid::from_slice(&id_bytes).map_err(|_| Error::Storage)?;
    let name_blob: Vec<u8> = row.get(1).map_err(|_| Error::Storage)?;
    let position: i64 = row.get(2).map_err(|_| Error::Storage)?;
    let created_at: i64 = row.get(3).map_err(|_| Error::Storage)?;
    let updated_at: i64 = row.get(4).map_err(|_| Error::Storage)?;
    let deleted_num: i64 = row.get(5).map_err(|_| Error::Storage)?;

    Ok(SpaceRow {
        id,
        name_blob,
        position: position as u32,
        created_at,
        updated_at,
        deleted: deleted_num != 0,
    })
}

fn parse_label_row(row: &Row<'_>) -> Result<LabelRow> {
    let id_bytes: Vec<u8> = row.get(0).map_err(|_| Error::Storage)?;
    let id = Uuid::from_slice(&id_bytes).map_err(|_| Error::Storage)?;
    let space_id_bytes: Option<Vec<u8>> = row.get(1).map_err(|_| Error::Storage)?;
    let space_id = match space_id_bytes {
        Some(b) => Some(Uuid::from_slice(&b).map_err(|_| Error::Storage)?),
        None => None,
    };
    let name_blob: Vec<u8> = row.get(2).map_err(|_| Error::Storage)?;
    let position: i64 = row.get(3).map_err(|_| Error::Storage)?;
    let created_at: i64 = row.get(4).map_err(|_| Error::Storage)?;
    let updated_at: i64 = row.get(5).map_err(|_| Error::Storage)?;
    let deleted_num: i64 = row.get(6).map_err(|_| Error::Storage)?;

    Ok(LabelRow {
        id,
        space_id,
        name_blob,
        position: position as u32,
        created_at,
        updated_at,
        deleted: deleted_num != 0,
    })
}

fn parse_record_row(row: &Row<'_>) -> Result<RecordRow> {
    let id_bytes: Vec<u8> = row.get(0).map_err(|_| Error::Storage)?;
    let id = Uuid::from_slice(&id_bytes).map_err(|_| Error::Storage)?;

    let rtype_num: u8 = row.get(1).map_err(|_| Error::Storage)?;
    let record_type = RecordType::try_from(rtype_num).map_err(|_| Error::Storage)?;

    let parent_id_bytes: Option<Vec<u8>> = row.get(2).map_err(|_| Error::Storage)?;
    let parent_id = match parent_id_bytes {
        Some(bytes) => Some(Uuid::from_slice(&bytes).map_err(|_| Error::Storage)?),
        None => None,
    };

    let key_epoch: u32 = row.get(3).map_err(|_| Error::Storage)?;
    let blob: Option<Vec<u8>> = row.get(4).map_err(|_| Error::Storage)?;
    let lamport: i64 = row.get(5).map_err(|_| Error::Storage)?;
    let origin_device: String = row.get(6).map_err(|_| Error::Storage)?;
    let updated_at: i64 = row.get(7).map_err(|_| Error::Storage)?;
    let deleted_num: i64 = row.get(8).map_err(|_| Error::Storage)?;

    Ok(RecordRow {
        id,
        record_type,
        parent_id,
        key_epoch,
        blob,
        lamport: lamport as u64,
        origin_device,
        updated_at,
        deleted: deleted_num != 0,
    })
}
