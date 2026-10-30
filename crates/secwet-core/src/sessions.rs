//! Active session tracking and process management for secwet run.
//!
//! Invariants:
//! - Unencrypted local storage: active_sessions tracks running processes on the current device.
//! - Stores PIDs, command names, target item/environment IDs, and injected secret IDs.
//! - ZERO secret values are ever written to active_sessions.
//! - Automatically purges stale/dead processes on query.

use crate::{Error, Result};
use rusqlite::{params, Connection, Row};
use secwet_proto::ActiveSession;
use uuid::Uuid;

pub fn init_active_sessions_table(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS active_sessions (
            session_id TEXT PRIMARY KEY,
            pid INTEGER NOT NULL,
            item_id TEXT NOT NULL,
            environment_id TEXT,
            command TEXT NOT NULL,
            secret_ids TEXT NOT NULL,
            started_at INTEGER NOT NULL
        );",
    )
    .map_err(|_| Error::Storage)?;
    Ok(())
}

pub fn insert_active_session(conn: &Connection, session: &ActiveSession) -> Result<()> {
    let secret_ids_json = serde_json::to_string(&session.secret_ids).map_err(|_| Error::Storage)?;
    let env_str = session.environment_id.map(|e| e.to_string());
    conn.execute(
        "INSERT OR REPLACE INTO active_sessions (session_id, pid, item_id, environment_id, command, secret_ids, started_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            session.session_id,
            session.pid as i64,
            session.item_id.to_string(),
            env_str,
            session.command,
            secret_ids_json,
            session.started_at,
        ],
    )
    .map_err(|_| Error::Storage)?;
    Ok(())
}

pub fn delete_active_session(conn: &Connection, session_id: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM active_sessions WHERE session_id = ?1",
        params![session_id],
    )
    .map_err(|_| Error::Storage)?;
    Ok(())
}

pub fn get_active_session(conn: &Connection, session_id: &str) -> Result<Option<ActiveSession>> {
    let mut stmt = conn
        .prepare(
            "SELECT session_id, pid, item_id, environment_id, command, secret_ids, started_at
             FROM active_sessions WHERE session_id = ?1",
        )
        .map_err(|_| Error::Storage)?;

    let mut rows = stmt
        .query(params![session_id])
        .map_err(|_| Error::Storage)?;

    if let Some(row) = rows.next().map_err(|_| Error::Storage)? {
        parse_active_session_row(row)
            .map(Some)
            .map_err(|_| Error::Storage)
    } else {
        Ok(None)
    }
}

pub fn query_all_active_sessions(conn: &Connection) -> Result<Vec<ActiveSession>> {
    let mut stmt = conn
        .prepare(
            "SELECT session_id, pid, item_id, environment_id, command, secret_ids, started_at
             FROM active_sessions ORDER BY started_at DESC",
        )
        .map_err(|_| Error::Storage)?;

    let rows = stmt
        .query_map([], parse_active_session_row)
        .map_err(|_| Error::Storage)?;

    let mut sessions = Vec::new();
    for r in rows {
        sessions.push(r.map_err(|_| Error::Storage)?);
    }
    Ok(sessions)
}

fn parse_active_session_row(row: &Row<'_>) -> rusqlite::Result<ActiveSession> {
    let session_id: String = row.get(0)?;
    let pid_num: i64 = row.get(1)?;
    let item_str: String = row.get(2)?;
    let env_str: Option<String> = row.get(3)?;
    let command: String = row.get(4)?;
    let secrets_json: String = row.get(5)?;
    let started_at: i64 = row.get(6)?;

    let item_id = Uuid::parse_str(&item_str).unwrap_or_else(|_| Uuid::nil());
    let environment_id = env_str.and_then(|s| Uuid::parse_str(&s).ok());
    let secret_ids: Vec<Uuid> = serde_json::from_str(&secrets_json).unwrap_or_default();

    Ok(ActiveSession {
        session_id,
        pid: pid_num as u32,
        item_id,
        environment_id,
        command,
        secret_ids,
        started_at,
    })
}

#[cfg(unix)]
pub fn is_process_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    let res = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if res == 0 {
        return true;
    }
    let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    err == libc::EPERM
}

#[cfg(not(unix))]
pub fn is_process_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    let output = std::process::Command::new("tasklist")
        .args(["/FI", &format!("PID eq {}", pid)])
        .output();
    if let Ok(out) = output {
        let text = String::from_utf8_lossy(&out.stdout);
        text.contains(&pid.to_string())
    } else {
        false
    }
}

#[cfg(unix)]
pub fn kill_process(pid: u32) -> Result<()> {
    if pid == 0 {
        return Ok(());
    }
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGTERM);
    }
    std::thread::sleep(std::time::Duration::from_millis(60));
    if is_process_alive(pid) {
        unsafe {
            libc::kill(pid as libc::pid_t, libc::SIGKILL);
        }
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn kill_process(pid: u32) -> Result<()> {
    if pid == 0 {
        return Ok(());
    }
    let _ = std::process::Command::new("taskkill")
        .args(["/F", "/PID", &pid.to_string()])
        .output();
    Ok(())
}

pub fn list_active_sessions(conn: &Connection) -> Result<Vec<ActiveSession>> {
    let all = query_all_active_sessions(conn)?;
    let mut alive = Vec::new();
    for session in all {
        if is_process_alive(session.pid) {
            alive.push(session);
        } else {
            let _ = delete_active_session(conn, &session.session_id);
        }
    }
    Ok(alive)
}

pub fn stop_session(conn: &Connection, session_id: &str) -> Result<()> {
    if let Some(session) = get_active_session(conn, session_id)? {
        let _ = kill_process(session.pid);
        delete_active_session(conn, session_id)?;
    }
    Ok(())
}

