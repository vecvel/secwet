use secwet_core::keys::MemoryStore;
use secwet_core::model::{SecretDraft, SecretKind};
use secwet_core::Secwet;
use std::sync::Arc;
use tempfile::tempdir;

#[test]
fn test_active_sessions_lifecycle() {
    let dir = tempdir().unwrap();
    let keystore = Arc::new(MemoryStore::new());
    let mut secwet = Secwet::create(dir.path(), "test-device", keystore.as_ref()).unwrap();

    let label = secwet.create_label("Backend", None).unwrap();
    let item = secwet.create_item(label.id, "API Service", None).unwrap();
    let secret = secwet
        .create_secret(SecretDraft::new(
            item.id,
            None,
            "DATABASE_URL",
            SecretKind::EnvVar,
            "postgres://localhost:5432/db",
            None,
        ))
        .unwrap();

    // 1. Initially no active sessions
    let sessions = secwet.list_active_sessions().unwrap();
    assert!(sessions.is_empty());

    // 2. Register an active session for the current running process (our own test PID)
    let my_pid = std::process::id();
    let sess = secwet
        .create_active_session(my_pid, item.id, None, "cargo test", &[secret.id])
        .unwrap();

    assert_eq!(sess.pid, my_pid);
    assert_eq!(sess.item_id, item.id);
    assert_eq!(sess.secret_ids, vec![secret.id]);

    // 3. List active sessions includes this process
    let active = secwet.list_active_sessions().unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].session_id, sess.session_id);

    // 4. Register a dummy session with a dead PID (e.g. 99999999)
    let dead_sess = secwet
        .create_active_session(99_999_999, item.id, None, "dead cmd", &[secret.id])
        .unwrap();

    // 5. Querying list_active_sessions automatically prunes dead sessions!
    let active_after_prune = secwet.list_active_sessions().unwrap();
    assert_eq!(active_after_prune.len(), 1);
    assert_eq!(active_after_prune[0].session_id, sess.session_id);

    // Check dead session was removed from database
    let lookup_dead = secwet_core::sessions::get_active_session(
        secwet.db_connection(),
        &dead_sess.session_id,
    )
    .unwrap();
    assert!(lookup_dead.is_none());

    // 6. Delete active session
    secwet.delete_active_session(&sess.session_id).unwrap();
    let empty = secwet.list_active_sessions().unwrap();
    assert!(empty.is_empty());
}
