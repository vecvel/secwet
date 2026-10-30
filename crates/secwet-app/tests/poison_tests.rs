//! A panic while the store mutex is held must not keep the keys in memory:
//! locking still works and clears the poison.

use std::sync::Arc;

use secwet_app::AppState;
use secwet_core::keys::MemoryStore;
use tempfile::tempdir;

#[test]
fn test_lock_works_after_a_panic_poisoned_the_store() {
    let dir = tempdir().unwrap();
    let state = Arc::new(AppState::new(dir.path().to_path_buf(), Arc::new(MemoryStore::new())));
    state.secwet_create(Some("Test Mac".into())).unwrap();

    let poisoner = Arc::clone(&state);
    let _ = std::thread::spawn(move || {
        let _guard = poisoner.secwet.lock().unwrap();
        panic!("command panicked while holding the store");
    })
    .join();
    assert!(state.secwet.is_poisoned());
    assert_eq!(state.spaces_list().unwrap_err().code, "internal");

    state.secwet_lock().unwrap();
    assert!(!state.secwet.is_poisoned());
    assert!(state.secwet.lock().unwrap().is_none());

    state.secwet_unlock().unwrap();
    state.spaces_list().unwrap();
}
