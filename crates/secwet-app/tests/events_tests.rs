//! The app layer reports changes through the host's `EventSink`.

use std::sync::{Arc, Mutex};

use secwet_app::{AppEvent, AppState};
use secwet_core::keys::MemoryStore;
use tempfile::tempdir;

#[test]
fn test_mutations_and_lock_reach_the_event_sink() {
    let dir = tempdir().unwrap();
    let state = AppState::new(dir.path().to_path_buf(), Arc::new(MemoryStore::new()));
    let seen: Arc<Mutex<Vec<AppEvent>>> = Arc::default();
    let sink = Arc::clone(&seen);
    state.set_event_sink(Arc::new(move |e: AppEvent| sink.lock().unwrap().push(e)));

    state.secwet_create(Some("Test Mac".into())).unwrap();
    state.space_create("Work".into(), None).unwrap();
    state.secwet_lock().unwrap();

    let events = seen.lock().unwrap().clone();
    assert_eq!(events.first(), Some(&AppEvent::changed("all")));
    assert!(events.contains(&AppEvent::changed("spaces")));
    assert_eq!(events.last(), Some(&AppEvent::Locked));
    assert_eq!(AppEvent::Locked.name(), "secwet://locked");
    assert_eq!(AppEvent::Locked.payload(), serde_json::Value::Null);
    assert_eq!(
        AppEvent::changed("spaces").payload(),
        serde_json::json!({ "scope": "spaces" })
    );
}

#[test]
fn test_events_are_dropped_without_a_sink() {
    let dir = tempdir().unwrap();
    let state = AppState::new(dir.path().to_path_buf(), Arc::new(MemoryStore::new()));
    state.secwet_create(None).unwrap();
    state.secwet_lock().unwrap();
}
