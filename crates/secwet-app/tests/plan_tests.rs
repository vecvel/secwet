//! F13: plans in the app layer. A Free store never contacts the relay.
//!
//! The relay here is a trap: a real TCP listener that counts every
//! connection. Any network call from a Free store fails the test.

use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use secwet_app::AppState;
use secwet_core::keys::MemoryStore;
use secwet_core::{MemoryStore as CoreMemoryStore, PlanState, RelayClient, Secwet};
use tempfile::tempdir;
use uuid::Uuid;

/// A relay address that records every connection attempt.
struct TrapRelay {
    url: String,
    hits: Arc<AtomicUsize>,
}

impl TrapRelay {
    fn start() -> TrapRelay {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                counter.fetch_add(1, Ordering::SeqCst);
                drop(conn);
            }
        });
        TrapRelay { url, hits }
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

fn code<T: std::fmt::Debug>(r: Result<T, secwet_app::UiError>) -> String {
    r.expect_err("must fail").code
}

#[tokio::test]
async fn free_plan_never_calls_relay() {
    let relay = TrapRelay::start();
    let dir = tempdir().unwrap();
    let state = AppState::new(dir.path().to_path_buf(), Arc::new(MemoryStore::new()));
    state.secwet_create(Some("Test Mac".into())).unwrap();
    // Even with a relay address set, Free stays local.
    state.relay_set_url(relay.url.clone()).unwrap();

    let plan = state.plan_status().unwrap();
    assert_eq!(plan.plan, "free");
    assert_eq!(plan.device_limit, 1);
    assert!(!plan.sync_enabled && !plan.relay_security);

    let status = state.relay_status().await.unwrap();
    assert!(!status.connected);
    assert_eq!(status.plan, "free");
    assert_eq!(state.plan_refresh().await.unwrap().plan, "free");

    assert_eq!(code(state.sync_now().await), "needs_pro");
    assert_eq!(code(state.sync_round().await), "needs_pro");
    assert_eq!(code(state.pairing_start().await), "needs_pro");
    assert_eq!(code(state.key_rotate().await), "needs_pro");
    assert_eq!(code(state.members_list().await), "needs_pro");
    assert_eq!(code(state.member_invite("a@example.com".into(), vec![]).await), "needs_pro");
    assert_eq!(code(state.member_set_grants(Uuid::new_v4().to_string(), vec![]).await), "needs_pro");
    assert_eq!(code(state.member_remove(Uuid::new_v4().to_string(), false).await), "needs_pro");
    assert_eq!(code(state.invitation_revoke(Uuid::new_v4().to_string()).await), "needs_pro");
    // Free revocation only changes the local record.
    let _ = state.device_revoke("unknown-device".into(), true).await;

    // Local data keeps working.
    let space = state.space_create("Work".into(), None).unwrap();
    assert_eq!(state.spaces_list().unwrap().iter().filter(|s| s.id == space.id).count(), 1);

    // The core paths refuse on their own too, before any request.
    let core_dir = tempdir().unwrap();
    let ks = CoreMemoryStore::new();
    let mut s = Secwet::create(core_dir.path(), "Core Mac", &ks).unwrap();
    s.set_relay_url(&relay.url).unwrap();
    let client = RelayClient::new(relay.url.clone(), s.device_id().to_string());
    assert!(matches!(s.sync_round(&client, &ks).await, Err(secwet_core::Error::NeedsPro)));
    assert!(matches!(s.push_outbox(&client).await, Err(secwet_core::Error::NeedsPro)));
    assert!(matches!(s.pull_and_apply_events(&client).await, Err(secwet_core::Error::NeedsPro)));
    assert_eq!(s.refresh_plan(&client).await.unwrap().state, PlanState::Free);
    assert_eq!(s.sync_entitlement_from_relay().await.unwrap().state, PlanState::Free);
    assert_eq!(s.pending_outbox_count().unwrap(), 0, "Free never queues sync events");

    assert_eq!(relay.hits(), 0, "a Free store contacted the relay");

    // Control: the explicit "Check for Pro" is the one call Free makes, and
    // the trap sees it.
    assert!(state.plan_activate().await.is_err());
    assert!(relay.hits() > 0);
}

#[tokio::test]
async fn paused_plan_blocks_pairing_without_network_and_keeps_data() {
    let relay = TrapRelay::start();
    let dir = tempdir().unwrap();
    let state = AppState::new(dir.path().to_path_buf(), Arc::new(MemoryStore::new()));
    state.secwet_create(Some("Test Mac".into())).unwrap();
    state.relay_set_url(relay.url.clone()).unwrap();
    // Pro that ended yesterday.
    state
        .with_secwet_mut(|s| {
            s.apply_entitlement(&secwet_proto::EntitlementResponse {
                secwet_id: s.secwet_id(),
                plan: "pro".into(),
                device_limit: 5,
                expires_at: Some("2001-01-01T00:00:00Z".into()),
            })
        })
        .unwrap();

    let plan = state.plan_status().unwrap();
    assert_eq!(plan.plan, "paused");
    assert!(!plan.sync_enabled);
    assert!(plan.relay_security, "revocation stays available");
    assert_eq!(code(state.pairing_start().await), "sync_paused");
    assert_eq!(relay.hits(), 0);

    // Writes still work and wait in the outbox for renewal.
    let space = state.space_create("Work".into(), None).unwrap();
    state.label_create_in_space("Ops".into(), None, Some(space.id)).unwrap();
    assert!(state.sync_status().unwrap().pending_outbox_count > 0);
}
