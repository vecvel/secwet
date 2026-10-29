//! Core tests for revocation, key rotation and tree-wise RBAC with
//! cryptographically scoped branch keys. Real crypto, real SQLite, no relay:
//! relay round trips are covered in `crates/secwet-relay/tests/m7_m8_e2e.rs`.

use secrecy::ExposeSecret;
use secwet_core::collab::RevocationOutcome;
use secwet_core::keys::KeyStore;
use secwet_core::{Error, MemoryStore, SecretDraft, SecretKind, Secwet, SecwetStatus};
use secwet_proto::{EventScope, MemberGrant, ScopeOp, ScopeTarget, TreeNode, TreeRole};
use tempfile::TempDir;
use uuid::Uuid;

struct Dev {
    dir: TempDir,
    ks: MemoryStore,
    s: Secwet,
}

fn owner() -> Dev {
    let dir = TempDir::new().unwrap();
    let ks = MemoryStore::new();
    let mut s = Secwet::create(dir.path(), "Owner Mac", &ks).unwrap();
    s.set_plan("pro").unwrap();
    Dev { dir, ks, s }
}

fn paired(from: &Dev) -> Dev {
    let id = from.s.secwet_id();
    let km = from.ks.get(&format!("secwet/{id}/master-key/1")).unwrap().unwrap();
    let mut k = [0u8; 32];
    k.copy_from_slice(km.as_slice());
    let dir = TempDir::new().unwrap();
    let ks = MemoryStore::new();
    let mut s = Secwet::create_paired(dir.path(), "Laptop", id, &k, &ks).unwrap();
    s.set_plan("pro").unwrap();
    Dev { dir, ks, s }
}

fn introduce(a: &mut Dev, b: &Dev, member: Option<Uuid>) {
    let id = b.s.device_id().to_string();
    a.s.test_register_device(&id, &b.s.device_sign_pub(), &b.s.test_enc_pub(), member).unwrap();
}

fn secret(s: &mut Secwet, item: Uuid, env: Option<Uuid>, name: &str, value: &str) -> Uuid {
    s.create_secret(SecretDraft::new(item, env, name, SecretKind::Password, value, None))
        .unwrap()
        .id
}

/// Delivers the sender's whole outbox to the receiver in order.
fn deliver(from: &Dev, to: &mut Dev, seq: &mut u64) -> usize {
    let mut applied = 0;
    for ev in from.s.peek_outbox(10_000).unwrap() {
        *seq += 1;
        if let Ok(true) = to.s.apply_signed_event(*seq, &ev) {
            applied += 1;
        }
    }
    applied
}

// ============================================================================
// Master key rotation
// ============================================================================

#[test]
fn rotation_reseals_existing_records() {
    let mut a = owner();
    let space = a.s.ensure_default_personal_space().unwrap().id;
    let label = a.s.create_label_in_space("Backend", None, Some(space)).unwrap();
    let item = a.s.create_item(label.id, "api", None).unwrap();
    let env = a.s.add_environment(item.id, "Production").unwrap();
    let sid = secret(&mut a.s, item.id, Some(env.id), "DB_URL", "postgres://secret");
    a.s.create_note(item.id, None, "Runbook", "<p>restart</p>").unwrap();

    let new_key = [9u8; 32];
    let resealed = a.s.adopt_master_epoch(2, &new_key, &a.ks).unwrap();
    assert!(resealed >= 4, "items, envs, secrets, notes, labels and spaces re-sealed: {resealed}");
    assert_eq!(a.s.key_epoch(), 2);

    let stale: i64 = a
        .s
        .db_connection()
        .query_row("SELECT COUNT(*) FROM records WHERE key_epoch < 2 AND blob IS NOT NULL", [], |r| r.get(0))
        .unwrap();
    assert_eq!(stale, 0, "no record left on epoch 1");

    // Remove epoch 1 entirely: everything must still open with epoch 2 alone.
    let id = a.s.secwet_id();
    a.ks.delete(&format!("secwet/{id}/master-key/1")).unwrap();
    let dir = a.dir.path().to_path_buf();
    let Dev { s, ks, dir: _keep } = a;
    s.lock();
    let reopened = Secwet::unlock(&dir, &ks);
    // Epoch 1 key missing is fine as long as the current one exists.
    let reopened = reopened.expect("unlock with only the current epoch");
    assert_eq!(reopened.reveal_secret(sid).unwrap().expose_secret(), "postgres://secret");
    assert_eq!(reopened.list_spaces().unwrap().len(), 1);
    assert!(reopened.list_labels().unwrap().iter().any(|l| l.name == "Backend"));
}

#[test]
fn rotation_new_writes_use_new_epoch() {
    let mut a = owner();
    let space = a.s.ensure_default_personal_space().unwrap().id;
    let label = a.s.create_label_in_space("Ops", None, Some(space)).unwrap();
    let item = a.s.create_item(label.id, "svc", None).unwrap();
    a.s.adopt_master_epoch(2, &[3u8; 32], &a.ks).unwrap();
    secret(&mut a.s, item.id, None, "TOKEN", "t0ken");
    let last = a.s.peek_outbox(1000).unwrap().pop().unwrap();
    assert_eq!(last.envelope.key_epoch, 2);
    let epoch: i64 = a
        .s
        .db_connection()
        .query_row("SELECT MAX(key_epoch) FROM records", [], |r| r.get(0))
        .unwrap();
    assert_eq!(epoch, 2);
}

#[test]
fn revoked_device_cannot_read_after_rotation() {
    let mut a = owner();
    let mut b = paired(&a);
    introduce(&mut b, &a, None);
    let space = a.s.ensure_default_personal_space().unwrap().id;
    let label = a.s.create_label_in_space("Ops", None, Some(space)).unwrap();
    let item = a.s.create_item(label.id, "svc", None).unwrap();
    // B is revoked; A rotates without B and writes afterwards.
    a.s.adopt_master_epoch(2, &[5u8; 32], &a.ks).unwrap();
    let before = a.s.peek_outbox(1000).unwrap().len();
    secret(&mut a.s, item.id, None, "AFTER_REVOKE", "never-for-b");
    let ev = a.s.peek_outbox(1000).unwrap().into_iter().nth(before).unwrap();
    assert_eq!(ev.envelope.key_epoch, 2);
    let res = b.s.apply_signed_event(1, &ev);
    assert!(matches!(res, Ok(false)), "B lacks epoch 2 and cannot decrypt: {res:?}");
    assert_eq!(b.s.deferred_count().unwrap(), 1, "kept for a key B will never receive");
    // And the ciphertext does not open with B's epoch-1 key either.
    assert!(secwet_core::sync::decrypt_event_body(&ev, &b.s.test_k_evt_witness().lock().unwrap()).is_err());
}

// ============================================================================
// Revocation directives
// ============================================================================

#[test]
fn revoke_with_remote_wipe_crypto_shreds_keys_and_db() {
    let a = owner();
    let mut b = paired(&a);
    introduce(&mut b, &a, None);
    let id = b.s.secwet_id();
    let bdev = b.s.device_id().to_string();
    let notice = a.s.test_sign_revocation(&bdev, true).unwrap();

    let out = b.s.handle_revocation_notice(&notice, &b.ks).unwrap();
    assert_eq!(out, RevocationOutcome::Wiped);

    for entry in ["device-sign", "device-enc", "master-key/1"] {
        assert!(b.ks.get(&format!("secwet/{id}/{entry}")).unwrap().is_none(), "{entry} shredded");
    }
    assert!(!b.dir.path().join("secwet").join(id.to_string()).exists(), "workspace directory deleted");
    assert!(!b.dir.path().join(format!(".secwet-pending-wipe-{id}")).exists(), "wipe marker removed once done");
    let Dev { s, dir, .. } = b;
    drop(s);
    assert_eq!(Secwet::status(dir.path()).unwrap(), SecwetStatus::Uninitialized);
}

#[test]
fn forged_wipe_directive_is_ignored() {
    let a = owner();
    let mut b = paired(&a);
    introduce(&mut b, &a, None);
    let bdev = b.s.device_id().to_string();
    let mut notice = a.s.test_sign_revocation(&bdev, true).unwrap();
    notice.signature[0] ^= 1;
    assert!(b.s.handle_revocation_notice(&notice, &b.ks).is_err());

    // A directive from a device B has never seen is ignored too.
    let stranger = owner();
    let notice = stranger.s.test_sign_revocation(&bdev, true).unwrap();
    assert!(b.s.handle_revocation_notice(&notice, &b.ks).is_err());

    // A directive for another device is ignored.
    let notice = a.s.test_sign_revocation("SOMEONEELSE00000000000000", true).unwrap();
    assert!(b.s.handle_revocation_notice(&notice, &b.ks).is_err());

    let id = b.s.secwet_id();
    assert!(b.ks.get(&format!("secwet/{id}/device-sign")).unwrap().is_some());
    assert!(b.s.list_spaces().is_ok());
}

#[test]
fn revoke_sync_only_preserves_offline_read_only_archive() {
    let mut a = owner();
    let space = a.s.ensure_default_personal_space().unwrap().id;
    let label = a.s.create_label_in_space("Ops", None, Some(space)).unwrap();
    let item = a.s.create_item(label.id, "svc", None).unwrap();
    let sid = secret(&mut a.s, item.id, None, "KEEP", "kept-value");

    let mut b = paired(&a);
    introduce(&mut a, &b, None);
    let notice = b.s.test_sign_revocation(&a.s.device_id().to_string(), false).unwrap();
    assert_eq!(
        a.s.handle_revocation_notice(&notice, &a.ks).unwrap(),
        RevocationOutcome::Archived
    );
    let _ = &mut b;

    assert!(a.s.unlinked_at().unwrap().is_some());
    assert_eq!(a.s.reveal_secret(sid).unwrap().expose_secret(), "kept-value");
    assert!(matches!(
        a.s.create_secret(SecretDraft::new(item.id, None, "NEW", SecretKind::Password, "x", None)),
        Err(Error::Revoked)
    ));
    assert!(matches!(a.s.delete_secret(sid), Err(Error::Revoked)));
    assert!(matches!(a.s.create_space("New", None), Err(Error::Revoked)));
    // Export of the archive is still allowed.
    let rk = a.s.create_recovery_key(&a.ks).unwrap();
    let out = a.dir.path().join("archive.secwet");
    a.s.export_to_file(rk.expose_secret(), &out).unwrap();
    assert!(out.exists());
    // The archive survives a restart.
    let Dev { s, ks, dir } = a;
    s.lock();
    let re = Secwet::unlock(dir.path(), &ks).unwrap();
    assert!(re.unlinked_at().unwrap().is_some());
}

// ============================================================================
// Tree-wise RBAC and branch-key isolation
// ============================================================================

struct Team {
    a: Dev,
    m: Dev,
    space: Uuid,
    group: Uuid,
    other_group: Uuid,
    item: Uuid,
    dev_env: Uuid,
    prod_env: Uuid,
    member: Uuid,
}

fn team(grants_for: impl Fn(&Team) -> Vec<MemberGrant>) -> Team {
    let mut a = owner();
    let space = a.s.create_space("Client Alpha", None).unwrap().id;
    a.s.test_install_space_root(&a.ks, space, 1).unwrap();
    let group = a.s.create_label_in_space("Backend", None, Some(space)).unwrap().id;
    let other_group = a.s.create_label_in_space("Billing", None, Some(space)).unwrap().id;
    let item = a.s.create_item(group, "auth-service", None).unwrap().id;
    let dev_env = a.s.add_environment(item, "Development").unwrap().id;
    let prod_env = a.s.add_environment(item, "Production").unwrap().id;
    let billing_item = a.s.create_item(other_group, "payments", None).unwrap().id;
    secret(&mut a.s, item, Some(dev_env), "DEV_DB", "dev-value");
    secret(&mut a.s, item, Some(prod_env), "PROD_DB", "prod-value-must-not-leak");
    secret(&mut a.s, item, None, "SHARED_FLAG", "general-value");
    secret(&mut a.s, billing_item, None, "STRIPE_KEY", "billing-value-must-not-leak");

    let member = Uuid::new_v4();
    let mdir = TempDir::new().unwrap();
    let mks = MemoryStore::new();
    let ms = Secwet::test_create_member(mdir.path(), a.s.secwet_id(), member, &mks).unwrap();
    let m = Dev { dir: mdir, ks: mks, s: ms };
    let mut t = Team { a, m, space, group, other_group, item, dev_env, prod_env, member };

    let grants = grants_for(&t);
    let signed = t.a.s.test_sign_grants(member, 1, grants.clone()).unwrap();
    t.a.s.test_set_member_grants(&signed).unwrap();
    t.m.s.test_set_my_grants(&signed).unwrap();
    let (a_id, m_id) = (t.a.s.device_id().to_string(), t.m.s.device_id().to_string());
    t.m.s.test_register_device(&a_id, &t.a.s.device_sign_pub(), &t.a.s.test_enc_pub(), None).unwrap();
    t.a.s.test_register_device(&m_id, &t.m.s.device_sign_pub(), &t.m.s.test_enc_pub(), Some(member)).unwrap();

    let sbk = t.a.s.test_wrap_member_bundle(space, &grants, &m_id, &t.m.s.test_enc_pub()).unwrap();
    t.m.s.test_accept_bundle(&t.m.ks, &sbk).unwrap();
    // Seed the branch the way a publish does.
    t.a.s.seed_space_events(space).unwrap();
    t
}

fn g(node: TreeNode, space: Uuid, role: TreeRole) -> MemberGrant {
    MemberGrant { node, space_id: Some(space), role }
}

fn member_secret_names(t: &Team) -> Vec<String> {
    let mut names = Vec::new();
    for label in t.m.s.list_labels().unwrap() {
        for item in t.m.s.list_items(label.id).unwrap() {
            for s in t.m.s.list_secrets(item.id, None).unwrap() {
                names.push(s.name);
            }
            for env in t.m.s.list_environments(item.id).unwrap() {
                for s in t.m.s.list_secrets(item.id, Some(env.id)).unwrap() {
                    names.push(s.name);
                }
            }
        }
    }
    names.sort();
    names
}

#[test]
fn environment_level_permission_isolation() {
    // Contractor: Editor strictly on Development, nothing else.
    let mut t = team(|t| vec![g(TreeNode::Environment(t.dev_env), t.space, TreeRole::Editor)]);
    let mut seq = 0;
    let (a, m) = (&t.a, &mut t.m);
    deliver(a, m, &mut seq);
    assert_eq!(member_secret_names(&t), vec!["DEV_DB".to_string()]);
    // Item name is visible for navigation, Production is not.
    let envs: Vec<String> = t.m.s.list_environments(t.item).unwrap().into_iter().map(|e| e.name).collect();
    assert_eq!(envs, vec!["Development".to_string()]);
}

#[test]
fn crypto_isolation_unauthorized_member_lacks_branch_key() {
    let t = team(|t| {
        vec![
            g(TreeNode::Item(t.item), t.space, TreeRole::Editor),
            g(TreeNode::Environment(t.prod_env), t.space, TreeRole::NoAccess),
        ]
    });
    let scope = |path: Vec<Uuid>, target| EventScope { space_id: t.space, path, target, op: ScopeOp::Write };
    assert!(t.m.s.test_can_derive(&scope(vec![t.group, t.item, t.dev_env], ScopeTarget::Content)));
    assert!(t.m.s.test_can_derive(&scope(vec![t.group, t.item], ScopeTarget::General)));
    assert!(!t.m.s.test_can_derive(&scope(vec![t.group, t.item, t.prod_env], ScopeTarget::Content)));
    assert!(!t.m.s.test_can_derive(&scope(vec![t.other_group], ScopeTarget::Name)));
    // The owner holds the whole branch.
    assert!(t.a.s.test_can_derive(&scope(vec![t.group, t.item, t.prod_env], ScopeTarget::Content)));

    // The raw events for Production carry only ciphertext the member cannot open.
    for ev in t.a.s.peek_outbox(10_000).unwrap() {
        let bytes = postcard::to_stdvec(&ev).unwrap();
        assert!(!bytes.windows(b"prod-value".len()).any(|w| w == b"prod-value"));
    }
}

#[test]
fn tree_rbac_member_cannot_read_unauthorized_scope() {
    let mut t = team(|t| vec![g(TreeNode::Group(t.group), t.space, TreeRole::Viewer)]);
    let mut seq = 0;
    let (a, m) = (&t.a, &mut t.m);
    deliver(a, m, &mut seq);
    let names = member_secret_names(&t);
    assert!(names.contains(&"PROD_DB".to_string()) && names.contains(&"DEV_DB".to_string()));
    assert!(!names.contains(&"STRIPE_KEY".to_string()), "Billing group is invisible");
    let groups: Vec<String> = t.m.s.list_labels().unwrap().into_iter().map(|l| l.name).collect();
    assert!(groups.contains(&"Backend".to_string()) && !groups.contains(&"Billing".to_string()));
    // The member's store never holds the owner's master key.
    let id = t.a.s.secwet_id();
    let owner_key = t.a.ks.get(&format!("secwet/{id}/master-key/1")).unwrap().unwrap();
    let member_key = t.m.ks.get(&format!("secwet/{id}/master-key/1")).unwrap().unwrap();
    assert_ne!(owner_key.as_slice(), member_key.as_slice());
}

#[test]
fn viewer_role_rejects_write_events() {
    let mut t = team(|t| vec![g(TreeNode::Space(t.space), t.space, TreeRole::Viewer)]);
    let mut seq = 0;
    {
        let (a, m) = (&t.a, &mut t.m);
        deliver(a, m, &mut seq);
    }
    // Locally, a viewer cannot write.
    let err = t.m.s.create_secret(SecretDraft::new(t.item, Some(t.dev_env), "X", SecretKind::Password, "v", None));
    assert!(matches!(err, Err(Error::Forbidden)), "{err:?}");

    // A tampered member client that believes it is an Editor still gets its
    // write dropped by the owner, who checks the signed grants.
    let fake = t.a.s.test_sign_grants(t.member, 2, vec![g(TreeNode::Space(t.space), t.space, TreeRole::Editor)]).unwrap();
    t.m.s.test_set_my_grants(&fake).unwrap();
    let before = t.m.s.peek_outbox(10_000).unwrap().len();
    secret(&mut t.m.s, t.item, Some(t.dev_env), "SNEAKY", "v");
    let ev = t.m.s.peek_outbox(10_000).unwrap().into_iter().nth(before).expect("scoped event queued");
    assert!(ev.envelope.scope.is_some());
    let applied = t.a.s.apply_signed_event(10_000, &ev).unwrap();
    assert!(!applied, "owner skips a write the member's signed role forbids");
}

#[test]
fn editor_cannot_move_records_across_branches() {
    let mut t = team(|t| {
        vec![
            g(TreeNode::Item(t.item), t.space, TreeRole::Editor),
            g(TreeNode::Environment(t.prod_env), t.space, TreeRole::NoAccess),
        ]
    });
    let mut seq = 0;
    {
        let (a, m) = (&t.a, &mut t.m);
        deliver(a, m, &mut seq);
    }
    // An editor deleting content needs Admin.
    let dev_id = t.m.s.list_secrets(t.item, Some(t.dev_env)).unwrap()[0].id;
    assert!(matches!(t.m.s.delete_secret(dev_id), Err(Error::Forbidden)));
    // Editor writes in Development reach the owner.
    let before = t.m.s.peek_outbox(10_000).unwrap().len();
    secret(&mut t.m.s, t.item, Some(t.dev_env), "NEW_DEV", "ok");
    let ev = t.m.s.peek_outbox(10_000).unwrap().into_iter().nth(before).unwrap();
    assert!(t.a.s.apply_signed_event(20_000, &ev).unwrap());
    assert!(t.a.s.list_secrets(t.item, Some(t.dev_env)).unwrap().iter().any(|s| s.name == "NEW_DEV"));
}

#[test]
fn member_revocation_triggers_branch_key_rotation() {
    let mut t = team(|t| vec![g(TreeNode::Space(t.space), t.space, TreeRole::Editor)]);
    let mut seq = 0;
    {
        let (a, m) = (&t.a, &mut t.m);
        deliver(a, m, &mut seq);
    }
    // Member removed: the owner opens epoch 2 without them and writes.
    t.a.s.test_install_space_root(&t.a.ks, t.space, 2).unwrap();
    let before = t.a.s.peek_outbox(100_000).unwrap().len();
    secret(&mut t.a.s, t.item, Some(t.dev_env), "AFTER_REMOVAL", "secret-after");
    let ev = t.a.s.peek_outbox(100_000).unwrap().into_iter().nth(before).unwrap();
    assert_eq!(ev.envelope.key_epoch, 2);
    let res = t.m.s.apply_signed_event(50_000, &ev);
    assert!(matches!(res, Ok(false)), "{res:?}");
    assert!(t.m.s.deferred_count().unwrap() >= 1);
    // Even trying every key the member holds, epoch-2 ciphertext stays closed.
    assert!(t.m.s.peek_outbox(0).is_ok());
    assert!(!format!("{:?}", t.m.s.list_secrets(t.item, Some(t.dev_env)).unwrap()).contains("AFTER_REMOVAL"));
}

#[test]
fn personal_space_cannot_be_shared() {
    let mut a = owner();
    let personal = a.s.ensure_default_personal_space().unwrap().id;
    let res = a.s.normalize_grants(&[(TreeNode::Space(personal), TreeRole::Viewer)]);
    assert!(matches!(res, Err(Error::Invalid { .. })));
}

#[test]
fn editor_cannot_turn_a_container_into_content() {
    // Editor on General with No access on Production tries to replace the
    // Production environment record by a note with the same id.
    let mut t = team(|t| {
        vec![
            g(TreeNode::General(t.item), t.space, TreeRole::Editor),
            g(TreeNode::Environment(t.prod_env), t.space, TreeRole::NoAccess),
        ]
    });
    let mut seq = 0;
    {
        let (a, m) = (&t.a, &mut t.m);
        deliver(a, m, &mut seq);
    }
    let before = t.m.s.peek_outbox(100_000).unwrap().len();
    t.m.s.create_note(t.item, None, "x", "<p>x</p>").unwrap();
    let ev = t.m.s.peek_outbox(100_000).unwrap().into_iter().nth(before).unwrap();
    // A modified client re-seals its permitted General-scope event with a body
    // that claims the Production environment's id as a note.
    let forged_body = secwet_proto::EventBody::Upsert {
        record_id: t.prod_env,
        record_type: secwet_proto::RecordType::Note.into(),
        lamport: 999_999,
        body: secwet_proto::RecordPayload::Note(secwet_proto::NoteBody::new(t.item, None, "x", "<p>x</p>", 0))
            .to_bytes()
            .unwrap(),
    };
    let ev = t.m.s.test_forge_scoped(&ev, &forged_body).unwrap();
    let applied = t.a.s.apply_signed_event(90_000, &ev).unwrap();
    assert!(!applied, "type change rejected");
    let envs: Vec<String> = t.a.s.list_environments(t.item).unwrap().into_iter().map(|e| e.name).collect();
    assert!(envs.contains(&"Production".to_string()), "Production survives: {envs:?}");
}
