//! Empirical integration tests for Secwet Spaces Architecture (Pattern A).
//!
//! Validates:
//! 1. Default "Personal" space is automatically seeded on `Secwet::create`.
//! 2. Default "Projects" label automatically belongs to the "Personal" space.
//! 3. Spaces CRUD (create, rename, list, reorder).
//! 4. Validation (length, characters, case-insensitive duplicate prevention).
//! 5. Group creation inside specific spaces and space filtering.
//! 6. Group relocation (`move_label_to_space`).
//! 7. Safe space deletion (reassigns active groups to Personal space, blocks deleting Personal).
//! 8. Automatic retrofit of legacy unassigned groups into Personal space on `unlock`.

use secwet_core::keys::MemoryStore;
use secwet_core::{Error, Secwet};
use tempfile::tempdir;
use uuid::Uuid;

fn create_test_secwet() -> (tempfile::TempDir, Secwet, MemoryStore, Uuid, Uuid) {
    let dir = tempdir().expect("tempdir");
    let keystore = MemoryStore::new();
    let secwet = Secwet::create(dir.path(), "test-device", &keystore).expect("secwet create");

    let spaces = secwet.list_spaces().expect("list spaces");
    assert_eq!(spaces.len(), 1, "Must have exactly 1 default space on creation");
    assert_eq!(spaces[0].name, "Personal");
    assert!(spaces[0].is_default);

    let labels = secwet.list_labels().expect("list labels");
    assert_eq!(labels.len(), 1, "Must have default Projects group");
    assert_eq!(labels[0].name, "Projects");
    assert_eq!(
        labels[0].space_id,
        Some(spaces[0].id),
        "Projects group must belong to Personal space"
    );

    let personal_id = spaces[0].id;
    let projects_id = labels[0].id;
    (dir, secwet, keystore, personal_id, projects_id)
}

#[test]
fn test_default_personal_space_auto_created_on_init() {
    let (_dir, secwet, _keystore, personal_id, projects_id) = create_test_secwet();

    let personal = secwet.get_space(personal_id).expect("get personal space");
    assert_eq!(personal.name, "Personal");
    assert_eq!(personal.icon.as_deref(), Some("user"));
    assert!(personal.is_default);
    assert_eq!(personal.groups_count, 1, "Personal space contains Projects group");

    let labels = secwet.list_labels().expect("list labels");
    assert_eq!(labels[0].id, projects_id);
    assert_eq!(labels[0].space_id, Some(personal_id));
}

#[test]
fn test_spaces_crud_and_validation() {
    let (_dir, mut secwet, _keystore, _personal_id, _projects_id) = create_test_secwet();

    // 1. Create custom spaces
    let work = secwet
        .create_space("Work", Some("briefcase".to_string()))
        .expect("create work space");
    assert_eq!(work.name, "Work");
    assert_eq!(work.icon.as_deref(), Some("briefcase"));
    assert!(!work.is_default);
    assert_eq!(work.groups_count, 0);

    let client = secwet
        .create_space("Client Alpha", Some("globe".to_string()))
        .expect("create client space");
    assert_eq!(client.name, "Client Alpha");

    // 2. Duplicate validation (case-insensitive)
    let dup_err = secwet.create_space("  work  ", None).unwrap_err();
    match dup_err {
        Error::Duplicate { field } => assert_eq!(field, "name"),
        other => panic!("Expected Duplicate error, got: {:?}", other),
    }

    // 3. Name validation
    let empty_err = secwet.create_space("   ", None).unwrap_err();
    assert!(matches!(empty_err, Error::Invalid { field: "name", .. }));

    let long_name = "A".repeat(65);
    let long_err = secwet.create_space(&long_name, None).unwrap_err();
    assert!(matches!(long_err, Error::Invalid { field: "name", .. }));

    // 4. List spaces
    let spaces = secwet.list_spaces().expect("list spaces");
    assert_eq!(spaces.len(), 3);
    assert_eq!(spaces[0].name, "Personal");
    assert_eq!(spaces[1].name, "Work");
    assert_eq!(spaces[2].name, "Client Alpha");

    // 5. Rename space
    let renamed = secwet
        .rename_space(work.id, "Professional", Some("building".to_string()))
        .expect("rename space");
    assert_eq!(renamed.name, "Professional");
    assert_eq!(renamed.icon.as_deref(), Some("building"));

    // 6. Reorder spaces
    secwet
        .reorder_spaces(&[client.id, work.id, spaces[0].id])
        .expect("reorder spaces");
    let reordered = secwet.list_spaces().expect("list reordered");
    assert_eq!(reordered[0].id, client.id);
    assert_eq!(reordered[1].id, work.id);
    assert_eq!(reordered[2].id, spaces[0].id);
}

#[test]
fn test_create_label_in_space_and_filtering() {
    let (_dir, mut secwet, _keystore, personal_id, _projects_id) = create_test_secwet();

    let work_space = secwet
        .create_space("Work", Some("briefcase".to_string()))
        .expect("create work space");

    // Create groups in Work space
    let backend = secwet
        .create_label_in_space("Backend Services", Some("server".to_string()), Some(work_space.id))
        .expect("create backend in work");
    assert_eq!(backend.space_id, Some(work_space.id));

    let frontend = secwet
        .create_label_in_space("Web Apps", Some("layout".to_string()), Some(work_space.id))
        .expect("create frontend in work");
    assert_eq!(frontend.space_id, Some(work_space.id));

    // Create group in Personal space
    let home = secwet
        .create_label_in_space("Smart Home", Some("home".to_string()), None)
        .expect("create smart home in personal default");
    assert_eq!(home.space_id, Some(personal_id));

    // Filter by space
    let work_labels = secwet.list_labels_by_space(work_space.id).expect("list work labels");
    assert_eq!(work_labels.len(), 2);
    let work_names: Vec<&str> = work_labels.iter().map(|l| l.name.as_str()).collect();
    assert!(work_names.contains(&"Backend Services"));
    assert!(work_names.contains(&"Web Apps"));

    let personal_labels = secwet.list_labels_by_space(personal_id).expect("list personal labels");
    assert_eq!(personal_labels.len(), 2); // Projects + Smart Home
    let personal_names: Vec<&str> = personal_labels.iter().map(|l| l.name.as_str()).collect();
    assert!(personal_names.contains(&"Projects"));
    assert!(personal_names.contains(&"Smart Home"));

    // Check space groups_count reflects correctly
    let work_view = secwet.get_space(work_space.id).expect("get work space");
    assert_eq!(work_view.groups_count, 2);

    let personal_view = secwet.get_space(personal_id).expect("get personal space");
    assert_eq!(personal_view.groups_count, 2);

    // Relocate Smart Home from Personal to Work
    secwet.move_label_to_space(home.id, work_space.id).expect("move smart home to work");
    let updated_work = secwet.list_labels_by_space(work_space.id).expect("list work after move");
    assert_eq!(updated_work.len(), 3);
}

#[test]
fn test_delete_space_reassigns_groups_to_personal_safely() {
    let (_dir, mut secwet, _keystore, personal_id, _projects_id) = create_test_secwet();

    // 1. Attempting to delete Personal space must fail
    let del_personal_err = secwet.delete_space(personal_id).unwrap_err();
    assert!(matches!(del_personal_err, Error::Invalid { field: "space", .. }));

    // 2. Create custom space and populate with groups
    let team_space = secwet
        .create_space("Team Alpha", None)
        .expect("create team space");
    let g1 = secwet
        .create_label_in_space("Core APIs", None, Some(team_space.id))
        .expect("create g1");
    let g2 = secwet
        .create_label_in_space("Mobile SDK", None, Some(team_space.id))
        .expect("create g2");

    assert_eq!(secwet.get_space(team_space.id).unwrap().groups_count, 2);

    // 3. Delete Team Alpha space
    secwet.delete_space(team_space.id).expect("delete team space");

    // Space must now be deleted (not found)
    assert!(secwet.get_space(team_space.id).is_err());

    // Both groups g1 and g2 must now safely belong to Personal space
    let personal_groups = secwet.list_labels_by_space(personal_id).expect("list personal");
    let personal_group_ids: Vec<Uuid> = personal_groups.iter().map(|g| g.id).collect();
    assert!(personal_group_ids.contains(&g1.id));
    assert!(personal_group_ids.contains(&g2.id));
}

#[test]
fn test_unlock_auto_retrofits_unassigned_labels() {
    let dir = tempdir().expect("tempdir");
    let keystore = MemoryStore::new();
    let db_path;

    // Phase 1: create secwet and add labels
    let personal_id;
    {
        let mut secwet = Secwet::create(dir.path(), "test-device", &keystore).expect("create secwet");
        personal_id = secwet.list_spaces().unwrap()[0].id;
        db_path = dir
            .path()
            .join("secwet")
            .join(secwet.secwet_id().to_string())
            .join("secwet.sqlite3");

        secwet.create_label("Extra Group 1", None).unwrap();
        secwet.create_label("Extra Group 2", None).unwrap();
    }

    // Phase 2: simulate unassigned groups by clearing space_id in SQLite
    {
        let conn = secwet_core::open_connection(&db_path).unwrap();
        conn.execute("UPDATE labels SET space_id = NULL", []).unwrap();
    }

    // Phase 3: unlock secwet and verify ensure_default_personal_space retrofitted all labels
    {
        let secwet = Secwet::unlock(dir.path(), &keystore).expect("unlock secwet");
        let spaces = secwet.list_spaces().expect("list spaces");
        assert_eq!(spaces.len(), 1);
        assert_eq!(spaces[0].id, personal_id);

        let labels = secwet.list_labels().expect("list labels");
        assert_eq!(labels.len(), 3); // Projects, Extra Group 1, Extra Group 2
        for l in labels {
            assert_eq!(
                l.space_id,
                Some(personal_id),
                "Label '{}' must be retrofitted to Personal space",
                l.name
            );
        }
    }
}
