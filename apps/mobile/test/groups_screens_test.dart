import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:secwet_mobile/screens/groups/group_screen.dart';
import 'package:secwet_mobile/screens/groups/groups_screen.dart';
import 'package:secwet_mobile/screens/groups/item_screen.dart';
import 'package:secwet_mobile/widgets/controls.dart';
import 'package:secwet_mobile/widgets/overlays.dart';

import 'support/fake_store.dart';

FakeStore seeded() {
  final store = FakeStore();
  final g = store.addGroup('Projects');
  final i = store.addItem(g['id'] as String, 'Payments API', description: 'Stripe and billing microservices');
  store.addItem(g['id'] as String, 'Frontend App');
  store.addEnvironment(i['id'] as String, 'Production');
  store.addSecret(i['id'] as String, 'STRIPE_SECRET_KEY', 'sk_live_12345');
  store.addGroup('Work things', space: 's2');
  return store;
}

/// Text fields of the open dialog (the screen behind keeps its own fields).
Finder dialogFields() => find.descendant(of: find.byType(SecwetDialog), matching: find.byType(EditableText));

void main() {
  group('Groups tab', () {
    testWidgets('shows the active space, its groups and entries, and New', (tester) async {
      await pumpScreen(tester, seeded(), const GroupsScreen());
      expect(find.text('Personal'), findsOneWidget);
      expect(find.text('Projects'), findsOneWidget);
      expect(find.text('Payments API'), findsOneWidget);
      expect(find.text('Frontend App'), findsOneWidget);
      expect(find.text('Work things'), findsNothing);
      expect(find.text('New'), findsOneWidget);
    });

    testWidgets('switching to Work and Global changes the groups', (tester) async {
      await pumpScreen(tester, seeded(), const GroupsScreen());
      await tester.tap(find.text('Personal'));
      await tester.pumpAndSettle();
      expect(find.text('Spaces'), findsOneWidget);
      await tester.tap(find.text('Work'));
      await tester.pumpAndSettle();
      expect(find.text('Work things'), findsOneWidget);
      expect(find.text('Projects'), findsNothing);
      await tester.tap(find.text('Work'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Global'));
      await tester.pumpAndSettle();
      expect(find.text('Work things'), findsOneWidget);
      expect(find.text('Projects'), findsOneWidget);
    });

    testWidgets('new group checks duplicates and creates', (tester) async {
      final store = seeded();
      await pumpScreen(tester, store, const GroupsScreen());
      await tester.tap(find.text('New'));
      await tester.pumpAndSettle();
      await tester.enterText(dialogFields().first, 'projects');
      await tester.pumpAndSettle();
      await tester.tap(find.text('Create Group'));
      await tester.pumpAndSettle();
      expect(find.text('A group called "projects" already exists in this space.'), findsOneWidget);
      await tester.enterText(dialogFields().first, 'Infrastructure');
      await tester.pumpAndSettle();
      await tester.tap(find.text('Create Group'));
      await tester.pumpAndSettle();
      expect(store.groups.any((g) => g['name'] == 'Infrastructure'), isTrue);
      // The new group opens.
      expect(find.text('No entries yet'), findsOneWidget);
    });

    testWidgets('member without admin sees no create controls', (tester) async {
      final store = seeded()
        ..owner = false
        ..grants = [
          {'kind': 'space', 'id': 's1', 'role': 'viewer', 'label': 'Personal'},
        ];
      await pumpScreen(tester, store, const GroupsScreen());
      expect(find.text('Payments API'), findsOneWidget);
      expect(find.text('New'), findsNothing);
      expect(byLabel('Add to Projects'), findsNothing);
    });

    testWidgets('unlinked device shows the read-only notice', (tester) async {
      final store = seeded()..linkState = 'unlinked';
      await pumpScreen(tester, store, const GroupsScreen());
      expect(find.text('Unlinked'), findsOneWidget);
      expect(find.text('New'), findsNothing);
    });
  });

  group('Group screen', () {
    testWidgets('lists entries with pills and filters by search', (tester) async {
      final store = seeded();
      await pumpScreen(tester, store, GroupScreen(groupId: store.groups.first['id'] as String));
      expect(find.text('Stripe and billing microservices'), findsOneWidget);
      expect(find.text('1 env'), findsOneWidget);
      expect(find.text('1 secret'), findsOneWidget);
      expect(find.text('0 secrets'), findsOneWidget);
      await tester.enterText(find.byType(EditableText), 'front');
      await tester.pumpAndSettle();
      expect(find.text('Payments API'), findsNothing);
      expect(find.text('Frontend App'), findsOneWidget);
    });

    testWidgets('deleting a group with entries needs its typed name', (tester) async {
      final store = seeded();
      await pumpScreen(tester, store, GroupScreen(groupId: store.groups.first['id'] as String));
      await tester.tap(byLabel('Actions'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Delete'));
      await tester.pumpAndSettle();
      final confirm = find.widgetWithText(SecwetButton, 'Delete');
      expect(tester.widget<SecwetButton>(confirm).onPressed, isNull);
      await tester.enterText(dialogFields(), 'Projects');
      await tester.pumpAndSettle();
      await tester.tap(confirm);
      await tester.pumpAndSettle();
      expect(store.groups.where((g) => g['name'] == 'Projects'), isEmpty);
    });

    testWidgets('rename refuses a duplicate name', (tester) async {
      final store = seeded();
      store.addGroup('Other');
      await pumpScreen(tester, store, GroupScreen(groupId: store.groups.first['id'] as String));
      await tester.tap(byLabel('Actions'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Rename'));
      await tester.pumpAndSettle();
      await tester.enterText(dialogFields(), 'other');
      await tester.tap(find.widgetWithText(SecwetButton, 'Rename'));
      await tester.pumpAndSettle();
      expect(find.text('A category called "other" already exists.'), findsOneWidget);
    });

    testWidgets('move down reorders inside the space', (tester) async {
      final store = seeded();
      store.addGroup('Second');
      await pumpScreen(tester, store, GroupScreen(groupId: store.groups.first['id'] as String));
      await tester.tap(byLabel('Actions'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Move down'));
      await tester.pumpAndSettle();
      final personal = [for (final g in store.groups) if (g['space_id'] == 's1') g['name']];
      expect(personal, ['Second', 'Projects']);
    });
  });

  group('Item screen', () {
    testWidgets('breadcrumb leads back to the group, then to Groups', (tester) async {
      await pumpScreen(tester, seeded(), const GroupsScreen());
      await tester.tap(find.text('Payments API'));
      await tester.pumpAndSettle();
      expect(find.byType(ItemScreen), findsOneWidget);
      // "Projects · Payments API"
      expect(find.text('Projects'), findsOneWidget);
      await tester.tap(find.text('Projects'));
      await tester.pumpAndSettle();
      expect(find.byType(ItemScreen), findsNothing);
      expect(find.byType(GroupScreen), findsOneWidget);
      await tester.tap(find.text('Groups'));
      await tester.pumpAndSettle();
      expect(find.byType(GroupScreen), findsNothing);
      expect(find.byType(GroupsScreen), findsOneWidget);
    });

    testWidgets('environments, content tabs with counts, masked secret', (tester) async {
      final store = seeded();
      final item = store.items.first['id'] as String;
      await pumpScreen(tester, store, ItemScreen(itemId: item));
      expect(find.text('General'), findsOneWidget);
      expect(find.text('Production'), findsOneWidget);
      expect(find.text('Secrets'), findsOneWidget);
      expect(find.text('Assets'), findsOneWidget);
      expect(find.text('Notes'), findsOneWidget);
      expect(find.text('STRIPE_SECRET_KEY'), findsOneWidget);
      expect(find.text('••••••••••••2345'), findsOneWidget);
      expect(find.text('sk_live_12345'), findsNothing);
    });

    testWidgets('reveal shows and hides the value; copy goes through the native clipboard', (tester) async {
      final store = seeded();
      await pumpScreen(tester, store, ItemScreen(itemId: store.items.first['id'] as String));
      await tester.tap(byLabel('Reveal STRIPE_SECRET_KEY'));
      await tester.pumpAndSettle();
      expect(find.text('sk_live_12345'), findsOneWidget);
      await tester.tap(byLabel('Hide STRIPE_SECRET_KEY'));
      await tester.pumpAndSettle();
      expect(find.text('sk_live_12345'), findsNothing);
      await tester.tap(byLabel('Copy STRIPE_SECRET_KEY value'));
      await tester.pump();
      expect(store.copied, ['sk_live_12345']);
      await tester.pump(const Duration(seconds: 4));
    });

    testWidgets('add secret validates names and saves to the open environment', (tester) async {
      final store = seeded();
      await pumpScreen(tester, store, ItemScreen(itemId: store.items.first['id'] as String));
      await tester.tap(find.text('Production'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Add secret'));
      await tester.pumpAndSettle();
      final fields = dialogFields();
      await tester.enterText(fields.at(0), '1BAD');
      await tester.enterText(fields.at(1), 'v');
      await tester.tap(find.text('Save secret'));
      await tester.pumpAndSettle();
      expect(find.text('Use letters, numbers, underscores, dots or dashes.'), findsOneWidget);
      await tester.enterText(fields.at(0), 'DB_URL');
      await tester.enterText(fields.at(1), 'postgres://x');
      await tester.tap(find.text('Save secret'));
      await tester.pumpAndSettle();
      final created = store.secrets.firstWhere((s) => s['name'] == 'DB_URL');
      expect(created['environment_id'], store.environments.first['id']);
      expect(find.text('DB_URL'), findsOneWidget);
    });

    testWidgets('pasting an env block fills several entries', (tester) async {
      final store = seeded();
      await pumpScreen(tester, store, ItemScreen(itemId: store.items.first['id'] as String));
      await tester.tap(byLabel('Add secret'));
      await tester.pumpAndSettle();
      await tester.enterText(dialogFields().at(1), 'A_KEY=one\nB_KEY="two"');
      await tester.pumpAndSettle();
      expect(find.text('Detected 2 secrets from clipboard'), findsOneWidget);
      expect(find.text('Save 2 secrets'), findsOneWidget);
      await tester.tap(find.text('Save 2 secrets'));
      await tester.pumpAndSettle();
      expect(store.values.values, containsAll(['one', 'two']));
      await tester.pump(const Duration(seconds: 4));
    });

    testWidgets('viewer can reveal but not add, edit or delete', (tester) async {
      final store = seeded()
        ..owner = false
        ..grants = [
          {'kind': 'space', 'id': 's1', 'role': 'viewer', 'label': 'Personal'},
        ];
      await pumpScreen(tester, store, ItemScreen(itemId: store.items.first['id'] as String));
      expect(byLabel('Add secret'), findsNothing);
      expect(byLabel('Actions'), findsNothing);
      await tester.tap(byLabel('Actions for STRIPE_SECRET_KEY'));
      await tester.pumpAndSettle();
      expect(find.text('Usage info & command'), findsOneWidget);
      expect(find.text('Edit secret'), findsNothing);
      expect(find.text('Delete secret'), findsNothing);
    });

    testWidgets('delete secret asks first', (tester) async {
      final store = seeded();
      await pumpScreen(tester, store, ItemScreen(itemId: store.items.first['id'] as String));
      await tester.tap(byLabel('Actions for STRIPE_SECRET_KEY'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Delete secret'));
      await tester.pumpAndSettle();
      expect(find.text('Delete "STRIPE_SECRET_KEY"?'), findsOneWidget);
      await tester.tap(find.widgetWithText(SecwetButton, 'Delete secret'));
      await tester.pumpAndSettle();
      expect(store.secrets, isEmpty);
      expect(find.text('No secrets yet'), findsOneWidget);
    });

    testWidgets('add environment refuses a duplicate and opens the new one', (tester) async {
      final store = seeded();
      await pumpScreen(tester, store, ItemScreen(itemId: store.items.first['id'] as String));
      await tester.tap(byLabel('Actions'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Add environment'));
      await tester.pumpAndSettle();
      await tester.enterText(dialogFields(), 'production');
      await tester.tap(find.widgetWithText(SecwetButton, 'Add environment'));
      await tester.pumpAndSettle();
      expect(find.text('An environment called "production" already exists.'), findsOneWidget);
      await tester.enterText(dialogFields(), 'Staging');
      await tester.tap(find.widgetWithText(SecwetButton, 'Add environment'));
      await tester.pumpAndSettle();
      expect(find.text('Staging'), findsOneWidget);
      expect(store.environments.length, 2);
    });

    testWidgets('notes tab opens the editor and creates a formatted note', (tester) async {
      final store = seeded();
      await pumpScreen(tester, store, ItemScreen(itemId: store.items.first['id'] as String));
      await tester.tap(find.text('Notes'));
      await tester.pumpAndSettle();
      expect(find.text('No rich-text notes yet'), findsOneWidget);
      await tester.tap(find.text('New note'));
      await tester.pumpAndSettle();
      await tester.enterText(find.byType(EditableText).at(0), 'Runbook');
      await tester.enterText(find.byType(EditableText).at(1), 'Restart the API');
      await tester.pumpAndSettle();
      await tester.tap(byLabel('Heading 1'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Create note'));
      await tester.pumpAndSettle();
      expect(store.notes.single['content'], '<h1>Restart the API</h1>');
      expect(find.text('Runbook'), findsOneWidget);
    });

    testWidgets('assets tab shows upload and the empty state', (tester) async {
      final store = seeded();
      await pumpScreen(tester, store, ItemScreen(itemId: store.items.first['id'] as String));
      await tester.tap(find.text('Assets'));
      await tester.pumpAndSettle();
      expect(find.text('Tap to upload an asset'), findsOneWidget);
      expect(find.text('No assets yet'), findsOneWidget);
    });
  });
}
