import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:secwet_mobile/screens/overview/overview_screen.dart';
import 'package:secwet_mobile/widgets/controls.dart';

import 'support/fake_store.dart';

FakeStore seeded() {
  final store = FakeStore();
  final g = store.addGroup('Projects');
  final i = store.addItem(g['id'] as String, 'Payments API');
  store.addSecret(i['id'] as String, 'STRIPE_SECRET_KEY', 'sk_live_12345');
  store.addNote(i['id'] as String, 'Runbook', '<p>Restart the API</p>');
  return store;
}

void main() {
  testWidgets('counts, recent secrets, recent notes, quick actions, checklist', (tester) async {
    await pumpScreen(tester, seeded(), const OverviewScreen());
    expect(find.text('Overview'), findsOneWidget);
    expect(find.text('Secrets'), findsOneWidget);
    expect(find.text('Recently changed secrets'), findsOneWidget);
    expect(find.text('STRIPE_SECRET_KEY'), findsOneWidget);
    expect(find.text('Payments API · General'), findsOneWidget);
    expect(find.text('Recent notes'), findsOneWidget);
    expect(find.text('Runbook'), findsOneWidget);
    await tester.scrollUntilVisible(find.text('Setup and safety'), 200, scrollable: find.byType(Scrollable).first);
    expect(find.text('Quick actions'), findsOneWidget);
    expect(find.text('New entry'), findsOneWidget);
    expect(find.text('Backup key'), findsOneWidget);
    expect(find.text('Initialized on this device'), findsOneWidget);
    expect(find.text('Create a recovery key'), findsOneWidget);
    // Free plan: pairing step points at the plans.
    expect(find.text('Needs Pro. Works the same on local device.'), findsOneWidget);
    expect(find.text('2 steps left'), findsOneWidget);
  });

  testWidgets('the phone has no command-line step', (tester) async {
    await pumpScreen(tester, seeded(), const OverviewScreen());
    await tester.scrollUntilVisible(find.text('Create a recovery key'), 200, scrollable: find.byType(Scrollable).first);
    expect(find.text('Connect the command line'), findsNothing);
    expect(find.text('Mark as read'), findsNothing);
    expect(find.text('2 steps left'), findsOneWidget);
  });

  testWidgets('customize hides widgets and KPIs and renames Home', (tester) async {
    final store = seeded();
    await pumpScreen(tester, store, const OverviewScreen());
    await tester.tap(byLabel('Customize'));
    await tester.pumpAndSettle();
    expect(find.text('Customize dashboard'), findsOneWidget);
    await tester.enterText(find.byType(EditableText).first, 'Command Center');
    await tester.tap(find.text('Recent Notes'));
    await tester.tap(find.text('Assets').last);
    await tester.tap(find.widgetWithText(SecwetButton, 'Save changes'));
    await tester.pumpAndSettle();
    expect(store.dashboard['home_label'], 'Command Center');
    expect(store.dashboard['widgets'], ['recent_secrets', 'quick_actions', 'checklist']);
    expect(store.dashboard['visible_kpis'], ['secrets', 'notes', 'devices']);
    expect(find.text('Command Center'), findsOneWidget);
    expect(find.text('Recent notes'), findsNothing);
  });

  testWidgets('viewer sees no New or New entry', (tester) async {
    final store = seeded()
      ..owner = false
      ..grants = [
        {'kind': 'space', 'id': 's1', 'role': 'viewer', 'label': 'Personal'},
      ];
    await pumpScreen(tester, store, const OverviewScreen());
    expect(find.widgetWithText(SecwetButton, 'New'), findsNothing);
    expect(find.text('New entry'), findsNothing);
    // Members never pair devices.
    expect(find.text('Pair device'), findsNothing);
  });
}

