// End to end against the real Rust core over dart:ffi (no fakes): opens or
// creates the Secwet on the device, then through the UI creates a secret in
// a fresh entry, reveals it, copies it, and deletes it, checking the core's
// state after each step. Run on a simulator or device:
//   flutter test integration_test/secret_flow_test.dart -d <device>
import 'package:flutter/widgets.dart' hide LockState;
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:secwet_mobile/app/app.dart';
import 'package:secwet_mobile/core/bridge.dart';
import 'package:secwet_mobile/core/secwet_api.dart';
import 'package:secwet_mobile/core/session.dart';
import 'package:secwet_mobile/widgets/controls.dart';
import 'package:secwet_mobile/widgets/overlays.dart';

Finder byLabel(String label) => find.byWidgetPredicate((w) => w is Tappable && w.label == label);

Finder dialogFields() => find.descendant(of: find.byType(SecwetDialog), matching: find.byType(EditableText));

/// Pumps until [finder] shows up; FFI calls run on background isolates, so
/// fixed pumps are not enough.
Future<void> waitFor(WidgetTester tester, Finder finder, {Duration timeout = const Duration(seconds: 20)}) async {
  final end = DateTime.now().add(timeout);
  while (DateTime.now().isBefore(end)) {
    await tester.pump(const Duration(milliseconds: 100));
    if (finder.evaluate().isNotEmpty) return;
  }
  throw TestFailure('Timed out waiting for $finder');
}

Future<void> waitGone(WidgetTester tester, Finder finder) async {
  final end = DateTime.now().add(const Duration(seconds: 20));
  while (DateTime.now().isBefore(end)) {
    await tester.pump(const Duration(milliseconds: 100));
    if (finder.evaluate().isEmpty) return;
  }
  throw TestFailure('Timed out waiting for $finder to go away');
}

Future<void> waitUntil(WidgetTester tester, Future<bool> Function() test, String what) async {
  final end = DateTime.now().add(const Duration(seconds: 20));
  while (DateTime.now().isBefore(end)) {
    await tester.pump(const Duration(milliseconds: 100));
    if (await test()) return;
  }
  throw TestFailure('Timed out waiting until $what');
}

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('create, reveal, copy and delete a secret through the real core', (tester) async {
    final api = SecwetApi(NativeSecwetBridge());

    // Open the store on this device, creating it on first run.
    final status = await api.status();
    if (status.state == LockState.uninitialized) {
      await api.create(deviceName: 'Integration test');
    } else if (status.state == LockState.locked) {
      await api.unlock();
    }

    // A fresh entry so the test never touches existing data.
    final stamp = DateTime.now().millisecondsSinceEpoch;
    final spaces = await api.spaces();
    final personal = spaces.firstWhere((s) => s.isDefault, orElse: () => spaces.first);
    final group = await api.createGroup('IT group $stamp', spaceId: personal.id);
    final item = await api.createItem(group.id, 'IT entry $stamp');
    const name = 'IT_SECRET_KEY';
    const value = 'it-value-0a1b2c3d';

    try {
      final session = SessionController(api);
      await tester.pumpWidget(SecwetApp(session: session));
      await waitFor(tester, find.text('Groups'));

      // Groups tab: the new entry is listed under its group.
      await tester.tap(find.text('Groups').last);
      await waitFor(tester, find.text('IT entry $stamp'));
      await tester.scrollUntilVisible(find.text('IT entry $stamp'), 120, scrollable: find.byType(Scrollable).first);
      await tester.tap(find.text('IT entry $stamp'));
      await waitFor(tester, find.text('No secrets yet'));

      // Add the secret through the dialog.
      await tester.tap(find.widgetWithText(SecwetButton, 'Add secret'));
      await waitFor(tester, dialogFields());
      await tester.enterText(dialogFields().at(0), name);
      await tester.enterText(dialogFields().at(1), value);
      await tester.pump();
      await tester.tap(find.text('Save secret'));
      await waitGone(tester, find.byType(SecwetDialog));
      await waitFor(tester, find.text(name));
      final created = (await api.secrets(itemId: item.id)).single;
      expect(created.name, name);
      expect(created.valueTail, value.substring(value.length - 4));
      // Masked until revealed.
      expect(find.text(value), findsNothing);
      expect(find.text('••••••••••••${created.valueTail}'), findsOneWidget);

      // Reveal shows the value from the core; hide drops it.
      await tester.tap(byLabel('Reveal $name'));
      await waitFor(tester, find.text(value));
      await tester.tap(byLabel('Hide $name'));
      await tester.pumpAndSettle();
      expect(find.text(value), findsNothing);

      // Copy goes to the native clipboard (auto-cleared after 30 seconds).
      await tester.tap(byLabel('Copy $name value'));
      await waitFor(tester, byLabel('Value copied'));

      // Delete it.
      await tester.tap(byLabel('Actions for $name'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Delete secret'));
      await waitFor(tester, find.text('Delete "$name"?'));
      await tester.tap(find.widgetWithText(SecwetButton, 'Delete secret'));
      await waitFor(tester, find.text('No secrets yet'));
      await waitUntil(tester, () async => (await api.secrets(itemId: item.id)).isEmpty, 'the secret is gone');
    } finally {
      await api.deleteGroup(group.id);
    }
  });
}
