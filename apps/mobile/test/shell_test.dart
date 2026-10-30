import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:secwet_mobile/app/app.dart';
import 'package:secwet_mobile/app/shell.dart';
import 'package:secwet_mobile/core/secwet_api.dart';
import 'package:secwet_mobile/core/session.dart';
import 'package:secwet_mobile/widgets/controls.dart';

import 'support/fake_bridge.dart';

Future<FakeBridge> pumpApp(
  WidgetTester tester,
  Map<String, Object? Function(Map<String, Object?>)> handlers, {
  DateTime Function()? clock,
}) async {
  final bridge = FakeBridge(handlers);
  await tester.pumpWidget(SecwetApp(session: SessionController(SecwetApi(bridge), clock: clock)));
  await tester.pumpAndSettle();
  return bridge;
}

void main() {
  testWidgets('unlocked opens the shell on Overview with three tabs', (tester) async {
    await pumpApp(tester, unlockedHandlers());
    for (final label in ['Groups', 'Overview', 'Settings']) {
      expect(find.text(label), findsWidgets);
    }
    // Overview content is live data from the bridge.
    expect(find.text('Secrets'), findsOneWidget);
    expect(find.text('5'), findsOneWidget);
    final tiles = find.descendant(of: find.byType(BottomTabs), matching: find.byType(IconTile));
    expect([for (final t in tester.widgetList<IconTile>(tiles)) t.selected], [false, true, false]);
  });

  testWidgets('tabs switch and keep the bar', (tester) async {
    await pumpApp(tester, unlockedHandlers());
    await tester.tap(find.text('Groups').last);
    await tester.pumpAndSettle();
    expect(find.text('Payments API'), findsOneWidget);
    await tester.tap(find.text('Settings').last);
    await tester.pumpAndSettle();
    expect(find.text('Security'), findsOneWidget);
  });

  testWidgets('no biometric means no biometric wording anywhere', (tester) async {
    await pumpApp(tester, unlockedHandlers());
    await tester.tap(find.text('Settings').last);
    await tester.pumpAndSettle();
    await tester.tap(find.text('Security'));
    await tester.pumpAndSettle();
    expect(find.textContaining('Face ID'), findsNothing);
    expect(find.text('Lock now'), findsOneWidget);
  });

  testWidgets('locking from Settings shows the blank lock screen', (tester) async {
    final bridge = await pumpApp(tester, unlockedHandlers());
    await tester.tap(find.text('Settings').last);
    await tester.pumpAndSettle();
    await tester.tap(find.text('Security'));
    await tester.pumpAndSettle();
    expect(find.text("Unlock with the phone's passcode"), findsOneWidget);
    // The shell stays in the tree under the cover only while unlocked.
    bridge.handlers['secwet_unlock'] = (_) => throw SecwetException('biometric_cancelled', 'Biometric check was cancelled.');
    await tester.tap(find.text('Lock'));
    await tester.pumpAndSettle();
    expect(bridge.calls, contains('secwet_lock'));
    // Blank: no title, no button, no logo.
    expect(find.text('Unlock'), findsNothing);
    expect(find.byType(SecwetButton), findsNothing);
    expect(find.text('Overview'), findsNothing);
  });

  testWidgets('a short trip away keeps it open; past the auto-lock time it locks', (tester) async {
    var now = DateTime(2026, 10, 29, 9);
    final bridge = await pumpApp(tester, unlockedHandlers(), clock: () => now);
    void away() {
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.hidden);
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.paused);
    }

    void back() {
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.hidden);
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    }

    away();
    await tester.pumpAndSettle();
    // The app-switcher snapshot sees the blank cover, not the content.
    expect(find.text('Secrets').hitTestable(), findsNothing);
    now = now.add(const Duration(minutes: 2));
    back();
    await tester.pumpAndSettle();
    expect(bridge.calls, isNot(contains('secwet_lock')));
    expect(find.text('Secrets'), findsOneWidget);

    away();
    now = now.add(const Duration(minutes: 15));
    back();
    await tester.pumpAndSettle();
    expect(bridge.calls, contains('secwet_lock'));
    // Back in front: the lock screen runs the system prompt by itself.
    expect(bridge.calls, contains('secwet_unlock'));
    expect(find.text('Secrets'), findsOneWidget);
  });
}
