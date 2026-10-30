import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:secwet_mobile/app/app.dart';
import 'package:secwet_mobile/core/secwet_api.dart';
import 'package:secwet_mobile/core/session.dart';
import 'package:secwet_mobile/widgets/controls.dart';

import 'support/fake_bridge.dart';

void main() {
  testWidgets('first launch creates a workspace with the device name', (tester) async {
    Map<String, Object?>? created;
    final handlers = unlockedHandlers();
    handlers['secwet_status'] = (_) => {'status': 'uninitialized'};
    handlers['secwet_create'] = (args) {
      created = args;
      return {'status': 'unlocked', 'secwet_id': 'id'};
    };
    final bridge = FakeBridge(handlers);
    await tester.pumpWidget(SecwetApp(session: SessionController(SecwetApi(bridge))));
    await tester.pumpAndSettle();

    expect(find.text('Welcome to Secwet'), findsOneWidget);
    expect(find.text('Restore from backup'), findsOneWidget);
    expect(find.text('Join with an invite'), findsOneWidget);
    await tester.tap(find.text('Create workspace'));
    await tester.pumpAndSettle();
    expect(created?['device_name'], 'Test Phone');
    expect(find.text('Overview'), findsWidgets);
  });

  testWidgets('join validates the link and email before calling Rust', (tester) async {
    final handlers = unlockedHandlers();
    handlers['secwet_status'] = (_) => {'status': 'uninitialized'};
    final bridge = FakeBridge(handlers);
    await tester.pumpWidget(SecwetApp(session: SessionController(SecwetApi(bridge))));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Join with an invite'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Join'));
    await tester.pumpAndSettle();
    expect(find.text('Paste the invite link you were sent.'), findsOneWidget);
    expect(find.text('Enter the email the invite was sent to.'), findsOneWidget);
    expect(bridge.calls, isNot(contains('invitation_accept')));
  });

  testWidgets('locked: blank screen, the prompt opens by itself and unlocks', (tester) async {
    final handlers = unlockedHandlers(biometric: true);
    handlers['secwet_status'] = (_) => {'status': 'locked', 'secwet_id': 'id'};
    final bridge = FakeBridge(handlers);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    await tester.pumpWidget(SecwetApp(session: SessionController(SecwetApi(bridge))));
    await tester.pumpAndSettle();
    // Rust runs the system prompt inside unlock; no button on the way.
    expect(bridge.calls.where((c) => c == 'secwet_unlock'), hasLength(1));
    expect(find.text('Overview'), findsWidgets);
  });

  testWidgets('a cancelled prompt leaves it blank; a tap prompts again', (tester) async {
    final handlers = unlockedHandlers(biometric: true);
    handlers['secwet_status'] = (_) => {'status': 'locked', 'secwet_id': 'id'};
    var cancel = true;
    handlers['secwet_unlock'] = (_) {
      if (cancel) throw SecwetException('biometric_cancelled', 'Biometric check was cancelled.');
      return null;
    };
    final bridge = FakeBridge(handlers);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    await tester.pumpWidget(SecwetApp(session: SessionController(SecwetApi(bridge))));
    await tester.pumpAndSettle();
    expect(bridge.calls.where((c) => c == 'secwet_unlock'), hasLength(1));
    expect(find.text('Unlock'), findsNothing);
    expect(find.textContaining('cancelled'), findsNothing);
    expect(find.byType(SecwetButton), findsNothing);

    // Closing the system prompt (inactive, then resumed) does not reopen it.
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    await tester.pumpAndSettle();
    expect(bridge.calls.where((c) => c == 'secwet_unlock'), hasLength(1));

    cancel = false;
    await tester.tapAt(const Offset(200, 300));
    await tester.pumpAndSettle();
    expect(bridge.calls.where((c) => c == 'secwet_unlock'), hasLength(2));
    expect(find.text('Overview'), findsWidgets);
  });

  testWidgets('coming back to the app prompts again', (tester) async {
    final handlers = unlockedHandlers();
    handlers['secwet_status'] = (_) => {'status': 'locked', 'secwet_id': 'id'};
    var cancel = true;
    handlers['secwet_unlock'] = (_) {
      if (cancel) throw SecwetException('biometric_cancelled', 'Biometric check was cancelled.');
      return null;
    };
    final bridge = FakeBridge(handlers);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    await tester.pumpWidget(SecwetApp(session: SessionController(SecwetApi(bridge))));
    await tester.pumpAndSettle();
    cancel = false;
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.hidden);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    await tester.pumpAndSettle();
    expect(bridge.calls.where((c) => c == 'secwet_unlock'), hasLength(2));
    expect(find.text('Overview'), findsWidgets);
  });

  testWidgets('no screen lock: locked stops at "Set a screen lock" and continues once set', (tester) async {
    var screenLock = false;
    final handlers = unlockedHandlers(screenLock: false, recovery: true);
    final base = handlers['biometric_status']!;
    handlers['biometric_status'] = (a) => {...(base(a) as Map<String, Object?>), 'device_lock': screenLock};
    handlers['secwet_status'] = (_) => {'status': 'locked', 'secwet_id': 'id'};
    final opened = <String>[];
    tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(const MethodChannel('app.secwet/platform'), (call) async {
      opened.add(call.method);
      return null;
    });
    final bridge = FakeBridge(handlers);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    await tester.pumpWidget(SecwetApp(session: SessionController(SecwetApi(bridge))));
    await tester.pumpAndSettle();
    expect(find.text('Set a screen lock to use Secwet'), findsOneWidget);
    // No unlock path at all: no prompt, no recovery key field.
    expect(bridge.calls, isNot(contains('secwet_unlock')));
    expect(find.byType(EditableText), findsNothing);

    await tester.tap(find.text('Open security settings'));
    await tester.pumpAndSettle();
    expect(opened, contains('openSecuritySettings'));

    // The user sets a passcode and comes back.
    screenLock = true;
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.hidden);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    await tester.pumpAndSettle();
    expect(find.text('Set a screen lock to use Secwet'), findsNothing);
    expect(bridge.calls, contains('secwet_unlock'));
    expect(find.text('Overview'), findsWidgets);
  });

  testWidgets('no screen lock: first launch stops before onboarding', (tester) async {
    final handlers = unlockedHandlers(screenLock: false);
    handlers['secwet_status'] = (_) => {'status': 'uninitialized'};
    final bridge = FakeBridge(handlers);
    await tester.pumpWidget(SecwetApp(session: SessionController(SecwetApi(bridge))));
    await tester.pumpAndSettle();
    expect(find.text('Set a screen lock to use Secwet'), findsOneWidget);
    expect(find.text('Create workspace'), findsNothing);
    expect(bridge.calls, isNot(contains('secwet_create')));
  });
}
