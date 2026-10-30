import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:secwet_mobile/core/bridge.dart';
import 'package:secwet_mobile/screens/settings/settings_screen.dart';
import 'package:secwet_mobile/screens/sharing/sharing_screen.dart';

import 'support/fake_store.dart';
import 'support/settings_fake.dart';

/// The test font draws every glyph a full em wide (about 1.8x the system
/// font), so two-button dialog rows that fit on a phone overflow at 390 pt.
/// Lay those screens out at 500 pt after [pumpScreen] to compensate.
Future<void> widen(WidgetTester tester) async {
  tester.view.physicalSize = const Size(1500, 2796);
  await tester.pumpAndSettle();
}

/// Answers `busy` to the first settings read, like a sync holding the store.
class BusyOnceFake extends SettingsFake {
  int busyAnswers = 0;

  @override
  Map<String, Object? Function(Map<String, Object?>)> handlers() {
    final h = super.handlers();
    final settings = h['settings_get']!;
    return {
      ...h,
      'settings_get': (a) {
        if (busyAnswers == 0) {
          busyAnswers++;
          throw SecwetException('busy', 'Secwet is syncing. Try again in a moment.');
        }
        return settings(a);
      },
    };
  }
}

void main() {
  group('Settings', () {
    testWidgets('shows the six desktop tabs without CLI', (tester) async {
      await pumpScreen(tester, SettingsFake(), const SettingsScreen());
      for (final t in ['General', 'Security', 'Devices', 'Recovery', 'Sync', 'Plan']) {
        expect(find.text(t), findsWidgets);
      }
      expect(find.text('CLI'), findsNothing);
      expect(find.text('Appearance'), findsWidgets);
      expect(find.text('Device name'), findsOneWidget);
      expect(find.text('Test Phone'), findsOneWidget);
    });

    testWidgets('devices show This device, Active and the remote wipe choice', (tester) async {
      final store = SettingsFake();
      final bridge = await pumpScreen(tester, store, const SettingsScreen(initialTab: SettingsTab.devices));
      await widen(tester);
      expect(find.text('This device'), findsOneWidget);
      expect(find.text('Active'), findsOneWidget);
      expect(find.text('Studio Mac'), findsOneWidget);
      expect(find.text('Pair a device'), findsOneWidget);

      await tester.tap(find.text('Revoke'));
      await tester.pumpAndSettle();
      expect(find.text('Revoke Studio Mac?'), findsOneWidget);
      // Erase is the default; switch to keeping a read-only copy.
      await tester.tap(find.text('Revoke and keep a read-only copy'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Revoke and keep copy'));
      await tester.pumpAndSettle();

      expect(bridge.calls, contains('device_revoke'));
      expect(store.revokes.single, {'device_id': 'd2', 'wipe': false});
      expect(find.text('Revoked Devices'), findsOneWidget);
      expect(find.text('Revoked'), findsOneWidget);
      // A revoke recommends rotating the key.
      expect(find.textContaining('Rotate'), findsWidgets);
    });

    testWidgets('revoke with erase asks for a remote wipe', (tester) async {
      final store = SettingsFake();
      await pumpScreen(tester, store, const SettingsScreen(initialTab: SettingsTab.devices));
      await widen(tester);
      await tester.tap(find.text('Revoke'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Revoke and erase').last);
      await tester.pumpAndSettle();
      expect(store.revokes.single['wipe'], true);
      expect(find.textContaining('erases its keys and local data'), findsOneWidget);
    });

    testWidgets('member devices cannot pair or revoke', (tester) async {
      await pumpScreen(tester, SettingsFake(owner: false), const SettingsScreen(initialTab: SettingsTab.devices));
      expect(find.text('Pair a device'), findsNothing);
      expect(find.text('Revoke'), findsNothing);
      expect(find.text('Member'), findsOneWidget);
    });

    testWidgets('Free asks for Pro before pairing', (tester) async {
      await pumpScreen(tester, SettingsFake(pro: false), const SettingsScreen(initialTab: SettingsTab.devices));
      await tester.tap(find.text('Pair a device'));
      await tester.pumpAndSettle();
      expect(find.textContaining('Pairing a second device requires Pro'), findsOneWidget);
    });

    testWidgets('unlinked is read-only everywhere', (tester) async {
      await pumpScreen(tester, SettingsFake(linkState: 'unlinked'), const SettingsScreen(initialTab: SettingsTab.devices));
      expect(find.text('Read-only'), findsWidgets);
      expect(find.text('Pair a device'), findsNothing);
    });

    testWidgets('recovery key is created and shown once', (tester) async {
      final store = SettingsFake();
      await pumpScreen(tester, store, const SettingsScreen(initialTab: SettingsTab.recovery));
      expect(find.text('Not created'), findsOneWidget);
      await tester.tap(find.text('Create'));
      await tester.pumpAndSettle();
      // Shown as whole groups so it never breaks inside one.
      expect(find.bySemanticsLabel('ABCD-EFGH-IJKL-MNOP'), findsOneWidget);
      expect(find.text('ABCD-'), findsOneWidget);
      expect(find.text('MNOP'), findsOneWidget);
      expect(store.recoveryCreated, isTrue);
    });

    testWidgets('sync shows the relay, the outbox and syncs now', (tester) async {
      final store = SettingsFake();
      final bridge = await pumpScreen(tester, store, const SettingsScreen(initialTab: SettingsTab.sync));
      expect(find.text('Connected'), findsOneWidget);
      expect(find.text('Waiting to sync'), findsOneWidget);
      await tester.tap(find.text('Sync now').last);
      await tester.pumpAndSettle();
      expect(bridge.calls, contains('sync_now'));
      expect(find.textContaining('Sent 2, received 1'), findsOneWidget);
    });

    testWidgets('plan shows Pro and the paused state', (tester) async {
      final store = SettingsFake()..paused = true;
      await pumpScreen(tester, store, const SettingsScreen(initialTab: SettingsTab.plan));
      expect(find.text('Paused'), findsWidgets);
      expect(find.text('Secwet ID'), findsOneWidget);
    });

    testWidgets('key rotation runs from Security', (tester) async {
      final store = SettingsFake()..rotationRecommended = true;
      final bridge = await pumpScreen(tester, store, const SettingsScreen(initialTab: SettingsTab.security));
      expect(find.text('Rotation recommended'), findsOneWidget);
      await tester.tap(find.text('Rotate encryption key'));
      await tester.pumpAndSettle();
      expect(find.text('Rotate encryption key?'), findsOneWidget);
      await tester.tap(find.text('Rotate key').last);
      await tester.pumpAndSettle();
      expect(bridge.calls, contains('key_rotate'));
      expect(find.text('Key rotated'), findsOneWidget);
    });

    testWidgets('waits out a sync in flight instead of showing empty values', (tester) async {
      final store = BusyOnceFake();
      await pumpScreen(tester, store, const SettingsScreen());
      await tester.pump(const Duration(milliseconds: 300));
      await tester.pumpAndSettle();
      expect(store.busyAnswers, 1);
      expect(find.text('Test Phone'), findsOneWidget);
    });

    testWidgets('renders in dark', (tester) async {
      await pumpScreen(tester, SettingsFake(), const SettingsScreen(initialTab: SettingsTab.devices), brightness: Brightness.dark);
      expect(find.text('Studio Mac'), findsOneWidget);
    });
  });

  group('Members', () {
    testWidgets('lists members of a space with status pills', (tester) async {
      await pumpScreen(tester, SettingsFake(), const SharingScreen(spaceId: 's2'));
      expect(find.text('Members of Work'), findsOneWidget);
      expect(find.text('ana@example.com'), findsOneWidget);
      expect(find.text('ben@example.com'), findsOneWidget);
      expect(find.text('Invited'), findsOneWidget);
      expect(find.text('Invite'), findsOneWidget);
    });

    testWidgets('remove member offers erase or keep', (tester) async {
      final store = SettingsFake();
      await pumpScreen(tester, store, const SharingScreen(spaceId: 's2'));
      await widen(tester);
      await tester.tap(byLabel('Actions for ana@example.com'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Remove member'));
      await tester.pumpAndSettle();
      expect(find.text('Remove and keep a read-only copy'), findsOneWidget);
      await tester.tap(find.text('Remove and erase').last);
      await tester.pumpAndSettle();
      expect(store.removed.single, {'member_id': 'm1', 'wipe': true});
      expect(find.text('ana@example.com'), findsNothing);
    });

    testWidgets('copy and revoke an invitation', (tester) async {
      final store = SettingsFake();
      await pumpScreen(tester, store, const SharingScreen(spaceId: 's2'));
      await widen(tester);
      await tester.tap(byLabel('Actions for ben@example.com'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Copy invite link'));
      await tester.pumpAndSettle();
      expect(store.copied, ['invite:inv2']);
      expect(find.text('Copied. Clears in 30 seconds.'), findsOneWidget);

      await tester.tap(byLabel('Actions for ben@example.com'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Revoke invitation'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Revoke invitation').last);
      await tester.pumpAndSettle();
      expect(store.revokedInvites, ['inv2']);
      expect(find.text('ben@example.com'), findsNothing);
    });

    testWidgets('invite checks the email, then creates a link to copy', (tester) async {
      final store = SettingsFake();
      await pumpScreen(tester, store, const SharingScreen(spaceId: 's2'));
      await widen(tester);
      await tester.tap(find.text('Invite'));
      await tester.pumpAndSettle();
      expect(find.text('Share Work'), findsOneWidget);

      await tester.tap(find.text('Create invite'));
      await tester.pumpAndSettle();
      expect(find.text('Enter a valid email address.'), findsOneWidget);

      await tester.enterText(find.byType(EditableText).first, 'cy@example.com');
      await tester.tap(find.text('Create invite'));
      await tester.pumpAndSettle();
      expect(store.invites.single['email'], 'cy@example.com');
      expect(find.textContaining('Send this link to cy@example.com'), findsOneWidget);
      await tester.tap(find.text('Copy link'));
      await tester.pumpAndSettle();
      expect(store.copied.last, startsWith('invite:'));
    });

    testWidgets('no relay explains sync instead of an error', (tester) async {
      await pumpScreen(tester, SettingsFake(pro: false), const SharingScreen(spaceId: 's2'));
      expect(find.text('ana@example.com'), findsNothing);
      expect(find.text('Sharing needs Pro and sync'), findsOneWidget);
    });
  });
}
