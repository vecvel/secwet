import 'package:flutter_test/flutter_test.dart';
import 'package:secwet_mobile/screens/settings/pair_join_screen.dart';

import 'support/fake_store.dart';

void main() {
  test('the relay host is read from the link', () {
    expect(pairingRelayHost('secwet://pair?v=1&s=a&k=b&r=relay.example.com'), 'relay.example.com');
    expect(pairingRelayHost('secwet://pair?v=1&s=a&k=b&r=https%3A%2F%2Frelay.example.com%2F'), 'relay.example.com');
    expect(pairingRelayHost('secwet://pair?v=1&s=a&k=b&r=192.168.1.4%3A8787'), '192.168.1.4:8787');
    expect(pairingRelayHost('secwet://pair?v=1&s=a&k=b'), isNull);
  });

  testWidgets('an opened pairing link waits for the user before joining', (tester) async {
    final bridge = await pumpScreen(
      tester,
      FakeStore(),
      const PairJoinScreen(link: 'secwet://pair?v=1&s=a&k=b&r=relay.attacker.example'),
    );
    expect(find.textContaining('through relay.attacker.example'), findsOneWidget);
    expect(bridge.calls, isNot(contains('pairing_join_start')));

    await tester.tap(find.text('Pair with this device'));
    await tester.pumpAndSettle();
    expect(bridge.calls, contains('pairing_join_start'));
  });

  testWidgets('dismissing an opened link shows the scanner instead', (tester) async {
    final bridge = await pumpScreen(tester, FakeStore(), const PairJoinScreen(link: 'secwet://pair?v=1&s=a&k=b&r=relay.example.com'));
    await tester.tap(find.text('Scan a code instead'));
    await tester.pumpAndSettle();
    expect(find.text('Scan code'), findsOneWidget);
    expect(bridge.calls, isNot(contains('pairing_join_start')));
  });
}
