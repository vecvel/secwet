import 'package:flutter_test/flutter_test.dart';
import 'package:secwet_mobile/screens/groups/item_screen.dart';
import 'package:secwet_mobile/screens/sharing/share_screen.dart';
import 'package:secwet_mobile/screens/sharing/sharing_screen.dart';

import 'support/fake_store.dart';

/// A Work space entry the owner can share, with its access tree.
class ShareFake extends FakeStore {
  late final group = addGroup('Work things', space: 's2');
  late final item = addItem(group['id'] as String, 'Billing');

  @override
  Map<String, Object? Function(Map<String, Object?>)> handlers() => {
        ...super.handlers(),
        'scope_nodes': (_) => [
              {'kind': 'space', 'id': 's2', 'label': 'Work', 'depth': 0},
              {'kind': 'group', 'id': group['id'], 'label': 'Work things', 'depth': 1, 'parent_id': 's2'},
              {'kind': 'item', 'id': item['id'], 'label': 'Billing', 'depth': 2, 'parent_id': group['id']},
              {'kind': 'general', 'id': item['id'], 'label': 'General', 'depth': 3, 'parent_id': item['id']},
            ],
      };
}

void main() {
  testWidgets('"Share this item" opens the share screen on that item', (tester) async {
    final store = ShareFake();
    final itemId = store.item['id'] as String;
    await pumpScreen(tester, store, ItemScreen(itemId: itemId));
    await tester.tap(byLabel('Actions'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Share this item…'));
    await tester.pumpAndSettle();

    expect(find.byType(SharingScreen), findsNothing);
    final share = tester.widget<ShareScreen>(find.byType(ShareScreen));
    expect(share.initialSpaceId, 's2');
    expect(share.focus?.kind, 'item');
    expect(share.focus?.id, itemId);
    expect(find.text('Share Work'), findsOneWidget);
  });
}
