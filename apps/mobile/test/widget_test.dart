import 'package:flutter_test/flutter_test.dart';
import 'package:secwet_mobile/main.dart';

void main() {
  testWidgets('bottom navigation switches destinations', (tester) async {
    await tester.pumpWidget(const SecwetApp());
    expect(find.text('Secrets'), findsWidgets);

    await tester.tap(find.text('Devices'));
    await tester.pumpAndSettle();
    expect(find.text('Devices'), findsNWidgets(2));
  });
}
