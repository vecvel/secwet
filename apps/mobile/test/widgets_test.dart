import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:secwet_mobile/theme/secwet_theme.dart';
import 'package:secwet_mobile/theme/secwet_tokens.dart';
import 'package:secwet_mobile/widgets/controls.dart';
import 'package:secwet_mobile/widgets/overlays.dart';

Widget host(Widget child, {SecwetPalette palette = SecwetPalette.light}) => MaterialApp(
      home: SecwetPaletteScope(palette: palette, child: Scaffold(body: Center(child: child))),
    );

void main() {
  testWidgets('primary and danger buttons use the deep fills in both themes', (tester) async {
    for (final p in [SecwetPalette.light, SecwetPalette.dark]) {
      await tester.pumpWidget(host(
        const Column(children: [
          SecwetButton(label: 'Save', onPressed: _noop),
          SecwetButton(label: 'Delete', variant: ButtonVariant.danger, onPressed: _noop),
        ]),
        palette: p,
      ));
      Color fill(String label) => ((tester.widget<Container>(find.ancestor(of: find.text(label), matching: find.byType(Container)).first)).decoration! as BoxDecoration).color!;
      expect(fill('Save'), const Color(0xFF3D6A4C));
      expect(fill('Delete'), const Color(0xFFB0372D));
      // 36 px (the mobile control height), in a 44 px tap area.
      expect(tester.getSize(find.ancestor(of: find.text('Save'), matching: find.byType(Container)).first).height, 36);
      // The 44 px tap area takes no layout space.
      expect(tester.getSize(find.ancestor(of: find.text('Save'), matching: find.byType(TouchTarget)).first).height, 36);
    }
  });

  testWidgets('selected tab changes color only, never weight or size', (tester) async {
    var selected = 'a';
    await tester.pumpWidget(host(StatefulBuilder(
      builder: (context, set) => SegmentedTabs<String>(
        tabs: const [TabSpec('a', 'Secrets', count: 2), TabSpec('b', 'Assets', count: 1)],
        selected: selected,
        onChanged: (v) => set(() => selected = v),
      ),
    )));
    TextStyle style(String t) => tester.widget<Text>(find.text(t)).style!;
    expect(style('Secrets').fontWeight, style('Assets').fontWeight);
    expect(style('Secrets').fontSize, style('Assets').fontSize);
    expect(style('Secrets').color, isNot(style('Assets').color));
    await tester.tap(find.text('Assets'));
    await tester.pump();
    expect(selected, 'b');
  });

  testWidgets('typed confirmation enables the button only on an exact match', (tester) async {
    bool? result;
    await tester.pumpWidget(host(Builder(
      builder: (context) => SecwetButton(
        label: 'Open',
        onPressed: () async => result = await showConfirmDialog(
          context,
          title: 'Delete group',
          message: 'This deletes the group and everything in it.',
          confirmLabel: 'Delete',
          typedName: 'Payments',
        ),
      ),
    )));
    await tester.tap(find.text('Open'));
    await tester.pumpAndSettle();
    Opacity confirm() => tester.widget<Opacity>(find.ancestor(of: find.text('Delete'), matching: find.byType(Opacity)).first);
    expect(confirm().opacity, 0.5);
    await tester.enterText(find.byType(TextField), 'Payment');
    await tester.pump();
    expect(confirm().opacity, 0.5);
    await tester.enterText(find.byType(TextField), 'Payments');
    await tester.pump();
    expect(confirm().opacity, 1);
    await tester.tap(find.text('Delete'));
    await tester.pumpAndSettle();
    expect(result, isTrue);
  });

  testWidgets('menu runs the picked entry', (tester) async {
    var renamed = false;
    await tester.pumpWidget(host(SecwetMenuButton(entries: [
      MenuEntry('Rename', onSelected: () => renamed = true),
      const MenuEntry.separator(),
      const MenuEntry('Delete', danger: true),
    ])));
    await tester.tap(find.bySemanticsLabel('More'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Rename'));
    await tester.pumpAndSettle();
    expect(renamed, isTrue);
  });

  testWidgets('a button takes taps up to 44 px around it', (tester) async {
    var taps = 0;
    await tester.pumpWidget(host(
      Center(child: SecwetButton(label: 'Go', onPressed: () => taps++)),
      palette: SecwetPalette.light,
    ));
    final box = tester.getRect(find.byType(TouchTarget));
    await tester.tapAt(box.topCenter - const Offset(0, 3));
    expect(taps, 1);
    await tester.tapAt(box.bottomCenter + const Offset(0, 3));
    expect(taps, 2);
    await tester.tapAt(box.topCenter - const Offset(0, 8));
    expect(taps, 2);
  });
}

void _noop() {}
