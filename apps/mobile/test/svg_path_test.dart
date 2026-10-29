import 'dart:ui';

import 'package:flutter_test/flutter_test.dart';
import 'package:secwet_mobile/theme/brand_mark.g.dart';
import 'package:secwet_mobile/theme/secwet_icons.g.dart';
import 'package:secwet_mobile/theme/svg_path.dart';

void main() {
  test('absolute and relative lines, close', () {
    final b = parseSvgPath('M2 3 L10 3 l0 5 h-8 z').getBounds();
    expect(b, const Rect.fromLTRB(2, 3, 10, 8));
  });

  test('implicit lineto after moveto, compact numbers', () {
    final b = parseSvgPath('m1-1 2.5.5 1e1 0').getBounds();
    expect(b.left, 1);
    expect(b.right, closeTo(13.5, 1e-9));
    expect(b.top, -1);
  });

  test('arcs, curves and smooth curves', () {
    final arc = parseSvgPath('M4 10a6 6 0 0 1 12 0').getBounds();
    expect(arc.width, closeTo(12, 1e-6));
    expect(arc.top, closeTo(4, 1e-6));
    final s = parseSvgPath('M0 0c1 0 2 1 2 2s1 2 2 2').getBounds();
    expect(s.right, closeTo(4, 1e-9));
    expect(s.bottom, closeTo(4, 1e-9));
  });

  test('malformed data stops without throwing', () {
    expect(() => parseSvgPath('M1 1 L oops'), returnsNormally);
  });

  test('every generated icon draws inside the 20 pt grid', () {
    for (final icon in SecwetIcons.values) {
      final shapes = secwetIconShapes[icon]!;
      expect(shapes, isNotEmpty, reason: icon.name);
      for (final s in shapes) {
        final b = s.toPath().getBounds();
        expect(b.isEmpty && b.width == 0 && b.height == 0, isFalse, reason: icon.name);
        expect(b.left >= 0 && b.top >= 0 && b.right <= 20 && b.bottom <= 20, isTrue, reason: '${icon.name} $b');
      }
    }
  });

  test('brand mark fits its 40 pt box at (12, 12)', () {
    for (final d in [BrandMarkPaths.largeBack, BrandMarkPaths.largeFront, BrandMarkPaths.smallBack, BrandMarkPaths.smallFront]) {
      final b = parseSvgPath(d).getBounds();
      expect(b.left >= 11.9 && b.top >= 11.9 && b.right <= 52.1 && b.bottom <= 52.1, isTrue, reason: '$b');
    }
  });
}
