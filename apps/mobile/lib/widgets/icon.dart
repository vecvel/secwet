import 'package:flutter/widgets.dart';

import '../theme/brand_mark.g.dart';
import '../theme/icon_shapes.dart';
import '../theme/secwet_icons.g.dart';
import '../theme/svg_path.dart';

export '../theme/secwet_icons.g.dart' show SecwetIcons;

/// One icon of the desktop outline set (SF Symbols style: 20 pt grid, 1.5
/// stroke, round caps and joins), drawn in [color] or the current text color.
class SecwetIcon extends StatelessWidget {
  const SecwetIcon(this.icon, {super.key, this.size = 16, this.color});

  final SecwetIcons icon;
  final double size;
  final Color? color;

  @override
  Widget build(BuildContext context) {
    final c = color ?? DefaultTextStyle.of(context).style.color ?? const Color(0xFF000000);
    return SizedBox.square(
      dimension: size,
      child: CustomPaint(painter: _IconPainter(icon, c)),
    );
  }
}

class _IconPainter extends CustomPainter {
  _IconPainter(this.icon, this.color);

  final SecwetIcons icon;
  final Color color;

  static final Map<SecwetIcons, List<(IconShape, Path)>> _cache = {};

  static List<(IconShape, Path)> _shapes(SecwetIcons icon) => _cache.putIfAbsent(
        icon,
        () => [for (final s in secwetIconShapes[icon]!) (s, s.toPath())],
      );

  @override
  void paint(Canvas canvas, Size size) {
    final scale = size.width / 20;
    canvas.save();
    canvas.scale(scale);
    for (final (shape, path) in _shapes(icon)) {
      final paint = Paint()
        ..color = color
        ..isAntiAlias = true;
      if (shape.filled) {
        paint.style = PaintingStyle.fill;
      } else {
        paint
          ..style = PaintingStyle.stroke
          ..strokeWidth = shape.strokeWidth ?? 1.5
          ..strokeCap = StrokeCap.round
          ..strokeJoin = StrokeJoin.round;
      }
      canvas.drawPath(path, paint);
    }
    canvas.restore();
  }

  @override
  bool shouldRepaint(_IconPainter old) => old.icon != icon || old.color != color;
}

/// Splash Twin mark with no background, in [color] (the accent by default at
/// the call sites). Uses the optical small cut at 32 px and below.
class BrandMark extends StatelessWidget {
  const BrandMark({super.key, this.size = 26, required this.color});

  final double size;
  final Color color;

  @override
  Widget build(BuildContext context) {
    return SizedBox.square(
      dimension: size,
      child: CustomPaint(painter: _BrandPainter(size <= BrandMarkPaths.smallMaxPx, color)),
    );
  }
}

class _BrandPainter extends CustomPainter {
  _BrandPainter(this.small, this.color);

  final bool small;
  final Color color;

  static final _paths = <bool, (Path, Path)>{};

  static (Path, Path) _get(bool small) => _paths.putIfAbsent(small, () {
        Path p(String d) => parseSvgPath(d)..fillType = PathFillType.evenOdd;
        return small
            ? (p(BrandMarkPaths.smallBack), p(BrandMarkPaths.smallFront))
            : (p(BrandMarkPaths.largeBack), p(BrandMarkPaths.largeFront));
      });

  @override
  void paint(Canvas canvas, Size size) {
    final (back, front) = _get(small);
    canvas.save();
    // viewBox "12 12 40 40"
    canvas.scale(size.width / 40);
    canvas.translate(-12, -12);
    canvas.drawPath(back, Paint()..color = color.withValues(alpha: color.a * BrandMarkPaths.backOpacity));
    canvas.drawPath(front, Paint()..color = color);
    canvas.restore();
  }

  @override
  bool shouldRepaint(_BrandPainter old) => old.small != small || old.color != color;
}
