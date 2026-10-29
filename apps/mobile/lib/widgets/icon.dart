import 'package:flutter/widgets.dart';

import '../theme/icon_shapes.dart';
import '../theme/secwet_icons.g.dart';

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
