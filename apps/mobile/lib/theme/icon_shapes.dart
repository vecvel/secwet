import 'dart:ui';

import 'svg_path.dart';

/// One shape of an outline icon on the 20 x 20 grid (see secwet_icons.g.dart).
sealed class IconShape {
  const IconShape({this.strokeWidth, this.filled = false});

  /// Overrides the icon's 1.5 stroke when set.
  final double? strokeWidth;

  /// Filled with the icon color instead of stroked.
  final bool filled;

  Path toPath();
}

class IconPath extends IconShape {
  const IconPath(this.d, {super.strokeWidth, super.filled});

  final String d;

  @override
  Path toPath() => parseSvgPath(d);
}

class IconRect extends IconShape {
  const IconRect(this.x, this.y, this.width, this.height, this.rx, {super.strokeWidth, super.filled});

  final double x, y, width, height, rx;

  @override
  Path toPath() => Path()
    ..addRRect(RRect.fromRectAndRadius(Rect.fromLTWH(x, y, width, height), Radius.circular(rx)));
}

class IconCircle extends IconShape {
  const IconCircle(this.cx, this.cy, this.r, {super.strokeWidth, super.filled});

  final double cx, cy, r;

  @override
  Path toPath() => Path()..addOval(Rect.fromCircle(center: Offset(cx, cy), radius: r));
}
