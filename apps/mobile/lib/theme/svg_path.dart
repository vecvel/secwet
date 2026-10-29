import 'dart:ui';

/// Parses SVG path data (`d`) into a Flutter [Path]. Covers the full command
/// set (M L H V C S Q T A Z, absolute and relative) used by the generated
/// icon set and brand mark. Malformed input stops at the first bad token.
Path parseSvgPath(String d) {
  final path = Path();
  final t = _Tokens(d);
  var cmd = '';
  var x = 0.0, y = 0.0; // current point
  var sx = 0.0, sy = 0.0; // subpath start
  var cx = 0.0, cy = 0.0; // last control point, for S and T
  var prev = '';

  while (t.more) {
    final c = t.command();
    if (c != null) {
      cmd = c;
    } else if (cmd.isEmpty) {
      break;
    }
    final rel = cmd == cmd.toLowerCase() && cmd != 'z';
    final ox = rel ? x : 0.0, oy = rel ? y : 0.0;
    switch (cmd.toUpperCase()) {
      case 'M':
        x = ox + t.number();
        y = oy + t.number();
        path.moveTo(x, y);
        sx = x;
        sy = y;
        // Further pairs after a moveto are linetos.
        cmd = rel ? 'l' : 'L';
      case 'L':
        x = ox + t.number();
        y = oy + t.number();
        path.lineTo(x, y);
      case 'H':
        x = ox + t.number();
        path.lineTo(x, y);
      case 'V':
        y = oy + t.number();
        path.lineTo(x, y);
      case 'C':
        final x1 = ox + t.number(), y1 = oy + t.number();
        cx = ox + t.number();
        cy = oy + t.number();
        x = ox + t.number();
        y = oy + t.number();
        path.cubicTo(x1, y1, cx, cy, x, y);
      case 'S':
        final reflect = 'CcSs'.contains(prev);
        final x1 = reflect ? 2 * x - cx : x, y1 = reflect ? 2 * y - cy : y;
        cx = ox + t.number();
        cy = oy + t.number();
        x = ox + t.number();
        y = oy + t.number();
        path.cubicTo(x1, y1, cx, cy, x, y);
      case 'Q':
        cx = ox + t.number();
        cy = oy + t.number();
        x = ox + t.number();
        y = oy + t.number();
        path.quadraticBezierTo(cx, cy, x, y);
      case 'T':
        final reflect = 'QqTt'.contains(prev);
        cx = reflect ? 2 * x - cx : x;
        cy = reflect ? 2 * y - cy : y;
        x = ox + t.number();
        y = oy + t.number();
        path.quadraticBezierTo(cx, cy, x, y);
      case 'A':
        final rx = t.number(), ry = t.number(), rotation = t.number();
        final large = t.flag(), sweep = t.flag();
        x = ox + t.number();
        y = oy + t.number();
        path.arcToPoint(
          Offset(x, y),
          radius: Radius.elliptical(rx, ry),
          rotation: rotation,
          largeArc: large,
          clockwise: sweep,
        );
      case 'Z':
        path.close();
        x = sx;
        y = sy;
      default:
        return path;
    }
    if (t.failed) break;
    prev = cmd;
    if (cmd.toUpperCase() == 'Z') cmd = '';
  }
  return path;
}

class _Tokens {
  _Tokens(this.s);

  final String s;
  int i = 0;
  bool failed = false;

  static final _number = RegExp(r'[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?');

  void _skip() {
    while (i < s.length && ' ,\t\n\r'.contains(s[i])) {
      i++;
    }
  }

  bool get more {
    _skip();
    return i < s.length && !failed;
  }

  String? command() {
    _skip();
    if (i < s.length && 'MmLlHhVvCcSsQqTtAaZz'.contains(s[i])) return s[i++];
    return null;
  }

  double number() {
    _skip();
    final m = _number.matchAsPrefix(s, i);
    if (m == null) {
      failed = true;
      return 0;
    }
    i = m.end;
    return double.parse(m.group(0)!);
  }

  /// Arc flags may be written without separators ("a1 1 0 01 2 2").
  bool flag() {
    _skip();
    if (i < s.length && (s[i] == '0' || s[i] == '1')) return s[i++] == '1';
    failed = true;
    return false;
  }
}
