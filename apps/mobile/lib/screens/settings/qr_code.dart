import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter/widgets.dart';

/// Our own QR encoder (ISO/IEC 18004) for the pairing code: byte mode,
/// error correction level M, versions 1 to 10 (up to 213 bytes, plenty for a
/// `secwet://pair` link). Follows the reference construction: data and
/// Reed-Solomon codewords interleaved by block, zig-zag placement, the mask
/// with the lowest penalty.
class QrMatrix {
  QrMatrix._(this.size, this._modules);

  /// Modules per side (21 for version 1, +4 per version).
  final int size;
  final List<bool> _modules;

  bool dark(int x, int y) => _modules[y * size + x];

  static const _maxVersion = 10;

  // Level M, index = version (0 unused). Checked against the standard's
  // capacity table: data codewords 16, 28, 44, 64, 86, 108, 124, 154, 182, 216.
  static const _eccPerBlock = [0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26];
  static const _blocks = [0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5];

  /// Encodes [text] as UTF-8. Throws [ArgumentError] when it does not fit.
  factory QrMatrix.encode(String text) {
    final data = utf8.encode(text);
    for (var v = 1; v <= _maxVersion; v++) {
      final countBits = v <= 9 ? 8 : 16;
      final capacity = _dataCodewords(v) * 8;
      if (4 + countBits + data.length * 8 <= capacity) return _build(v, data, countBits, capacity);
    }
    throw ArgumentError('Text too long for a QR code: ${data.length} bytes');
  }

  static int _rawModules(int v) {
    var result = (16 * v + 128) * v + 64;
    if (v >= 2) {
      final align = v ~/ 7 + 2;
      result -= (25 * align - 10) * align - 55;
      if (v >= 7) result -= 36;
    }
    return result;
  }

  static int _dataCodewords(int v) => _rawModules(v) ~/ 8 - _eccPerBlock[v] * _blocks[v];

  static QrMatrix _build(int v, List<int> data, int countBits, int capacity) {
    // Segment: mode 0100 (byte), count, bytes, terminator, padding.
    final bits = <bool>[];
    void put(int value, int length) {
      for (var i = length - 1; i >= 0; i--) {
        bits.add((value >> i) & 1 == 1);
      }
    }

    put(0x4, 4);
    put(data.length, countBits);
    for (final b in data) {
      put(b, 8);
    }
    put(0, (capacity - bits.length).clamp(0, 4));
    put(0, (8 - bits.length % 8) % 8);
    for (var pad = 0xEC; bits.length < capacity; pad ^= 0xEC ^ 0x11) {
      put(pad, 8);
    }
    final codewords = Uint8List(bits.length ~/ 8);
    for (var i = 0; i < bits.length; i++) {
      if (bits[i]) codewords[i >> 3] |= 0x80 >> (i & 7);
    }

    final q = _Builder(v);
    q.drawFunctionPatterns();
    q.drawCodewords(_interleave(v, codewords));
    var best = 0;
    var bestPenalty = -1;
    for (var mask = 0; mask < 8; mask++) {
      q.applyMask(mask);
      q.drawFormatBits(mask);
      final penalty = q.penalty();
      if (bestPenalty < 0 || penalty < bestPenalty) {
        best = mask;
        bestPenalty = penalty;
      }
      q.applyMask(mask); // XOR again to undo
    }
    q.applyMask(best);
    q.drawFormatBits(best);
    return QrMatrix._(q.size, q.modules);
  }

  /// Splits into blocks, appends each block's Reed-Solomon codewords and
  /// interleaves them column by column.
  static List<int> _interleave(int v, Uint8List data) {
    final numBlocks = _blocks[v];
    final eccLen = _eccPerBlock[v];
    final raw = _rawModules(v) ~/ 8;
    final numShort = numBlocks - raw % numBlocks;
    final shortLen = raw ~/ numBlocks;
    final divisor = _rsDivisor(eccLen);
    final blocks = <List<int>>[];
    var k = 0;
    for (var i = 0; i < numBlocks; i++) {
      final len = shortLen - eccLen + (i < numShort ? 0 : 1);
      final dat = data.sublist(k, k + len).toList();
      k += len;
      final ecc = _rsRemainder(dat, divisor);
      if (i < numShort) dat.add(0);
      blocks.add([...dat, ...ecc]);
    }
    final out = <int>[];
    for (var i = 0; i < blocks[0].length; i++) {
      for (var j = 0; j < blocks.length; j++) {
        if (i != shortLen - eccLen || j >= numShort) out.add(blocks[j][i]);
      }
    }
    return out;
  }

  static int _gfMul(int x, int y) {
    var z = 0;
    for (var i = 7; i >= 0; i--) {
      z = (z << 1) ^ ((z >> 7) * 0x11D);
      z ^= ((y >> i) & 1) * x;
    }
    return z & 0xFF;
  }

  static List<int> _rsDivisor(int degree) {
    final result = List<int>.filled(degree, 0);
    result[degree - 1] = 1;
    var root = 1;
    for (var i = 0; i < degree; i++) {
      for (var j = 0; j < degree; j++) {
        result[j] = _gfMul(result[j], root);
        if (j + 1 < degree) result[j] ^= result[j + 1];
      }
      root = _gfMul(root, 0x02);
    }
    return result;
  }

  static List<int> _rsRemainder(List<int> data, List<int> divisor) {
    final result = List<int>.filled(divisor.length, 0, growable: true);
    for (final b in data) {
      final factor = b ^ result.removeAt(0);
      result.add(0);
      for (var i = 0; i < divisor.length; i++) {
        result[i] ^= _gfMul(divisor[i], factor);
      }
    }
    return result;
  }
}

class _Builder {
  _Builder(this.version)
      : size = version * 4 + 17,
        modules = List.filled((version * 4 + 17) * (version * 4 + 17), false),
        function = List.filled((version * 4 + 17) * (version * 4 + 17), false);

  final int version;
  final int size;
  final List<bool> modules;
  final List<bool> function;

  bool get(int x, int y) => modules[y * size + x];

  void set(int x, int y, bool dark) {
    modules[y * size + x] = dark;
    function[y * size + x] = true;
  }

  void drawFunctionPatterns() {
    for (var i = 0; i < size; i++) {
      set(6, i, i.isEven);
      set(i, 6, i.isEven);
    }
    _finder(3, 3);
    _finder(size - 4, 3);
    _finder(3, size - 4);
    final align = _alignmentPositions();
    final n = align.length;
    for (var i = 0; i < n; i++) {
      for (var j = 0; j < n; j++) {
        final corner = (i == 0 && j == 0) || (i == 0 && j == n - 1) || (i == n - 1 && j == 0);
        if (!corner) _alignment(align[i], align[j]);
      }
    }
    drawFormatBits(0); // reserve; redrawn per mask
    if (version >= 7) {
      var rem = version;
      for (var i = 0; i < 12; i++) {
        rem = (rem << 1) ^ ((rem >> 11) * 0x1F25);
      }
      final bits = version << 12 | rem;
      for (var i = 0; i < 18; i++) {
        final bit = (bits >> i) & 1 == 1;
        final a = size - 11 + i % 3;
        final b = i ~/ 3;
        set(a, b, bit);
        set(b, a, bit);
      }
    }
  }

  void _finder(int cx, int cy) {
    for (var dy = -4; dy <= 4; dy++) {
      for (var dx = -4; dx <= 4; dx++) {
        final x = cx + dx;
        final y = cy + dy;
        if (x < 0 || y < 0 || x >= size || y >= size) continue;
        final dist = dx.abs() > dy.abs() ? dx.abs() : dy.abs();
        set(x, y, dist != 2 && dist != 4);
      }
    }
  }

  void _alignment(int cx, int cy) {
    for (var dy = -2; dy <= 2; dy++) {
      for (var dx = -2; dx <= 2; dx++) {
        final dist = dx.abs() > dy.abs() ? dx.abs() : dy.abs();
        set(cx + dx, cy + dy, dist != 1);
      }
    }
  }

  List<int> _alignmentPositions() {
    if (version == 1) return const [];
    final n = version ~/ 7 + 2;
    final step = (version * 8 + n * 3 + 5) ~/ (n * 4 - 4) * 2;
    final result = List<int>.filled(n, 6);
    for (var i = n - 1, pos = size - 7; i >= 1; i--, pos -= step) {
      result[i] = pos;
    }
    return result;
  }

  /// Level M (format bits 00) with [mask], BCH-protected and XOR-masked.
  void drawFormatBits(int mask) {
    final data = mask; // (0 << 3) | mask
    var rem = data;
    for (var i = 0; i < 10; i++) {
      rem = (rem << 1) ^ ((rem >> 9) * 0x537);
    }
    final bits = (data << 10 | rem) ^ 0x5412;
    bool bit(int i) => (bits >> i) & 1 == 1;
    for (var i = 0; i <= 5; i++) {
      set(8, i, bit(i));
    }
    set(8, 7, bit(6));
    set(8, 8, bit(7));
    set(7, 8, bit(8));
    for (var i = 9; i < 15; i++) {
      set(14 - i, 8, bit(i));
    }
    for (var i = 0; i < 8; i++) {
      set(size - 1 - i, 8, bit(i));
    }
    for (var i = 8; i < 15; i++) {
      set(8, size - 15 + i, bit(i));
    }
    set(8, size - 8, true);
  }

  void drawCodewords(List<int> data) {
    var i = 0;
    for (var right = size - 1; right >= 1; right -= 2) {
      if (right == 6) right = 5;
      for (var vert = 0; vert < size; vert++) {
        for (var j = 0; j < 2; j++) {
          final x = right - j;
          final upward = ((right + 1) & 2) == 0;
          final y = upward ? size - 1 - vert : vert;
          if (!function[y * size + x] && i < data.length * 8) {
            modules[y * size + x] = (data[i >> 3] >> (7 - (i & 7))) & 1 == 1;
            i++;
          }
        }
      }
    }
  }

  void applyMask(int mask) {
    for (var y = 0; y < size; y++) {
      for (var x = 0; x < size; x++) {
        if (function[y * size + x]) continue;
        final invert = switch (mask) {
          0 => (x + y) % 2 == 0,
          1 => y % 2 == 0,
          2 => x % 3 == 0,
          3 => (x + y) % 3 == 0,
          4 => (x ~/ 3 + y ~/ 2) % 2 == 0,
          5 => x * y % 2 + x * y % 3 == 0,
          6 => (x * y % 2 + x * y % 3) % 2 == 0,
          _ => ((x + y) % 2 + x * y % 3) % 2 == 0,
        };
        if (invert) modules[y * size + x] = !modules[y * size + x];
      }
    }
  }

  /// The standard's four penalty rules: runs, 2x2 blocks, finder-like
  /// patterns, and dark/light balance.
  int penalty() {
    var result = 0;
    for (final horizontal in [true, false]) {
      for (var a = 0; a < size; a++) {
        var run = 0;
        bool? color;
        var window = 0;
        for (var b = 0; b < size; b++) {
          final dark = horizontal ? get(b, a) : get(a, b);
          if (dark == color) {
            run++;
            if (run == 5) {
              result += 3;
            } else if (run > 5) {
              result++;
            }
          } else {
            color = dark;
            run = 1;
          }
          // 1:1:3:1:1 with four light modules on one side (rule 3).
          window = ((window << 1) | (dark ? 1 : 0)) & 0x7FF;
          if (b >= 10 && (window == 0x5D0 || window == 0x05D)) result += 40;
        }
      }
    }
    for (var y = 0; y < size - 1; y++) {
      for (var x = 0; x < size - 1; x++) {
        final c = get(x, y);
        if (c == get(x + 1, y) && c == get(x, y + 1) && c == get(x + 1, y + 1)) result += 3;
      }
    }
    final dark = modules.where((m) => m).length;
    final total = size * size;
    final k = ((dark * 20 - total * 10).abs() + total - 1) ~/ total - 1;
    return result + (k < 0 ? 0 : k) * 10;
  }
}

/// A QR code with a quiet zone: dark modules on white in both themes so any
/// camera reads it (as on desktop).
class QrCode extends StatelessWidget {
  const QrCode({super.key, required this.data, this.size = 200, this.semanticLabel});

  final String data;
  final double size;
  final String? semanticLabel;

  @override
  Widget build(BuildContext context) {
    final matrix = QrMatrix.encode(data);
    return Semantics(
      label: semanticLabel,
      image: true,
      child: SizedBox.square(dimension: size, child: CustomPaint(painter: _QrPainter(matrix))),
    );
  }
}

class _QrPainter extends CustomPainter {
  _QrPainter(this.matrix);

  final QrMatrix matrix;

  static const _quiet = 2;
  static const _dark = Color(0xFF1A1916);

  @override
  void paint(Canvas canvas, Size size) {
    canvas.drawRect(Offset.zero & size, Paint()..color = const Color(0xFFFFFFFF));
    final n = matrix.size + _quiet * 2;
    final cell = size.width / n;
    final path = Path();
    for (var y = 0; y < matrix.size; y++) {
      for (var x = 0; x < matrix.size; x++) {
        if (matrix.dark(x, y)) {
          path.addRect(Rect.fromLTWH((x + _quiet) * cell, (y + _quiet) * cell, cell + 0.01, cell + 0.01));
        }
      }
    }
    canvas.drawPath(path, Paint()..color = _dark);
  }

  @override
  bool shouldRepaint(_QrPainter old) => !identical(old.matrix, matrix);
}
