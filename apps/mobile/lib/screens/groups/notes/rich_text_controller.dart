import 'package:flutter/widgets.dart';

import '../../../theme/secwet_theme.dart';
import '../../../theme/secwet_tokens.dart';
import 'rich_text.dart';

/// A [TextEditingController] that keeps a block kind per line and an inline
/// style per character next to the plain text, so one TextField edits a
/// formatted note. Every edit is diffed against the previous text to carry
/// the formatting along; list markers are kept and renumbered here.
class RichTextController extends TextEditingController {
  RichTextController(RichDoc doc)
      : _blocks = [...doc.blocks],
        _styles = [...doc.styles],
        super(text: doc.text) {
    _history.add(_snapshot());
  }

  List<BlockKind> _blocks;
  List<InlineStyle> _styles;

  /// Formatting for the next typed characters when the selection is collapsed.
  InlineStyle? _pending;

  final _history = <_Snapshot>[];
  int _historyIndex = 0;
  DateTime _lastEdit = DateTime.fromMillisecondsSinceEpoch(0);
  bool _restoring = false;

  RichDoc get doc => RichDoc(text, [..._blocks], [..._styles]);

  bool get canUndo => _historyIndex > 0;
  bool get canRedo => _historyIndex < _history.length - 1;

  // ---------------------------------------------------------------------------
  // Editing
  // ---------------------------------------------------------------------------

  @override
  set value(TextEditingValue newValue) {
    final old = super.value;
    if (_restoring || newValue.text == old.text) {
      if (!_restoring && newValue.selection != old.selection) _pending = null;
      super.value = newValue;
      return;
    }
    super.value = _apply(old, newValue);
    _record();
  }

  TextEditingValue _apply(TextEditingValue old, TextEditingValue next) {
    final a = old.text;
    final b = next.text;
    var p = 0;
    final maxP = a.length < b.length ? a.length : b.length;
    while (p < maxP && a.codeUnitAt(p) == b.codeUnitAt(p)) {
      p++;
    }
    var s = 0;
    while (s < a.length - p && s < b.length - p && a.codeUnitAt(a.length - 1 - s) == b.codeUnitAt(b.length - 1 - s)) {
      s++;
    }
    final removed = a.substring(p, a.length - s);
    final inserted = b.substring(p, b.length - s);
    final line = '\n'.allMatches(a.substring(0, p)).length;
    final lineStart = p == 0 ? 0 : a.lastIndexOf('\n', p - 1) + 1;
    final oldLine = a.substring(lineStart, a.indexOf('\n', lineStart) < 0 ? a.length : a.indexOf('\n', lineStart));
    final kind = _blocks[line];

    // Enter on an empty list item ends the list instead of adding an item.
    if (inserted == '\n' && removed.isEmpty && (kind == BlockKind.bullet || kind == BlockKind.numbered)) {
      final marker = markerLength(kind, oldLine);
      if (marker > 0 && oldLine.length == marker) {
        final text = a.replaceRange(lineStart, lineStart + marker, '');
        _styles.removeRange(lineStart, lineStart + marker);
        _blocks[line] = BlockKind.paragraph;
        _pending = null;
        return TextEditingValue(text: text, selection: TextSelection.collapsed(offset: lineStart));
      }
    }

    // Inline styles: inserted characters take the pending style, else the
    // style of the character before them (links do not extend).
    InlineStyle typed = _pending ??
        (p > 0 && a[p - 1] != '\n' ? _styles[p - 1].copyWith(clearLink: true) : InlineStyle.plain);
    final insertedStyles = [for (final c in inserted.split('')) c == '\n' ? InlineStyle.plain : typed];
    _styles = [..._styles.sublist(0, p), ...insertedStyles, ..._styles.sublist(a.length - s)];

    // Blocks: lines removed with the deleted newlines merge into this one; new
    // lines continue lists, quotes, code and tables, and end headings.
    final removedLines = '\n'.allMatches(removed).length;
    final insertedLines = '\n'.allMatches(inserted).length;
    final follow = switch (kind) {
      BlockKind.h1 || BlockKind.h2 || BlockKind.h3 => BlockKind.paragraph,
      _ => kind,
    };
    final newLines = List.filled(insertedLines, follow);
    _blocks = [..._blocks.sublist(0, line + 1), ...newLines, ..._blocks.sublist(line + 1 + removedLines)];

    var text = b;
    var selection = next.selection;
    var composing = next.composing;
    if (!composing.isValid) {
      final fixed = _normalize(text, selection, freshLines: {for (var k = 1; k <= insertedLines; k++) line + k});
      text = fixed.$1;
      selection = fixed.$2;
    }
    if (_pending != null && !selection.isCollapsed) _pending = null;
    return TextEditingValue(text: text, selection: selection, composing: composing);
  }

  /// Keeps list markers right: new list lines get one, lines whose marker was
  /// deleted become paragraphs, and numbered lists count from 1.
  (String, TextSelection) _normalize(String text, TextSelection sel, {Set<int> freshLines = const {}}) {
    final lines = text.split('\n');
    var offset = 0;
    var number = 0;
    var base = sel.baseOffset;
    var extent = sel.extentOffset;
    final out = StringBuffer();
    final styles = <InlineStyle>[];
    for (var i = 0; i < lines.length; i++) {
      var l = lines[i];
      final lineStyles = _styles.sublist(offset, offset + l.length);
      final kind = _blocks[i];
      String? want;
      if (kind == BlockKind.numbered) {
        number++;
        want = '$number. ';
      } else {
        number = 0;
        if (kind == BlockKind.bullet) want = bulletMarker;
      }
      if (want != null) {
        final have = markerLength(kind, l);
        if (have == 0 && !freshLines.contains(i)) {
          _blocks[i] = BlockKind.paragraph;
          if (kind == BlockKind.numbered) number = 0;
        } else if (have == 0 || l.substring(0, have) != want) {
          final at = out.length;
          final delta = want.length - have;
          l = want + l.substring(have);
          lineStyles.replaceRange(0, have, List.filled(want.length, InlineStyle.plain));
          if (base >= at + have) {
            base += delta;
          } else if (base > at) {
            base = at + want.length;
          }
          if (extent >= at + have) {
            extent += delta;
          } else if (extent > at) {
            extent = at + want.length;
          }
        }
      }
      if (i > 0) {
        out.write('\n');
        styles.add(InlineStyle.plain);
      }
      out.write(l);
      styles.addAll(lineStyles);
      offset += lines[i].length + 1;
    }
    _styles = styles;
    return (out.toString(), TextSelection(baseOffset: base, extentOffset: extent));
  }

  // ---------------------------------------------------------------------------
  // Toolbar commands
  // ---------------------------------------------------------------------------

  TextSelection get _sel => selection.isValid ? selection : TextSelection.collapsed(offset: text.length);

  /// Whether the selection (or the pending style at the caret) has [test].
  bool hasInline(bool Function(InlineStyle s) test) {
    final sel = _sel;
    if (sel.isCollapsed) {
      if (_pending != null) return test(_pending!);
      final i = sel.start - 1;
      return i >= 0 && text[i] != '\n' && test(_styles[i]);
    }
    for (var i = sel.start; i < sel.end; i++) {
      if (text[i] != '\n' && !test(_styles[i])) return false;
    }
    return true;
  }

  /// Turns bold, italic, underline or strikethrough on or off for the
  /// selection, or for what is typed next when nothing is selected.
  void toggleInline(bool Function(InlineStyle s) test, InlineStyle Function(InlineStyle s, bool on) set) {
    final sel = _sel;
    final on = !hasInline(test);
    if (sel.isCollapsed) {
      final i = sel.start - 1;
      final current = _pending ?? (i >= 0 && text[i] != '\n' ? _styles[i].copyWith(clearLink: true) : InlineStyle.plain);
      _pending = set(current, on);
      notifyListeners();
      return;
    }
    for (var i = sel.start; i < sel.end; i++) {
      if (text[i] != '\n') _styles[i] = set(_styles[i], on);
    }
    _changed();
  }

  /// Line indexes the selection touches.
  (int, int) _selectedLines() {
    final sel = _sel;
    final first = '\n'.allMatches(text.substring(0, sel.start)).length;
    final last = '\n'.allMatches(text.substring(0, sel.end)).length;
    return (first, last);
  }

  BlockKind get currentBlock => _blocks[_selectedLines().$1];

  /// Sets the block kind of every selected line; picking the current list
  /// kind again turns the list off.
  void setBlock(BlockKind kind) {
    final (first, last) = _selectedLines();
    final allSame = [for (var i = first; i <= last; i++) _blocks[i]].every((k) => k == kind);
    final target = allSame && kind != BlockKind.paragraph ? BlockKind.paragraph : kind;
    final lines = text.split('\n');
    // Drop the old markers of the touched lines; the normalizer then adds the right ones.
    final cuts = <(int, int)>[];
    final out = StringBuffer();
    final styles = <InlineStyle>[];
    var offset = 0;
    for (var i = 0; i < lines.length; i++) {
      var l = lines[i];
      var st = _styles.sublist(offset, offset + l.length);
      if (i >= first && i <= last) {
        final m = markerLength(_blocks[i], l);
        if (m > 0) {
          cuts.add((offset, m));
          l = l.substring(m);
          st = st.sublist(m);
        }
        _blocks[i] = target;
      }
      if (i > 0) {
        out.write('\n');
        styles.add(InlineStyle.plain);
      }
      out.write(l);
      styles.addAll(st);
      offset += lines[i].length + 1;
    }
    int map(int o) {
      var r = o;
      for (final (at, m) in cuts) {
        if (o >= at + m) {
          r -= m;
        } else if (o > at) {
          r -= o - at;
        }
      }
      return r;
    }

    final sel = _sel;
    _styles = styles;
    final fixed = _normalize(
      out.toString(),
      TextSelection(baseOffset: map(sel.baseOffset), extentOffset: map(sel.extentOffset)),
      freshLines: {for (var i = first; i <= last; i++) i},
    );
    _set(fixed.$1, fixed.$2);
  }

  /// Links the selection to [url]; with nothing selected the URL itself is inserted as a link.
  void setLink(String url) {
    final sel = _sel;
    if (sel.isCollapsed) {
      final style = (_pending ?? InlineStyle.plain).copyWith(link: url);
      final t = text.replaceRange(sel.start, sel.start, url);
      _styles.insertAll(sel.start, List.filled(url.length, style));
      _set(t, TextSelection.collapsed(offset: sel.start + url.length));
      return;
    }
    for (var i = sel.start; i < sel.end; i++) {
      if (text[i] != '\n') _styles[i] = _styles[i].copyWith(link: url);
    }
    _changed();
  }

  /// Inserts a two-column table (header row and one row) after the current line.
  void insertTable() {
    final sel = _sel;
    final lineEnd = text.indexOf('\n', sel.end) < 0 ? text.length : text.indexOf('\n', sel.end);
    final line = '\n'.allMatches(text.substring(0, lineEnd)).length;
    const rows = ['Header 1 | Header 2', 'Cell 1 | Cell 2'];
    final currentEmpty = (lineEnd == 0 || text[lineEnd - 1] == '\n') && _blocks[line] == BlockKind.paragraph;
    final insert = currentEmpty ? '${rows.join('\n')}\n' : '\n${rows.join('\n')}\n';
    final t = text.replaceRange(lineEnd, lineEnd, insert);
    _styles.insertAll(lineEnd, List.filled(insert.length, InlineStyle.plain));
    if (currentEmpty) {
      _blocks.replaceRange(line, line + 1, [BlockKind.tableRow, BlockKind.tableRow, BlockKind.paragraph]);
    } else {
      _blocks.insertAll(line + 1, [BlockKind.tableRow, BlockKind.tableRow, BlockKind.paragraph]);
    }
    _set(t, TextSelection.collapsed(offset: lineEnd + insert.length));
  }

  void undo() {
    if (!canUndo) return;
    _historyIndex--;
    _restore(_history[_historyIndex]);
  }

  void redo() {
    if (!canRedo) return;
    _historyIndex++;
    _restore(_history[_historyIndex]);
  }

  void _set(String t, TextSelection sel) {
    _restoring = true;
    super.value = TextEditingValue(text: t, selection: sel);
    _restoring = false;
    _record(force: true);
  }

  void _changed() {
    _record(force: true);
    notifyListeners();
  }

  // ---------------------------------------------------------------------------
  // History
  // ---------------------------------------------------------------------------

  _Snapshot _snapshot() => _Snapshot(text, [..._blocks], [..._styles], selection);

  void _record({bool force = false}) {
    final now = DateTime.now();
    final coalesce = !force && now.difference(_lastEdit) < const Duration(milliseconds: 800) && _historyIndex > 0;
    _lastEdit = force ? DateTime.fromMillisecondsSinceEpoch(0) : now;
    _history.removeRange(_historyIndex + 1, _history.length);
    if (coalesce) {
      _history[_historyIndex] = _snapshot();
    } else {
      _history.add(_snapshot());
      _historyIndex = _history.length - 1;
      if (_history.length > 200) {
        _history.removeAt(0);
        _historyIndex--;
      }
    }
  }

  void _restore(_Snapshot s) {
    _blocks = [...s.blocks];
    _styles = [...s.styles];
    _pending = null;
    _restoring = true;
    super.value = TextEditingValue(text: s.text, selection: s.selection.isValid ? s.selection : TextSelection.collapsed(offset: s.text.length));
    _restoring = false;
  }

  // ---------------------------------------------------------------------------
  // Rendering
  // ---------------------------------------------------------------------------

  @override
  TextSpan buildTextSpan({required BuildContext context, TextStyle? style, required bool withComposing}) {
    final p = context.palette;
    final base = style ?? SecwetText.body(p);
    final lines = text.split('\n');
    final spans = <InlineSpan>[];
    var offset = 0;
    for (var i = 0; i < lines.length; i++) {
      final l = lines[i];
      final kind = i < _blocks.length ? _blocks[i] : BlockKind.paragraph;
      final ls = lineStyle(kind, base, p);
      final marker = markerLength(kind, l);
      if (marker > 0) {
        spans.add(TextSpan(text: l.substring(0, marker), style: ls.copyWith(color: p.accent)));
      }
      var j = marker;
      while (j < l.length) {
        final s = _styles[offset + j];
        var k = j + 1;
        while (k < l.length && _styles[offset + k] == s) {
          k++;
        }
        spans.add(TextSpan(text: l.substring(j, k), style: _inline(ls, s, p)));
        j = k;
      }
      if (i < lines.length - 1) spans.add(TextSpan(text: '\n', style: ls));
      offset += l.length + 1;
    }
    return TextSpan(style: base, children: spans);
  }

  static TextStyle _inline(TextStyle base, InlineStyle s, SecwetPalette p) {
    final decorations = <TextDecoration>[
      if (s.underline || s.link != null) TextDecoration.underline,
      if (s.strike) TextDecoration.lineThrough,
    ];
    return base.copyWith(
      fontWeight: s.bold ? FontWeight.w700 : null,
      fontStyle: s.italic ? FontStyle.italic : null,
      color: s.link != null ? p.accent : null,
      decoration: decorations.isEmpty ? null : TextDecoration.combine(decorations),
    );
  }
}

/// Text style of a line of [kind] in the editor and the note preview.
TextStyle lineStyle(BlockKind kind, TextStyle base, SecwetPalette p) => switch (kind) {
      BlockKind.h1 => base.copyWith(fontSize: 22, height: 1.35, fontWeight: FontWeight.w600),
      BlockKind.h2 => base.copyWith(fontSize: 18, height: 1.4, fontWeight: FontWeight.w600),
      BlockKind.h3 => base.copyWith(fontSize: SecwetFontSize.lg, fontWeight: FontWeight.w600),
      BlockKind.quote => base.copyWith(fontStyle: FontStyle.italic, color: p.textSecondary),
      BlockKind.code => base.copyWith(fontSize: SecwetFontSize.md, color: p.textSecondary, backgroundColor: p.surfaceSunken),
      BlockKind.tableRow => base.copyWith(fontSize: SecwetFontSize.md, backgroundColor: p.cardHeaderBg),
      _ => base,
    };

class _Snapshot {
  const _Snapshot(this.text, this.blocks, this.styles, this.selection);

  final String text;
  final List<BlockKind> blocks;
  final List<InlineStyle> styles;
  final TextSelection selection;
}
