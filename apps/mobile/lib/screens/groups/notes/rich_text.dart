// The note document model for our own rich-text editor: lines of text, a
// block kind per line, and an inline style per character. Notes are stored
// as HTML (the same content the desktop editor writes), so this file also
// holds a small HTML reader and writer for the tags the editors use. No
// third-party packages.

/// What a line is. Lists keep their marker ("• " or "1. ") in the text so
/// the caret maps 1:1 to the characters on screen; the writer drops it.
enum BlockKind { paragraph, h1, h2, h3, bullet, numbered, quote, code, tableRow }

/// Inline formatting of one character.
class InlineStyle {
  const InlineStyle({this.bold = false, this.italic = false, this.underline = false, this.strike = false, this.link});

  static const plain = InlineStyle();

  final bool bold;
  final bool italic;
  final bool underline;
  final bool strike;
  final String? link;

  bool get isPlain => !bold && !italic && !underline && !strike && link == null;

  InlineStyle copyWith({bool? bold, bool? italic, bool? underline, bool? strike, String? link, bool clearLink = false}) =>
      InlineStyle(
        bold: bold ?? this.bold,
        italic: italic ?? this.italic,
        underline: underline ?? this.underline,
        strike: strike ?? this.strike,
        link: clearLink ? null : (link ?? this.link),
      );

  @override
  bool operator ==(Object other) =>
      other is InlineStyle &&
      other.bold == bold &&
      other.italic == italic &&
      other.underline == underline &&
      other.strike == strike &&
      other.link == link;

  @override
  int get hashCode => Object.hash(bold, italic, underline, strike, link);
}

/// Marker text at the start of a list line.
const bulletMarker = '• ';
final numberedMarker = RegExp(r'^\d+\. ');

/// Length of the list marker at the start of [line] for [kind], or 0.
int markerLength(BlockKind kind, String line) {
  if (kind == BlockKind.bullet && line.startsWith(bulletMarker)) return bulletMarker.length;
  if (kind == BlockKind.numbered) return numberedMarker.firstMatch(line)?.end ?? 0;
  return 0;
}

/// A note body: [text] with lines split by '\n', one [blocks] entry per line
/// and one [styles] entry per character (newlines are plain).
class RichDoc {
  RichDoc(this.text, this.blocks, this.styles)
      : assert(blocks.length == '\n'.allMatches(text).length + 1),
        assert(styles.length == text.length);

  RichDoc.empty()
      : text = '',
        blocks = [BlockKind.paragraph],
        styles = [];

  final String text;
  final List<BlockKind> blocks;
  final List<InlineStyle> styles;

  List<String> get lines => text.split('\n');

  bool get isEmpty => text.trim().isEmpty;
}

// ---------------------------------------------------------------------------
// HTML reader
// ---------------------------------------------------------------------------

class _Node {
  _Node(this.tag, [this.attrs = const {}]);

  final String tag;
  final Map<String, String> attrs;
  final children = <Object>[]; // _Node or String
}

const _voidTags = {'br', 'hr', 'img', 'input', 'meta', 'link', 'col', 'wbr'};

final _tagRe = RegExp(r'<(/?)([a-zA-Z][a-zA-Z0-9]*)((?:\s+[^\s=/>]+(?:\s*=\s*(?:"[^"]*"|' "'[^']*'" r'|[^\s>]+))?)*)\s*(/?)>');
final _attrRe = RegExp(r'([^\s=/>]+)(?:\s*=\s*(?:"([^"]*)"|' "'([^']*)'" r'|([^\s>]+)))?');

String decodeEntities(String s) {
  if (!s.contains('&')) return s;
  return s.replaceAllMapped(RegExp(r'&(#x[0-9a-fA-F]+|#\d+|[a-zA-Z]+);'), (m) {
    final e = m.group(1)!;
    if (e.startsWith('#x')) return String.fromCharCode(int.tryParse(e.substring(2), radix: 16) ?? 0xFFFD);
    if (e.startsWith('#')) return String.fromCharCode(int.tryParse(e.substring(1)) ?? 0xFFFD);
    return switch (e) {
      'amp' => '&',
      'lt' => '<',
      'gt' => '>',
      'quot' => '"',
      'apos' => "'",
      'nbsp' => ' ',
      _ => m.group(0)!,
    };
  });
}

_Node _parseTree(String html) {
  final root = _Node('#root');
  final stack = [root];
  var pos = 0;
  // Comments never carry content in notes; drop them first.
  html = html.replaceAll(RegExp(r'<!--.*?-->', dotAll: true), '');
  for (final m in _tagRe.allMatches(html)) {
    if (m.start > pos) stack.last.children.add(decodeEntities(html.substring(pos, m.start)));
    pos = m.end;
    final closing = m.group(1) == '/';
    final tag = m.group(2)!.toLowerCase();
    if (closing) {
      final i = stack.lastIndexWhere((n) => n.tag == tag);
      if (i > 0) stack.removeRange(i, stack.length);
      continue;
    }
    final attrs = <String, String>{};
    for (final a in _attrRe.allMatches(m.group(3) ?? '')) {
      attrs[a.group(1)!.toLowerCase()] = decodeEntities(a.group(2) ?? a.group(3) ?? a.group(4) ?? '');
    }
    final node = _Node(tag, attrs);
    stack.last.children.add(node);
    if (!_voidTags.contains(tag) && m.group(4) != '/') stack.add(node);
  }
  if (pos < html.length) stack.last.children.add(decodeEntities(html.substring(pos)));
  return root;
}

class _Builder {
  final _lines = <(BlockKind, StringBuffer, List<InlineStyle>)>[];
  StringBuffer _buf = StringBuffer();
  List<InlineStyle> _styles = [];
  BlockKind _kind = BlockKind.paragraph;
  int _number = 0;

  bool get _lineEmpty => _buf.isEmpty;

  void text(String s, InlineStyle style, {bool pre = false}) {
    if (!pre) {
      s = s.replaceAll(RegExp(r'[\s ]+'), ' ');
      if (_lineEmpty) s = s.trimLeft();
      if (s.isEmpty) return;
      if (_buf.toString().endsWith(' ') && s.startsWith(' ')) s = s.substring(1);
    }
    for (final part in s.split('\n').indexed) {
      if (part.$1 > 0) newline(force: true);
      _buf.write(part.$2);
      _styles.addAll(List.filled(part.$2.length, style));
    }
  }

  void startBlock(BlockKind kind) {
    if (!_lineEmpty) newline();
    _kind = kind;
    if (kind == BlockKind.bullet) {
      _buf.write(bulletMarker);
      _styles.addAll(List.filled(bulletMarker.length, InlineStyle.plain));
    } else if (kind == BlockKind.numbered) {
      _number++;
      final m = '$_number. ';
      _buf.write(m);
      _styles.addAll(List.filled(m.length, InlineStyle.plain));
    }
  }

  void endBlock() {
    if (!_lineEmpty) newline();
    _kind = BlockKind.paragraph;
  }

  void resetNumbering() => _number = 0;

  /// Ends the current line. Empty lines are kept only when [force]d (a `<br>`
  /// or a blank paragraph), so markup whitespace never adds lines.
  void newline({bool force = false}) {
    if (_lineEmpty && !force) return;
    // Trailing spaces of a wrapped HTML line are not content.
    var s = _buf.toString();
    var st = _styles;
    if (_kind != BlockKind.code) {
      final trimmed = s.trimRight();
      st = st.sublist(0, trimmed.length);
      s = trimmed;
    }
    _lines.add((_kind, StringBuffer(s), st));
    _buf = StringBuffer();
    _styles = [];
    if (_kind == BlockKind.bullet || _kind == BlockKind.numbered) {
      // A <br> inside a list item continues as a plain line.
      _kind = BlockKind.paragraph;
    }
  }

  void line(BlockKind kind, String s) {
    if (!_lineEmpty) newline();
    _lines.add((kind, StringBuffer(s), List.filled(s.length, InlineStyle.plain)));
  }

  RichDoc build() {
    if (!_lineEmpty) newline();
    while (_lines.isNotEmpty && _lines.last.$2.isEmpty && _lines.last.$1 == BlockKind.paragraph) {
      _lines.removeLast();
    }
    if (_lines.isEmpty) return RichDoc.empty();
    final text = _lines.map((l) => l.$2.toString()).join('\n');
    final styles = <InlineStyle>[];
    for (final (i, l) in _lines.indexed) {
      if (i > 0) styles.add(InlineStyle.plain);
      styles.addAll(l.$3);
    }
    return RichDoc(text, [for (final l in _lines) l.$1], styles);
  }
}

String _textOf(_Node n) {
  final b = StringBuffer();
  void walk(Object o) {
    if (o is String) {
      b.write(o);
    } else if (o is _Node) {
      if (o.tag == 'br') b.write(' ');
      o.children.forEach(walk);
    }
  }

  walk(n);
  return b.toString().replaceAll(RegExp(r'[\s ]+'), ' ').trim();
}

/// Reads note HTML (desktop contenteditable output or our own) into a [RichDoc].
/// Plain text without tags becomes paragraphs.
RichDoc parseNoteHtml(String html) {
  if (html.trim().isEmpty) return RichDoc.empty();
  if (!html.contains('<')) {
    final lines = html.replaceAll('\r\n', '\n').split('\n');
    final text = lines.join('\n');
    return RichDoc(text, List.filled(lines.length, BlockKind.paragraph), List.filled(text.length, InlineStyle.plain));
  }
  final b = _Builder();

  void walk(Object o, InlineStyle style, bool pre) {
    if (o is String) {
      b.text(o, style, pre: pre);
      return;
    }
    final n = o as _Node;
    void kids(InlineStyle s, {bool p = false}) {
      for (final c in n.children) {
        walk(c, s, pre || p);
      }
    }

    switch (n.tag) {
      case 'br':
        b.newline(force: true);
      case 'b' || 'strong':
        kids(style.copyWith(bold: true));
      case 'i' || 'em':
        kids(style.copyWith(italic: true));
      case 'u' || 'ins':
        kids(style.copyWith(underline: true));
      case 's' || 'strike' || 'del':
        kids(style.copyWith(strike: true));
      case 'a':
        kids(style.copyWith(link: n.attrs['href']));
      case 'span':
        final css = (n.attrs['style'] ?? '').toLowerCase();
        kids(style.copyWith(
          bold: css.contains('font-weight: bold') || css.contains('font-weight: 700') ? true : null,
          italic: css.contains('font-style: italic') ? true : null,
          underline: css.contains('underline') ? true : null,
          strike: css.contains('line-through') ? true : null,
        ));
      case 'h1' || 'h2' || 'h3' || 'h4' || 'h5' || 'h6':
        b.startBlock(switch (n.tag) {
          'h1' => BlockKind.h1,
          'h2' => BlockKind.h2,
          _ => BlockKind.h3,
        });
        kids(style);
        b.endBlock();
      case 'p' || 'div':
        final had = n.children.isNotEmpty;
        b.startBlock(BlockKind.paragraph);
        kids(style);
        // An empty paragraph is a blank line (`<p><br></p>` gets its line from the br).
        if (!had) b.newline(force: true);
        b.endBlock();
      case 'blockquote':
        b.startBlock(BlockKind.quote);
        kids(style);
        b.endBlock();
      case 'pre':
        b.startBlock(BlockKind.code);
        kids(style, p: true);
        b.endBlock();
      case 'ul' || 'ol':
        final kind = n.tag == 'ul' ? BlockKind.bullet : BlockKind.numbered;
        b.resetNumbering();
        for (final c in n.children) {
          if (c is _Node && c.tag == 'li') {
            b.startBlock(kind);
            for (final cc in c.children) {
              walk(cc, style, pre);
            }
            b.endBlock();
          } else {
            walk(c, style, pre);
          }
        }
      case 'li':
        b.startBlock(BlockKind.bullet);
        kids(style);
        b.endBlock();
      case 'table':
        final rows = <_Node>[];
        void collect(_Node x) {
          for (final c in x.children) {
            if (c is _Node) c.tag == 'tr' ? rows.add(c) : collect(c);
          }
        }

        collect(n);
        for (final r in rows) {
          final cells = [
            for (final c in r.children)
              if (c is _Node && (c.tag == 'td' || c.tag == 'th')) _textOf(c),
          ];
          b.line(BlockKind.tableRow, cells.join(' | '));
        }
      case 'script' || 'style' || 'head' || 'title':
        break;
      default:
        kids(style);
    }
  }

  for (final c in _parseTree(html).children) {
    walk(c, InlineStyle.plain, false);
  }
  return b.build();
}

// ---------------------------------------------------------------------------
// HTML writer
// ---------------------------------------------------------------------------

String escapeHtml(String s) =>
    s.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;');

String _inlineHtml(String text, List<InlineStyle> styles) {
  final out = StringBuffer();
  var i = 0;
  while (i < text.length) {
    final s = styles[i];
    var j = i + 1;
    while (j < text.length && styles[j] == s) {
      j++;
    }
    var chunk = escapeHtml(text.substring(i, j));
    if (s.strike) chunk = '<s>$chunk</s>';
    if (s.underline) chunk = '<u>$chunk</u>';
    if (s.italic) chunk = '<i>$chunk</i>';
    if (s.bold) chunk = '<b>$chunk</b>';
    if (s.link != null) chunk = '<a href="${escapeHtml(s.link!)}">$chunk</a>';
    out.write(chunk);
    i = j;
  }
  return out.toString();
}

/// Writes [doc] as the note HTML both apps read.
String noteHtml(RichDoc doc) {
  final lines = doc.lines;
  final out = StringBuffer();
  var offset = 0;
  final starts = <int>[];
  for (final l in lines) {
    starts.add(offset);
    offset += l.length + 1;
  }
  String body(int i) {
    final line = lines[i];
    final skip = markerLength(doc.blocks[i], line);
    return _inlineHtml(line.substring(skip), doc.styles.sublist(starts[i] + skip, starts[i] + line.length));
  }

  var i = 0;
  while (i < lines.length) {
    final kind = doc.blocks[i];
    var j = i + 1;
    while (j < lines.length && doc.blocks[j] == kind) {
      j++;
    }
    switch (kind) {
      case BlockKind.bullet || BlockKind.numbered:
        final tag = kind == BlockKind.bullet ? 'ul' : 'ol';
        out.write('<$tag>');
        for (var k = i; k < j; k++) {
          out.write('<li>${body(k)}</li>');
        }
        out.write('</$tag>');
        i = j;
      case BlockKind.code:
        out.write('<pre>${[for (var k = i; k < j; k++) escapeHtml(lines[k])].join('\n')}</pre>');
        i = j;
      case BlockKind.tableRow:
        out.write('<table>');
        for (var k = i; k < j; k++) {
          final cells = lines[k].split(' | ');
          final cell = k == i ? 'th' : 'td';
          if (k == i) out.write('<thead>');
          if (k == i + 1) out.write('<tbody>');
          out.write('<tr>${[for (final c in cells) '<$cell>${escapeHtml(c.trim())}</$cell>'].join()}</tr>');
          if (k == i) out.write('</thead>');
        }
        if (j - i > 1) out.write('</tbody>');
        out.write('</table>');
        i = j;
      default:
        final tag = switch (kind) {
          BlockKind.h1 => 'h1',
          BlockKind.h2 => 'h2',
          BlockKind.h3 => 'h3',
          BlockKind.quote => 'blockquote',
          _ => 'p',
        };
        final content = body(i);
        out.write('<$tag>${content.isEmpty ? '<br>' : content}</$tag>');
        i++;
    }
  }
  return out.toString();
}

/// Plain text with the structure kept, as the desktop "Copy as plain text"
/// (extractPlainTextFromHtml): "# " headings, "• " list items, "a | b" table
/// rows, "> " quotes and fenced code.
String notePlainText(RichDoc doc) {
  final lines = doc.lines;
  final out = StringBuffer();
  var i = 0;
  while (i < lines.length) {
    final kind = doc.blocks[i];
    final text = lines[i].substring(markerLength(kind, lines[i])).trim();
    switch (kind) {
      case BlockKind.h1:
        out.write('# $text\n\n');
      case BlockKind.h2:
        out.write('## $text\n\n');
      case BlockKind.h3:
        out.write('### $text\n\n');
      case BlockKind.bullet || BlockKind.numbered:
        out.write('• $text\n');
      case BlockKind.tableRow:
        out.write('${[for (final c in lines[i].split(' | ')) c.trim()].join(' | ')}\n');
      case BlockKind.quote:
        out.write('> $text\n\n');
      case BlockKind.code:
        var j = i;
        final code = <String>[];
        while (j < lines.length && doc.blocks[j] == BlockKind.code) {
          code.add(lines[j]);
          j++;
        }
        out.write('```\n${code.join('\n').trim()}\n```\n\n');
        i = j;
        continue;
      case BlockKind.paragraph:
        out.write('$text\n\n');
    }
    i++;
  }
  return out.toString().replaceAll(RegExp(r'\n{3,}'), '\n\n').trim();
}
