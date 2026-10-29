// Key-value parser for pasted environment files and credential blocks, the
// same rules as the desktop:
// KEY=VALUE, KEY: VALUE, quoted keys and values, ";" and "," record
// separators outside quotes, "#" and "//" comments, "export " prefixes.

class ParsedSecret {
  const ParsedSecret(this.name, this.value);

  final String name;
  final String value;
}

final _nextPair = RegExp(r'''^(?:[A-Za-z_][A-Za-z0-9_.-]*|["'`][^"'`]+["'`])\s*[:=]''');

bool _isQuote(String c) => c == '"' || c == "'" || c == '`';

List<ParsedSecret> parseSecretText(String raw) {
  if (raw.trim().isEmpty) return const [];
  final text = raw.replaceAll('\r\n', '\n').replaceAll('\r', '\n');

  final chunks = <String>[];
  var current = StringBuffer();
  String? inQuote;
  var i = 0;
  void flush() {
    final c = current.toString().trim();
    if (c.isNotEmpty) chunks.add(c);
    current = StringBuffer();
  }

  while (i < text.length) {
    final ch = text[i];
    if (inQuote != null && ch == r'\' && i + 1 < text.length) {
      current
        ..write(ch)
        ..write(text[i + 1]);
      i += 2;
      continue;
    }
    if (inQuote != null) {
      current.write(ch);
      if (ch == inQuote) inQuote = null;
    } else if (_isQuote(ch)) {
      inQuote = ch;
      current.write(ch);
    } else if (ch == '\n' || ch == ';') {
      flush();
    } else if (ch == ',') {
      if (_nextPair.hasMatch(text.substring(i + 1).trimLeft())) {
        flush();
      } else {
        current.write(ch);
      }
    } else {
      current.write(ch);
    }
    i++;
  }
  flush();

  final entries = <ParsedSecret>[];
  for (var chunk in chunks) {
    chunk = chunk.trim();
    if (chunk.isEmpty || chunk.startsWith('#') || chunk.startsWith('//')) continue;
    if (chunk.startsWith('export ')) chunk = chunk.substring(7).trim();
    if (chunk.isEmpty) continue;

    String? key;
    String? valStr;
    final first = chunk[0];
    if (_isQuote(first)) {
      final end = chunk.indexOf(first, 1);
      if (end != -1) {
        key = chunk.substring(1, end).trim();
        final rest = chunk.substring(end + 1).trim();
        if (rest.isNotEmpty && (rest[0] == '=' || rest[0] == ':')) valStr = rest.substring(1).trim();
      }
    } else {
      final eq = chunk.indexOf('=');
      final col = chunk.indexOf(':');
      final sep = eq != -1 && col != -1 ? (eq < col ? eq : col) : (eq != -1 ? eq : col);
      if (sep != -1) {
        key = chunk.substring(0, sep).trim();
        valStr = chunk.substring(sep + 1).trim();
      }
    }

    if (key != null && key.isNotEmpty && valStr != null) {
      var val = valStr;
      if (valStr.length >= 2 && _isQuote(valStr[0])) {
        final last = valStr.lastIndexOf(valStr[0]);
        val = last > 0 ? valStr.substring(1, last) : valStr.substring(1);
      } else if (val.endsWith(',') || val.endsWith(';')) {
        val = val.substring(0, val.length - 1).trim();
      }
      entries.add(ParsedSecret(key, val));
    }
  }
  return entries;
}
