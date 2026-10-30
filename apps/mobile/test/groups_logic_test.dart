import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:secwet_mobile/core/models.dart';
import 'package:secwet_mobile/screens/groups/access.dart';
import 'package:secwet_mobile/screens/groups/common.dart';
import 'package:secwet_mobile/screens/groups/notes/rich_text.dart';
import 'package:secwet_mobile/screens/groups/notes/rich_text_controller.dart';
import 'package:secwet_mobile/screens/groups/secrets/secret_parser.dart';

Access member(List<(String, String?, String)> grants) => Access(
      isOwner: false,
      grants: [for (final (k, id, r) in grants) Grant(kind: k, id: id, role: r, label: '')],
    );

void main() {
  group('access (desktop lib/access.ts)', () {
    test('owners and missing access are admin everywhere', () {
      expect(effectiveRole(null, const NodePath(spaceId: 's')), 'admin');
      expect(effectiveRole(const Access(isOwner: true, grants: []), const NodePath(itemId: 'i')), 'admin');
    });

    test('the most specific grant on the path wins', () {
      final a = member([('space', 's1', 'viewer'), ('item', 'i1', 'editor'), ('environment', 'e1', 'no_access')]);
      expect(effectiveRole(a, const NodePath(spaceId: 's1', groupId: 'g1')), 'viewer');
      expect(effectiveRole(a, const NodePath(spaceId: 's1', groupId: 'g1', itemId: 'i1', general: true)), 'editor');
      expect(effectiveRole(a, const NodePath(spaceId: 's1', groupId: 'g1', itemId: 'i1', environmentId: 'e1')), 'no_access');
      expect(effectiveRole(a, const NodePath(spaceId: 's2')), 'no_access');
    });

    test('permissions by role, and read-only stops every change', () {
      final editor = Permissions.fromRole('editor', false);
      expect([editor.canView, editor.canWrite, editor.canDelete, editor.canManage], [true, true, false, false]);
      final admin = Permissions.fromRole('admin', true);
      expect([admin.canView, admin.canWrite, admin.canDelete, admin.canShare], [true, false, false, false]);
      expect(isReadOnly(const LinkStatus(state: 'unlinked')), isTrue);
      expect(isReadOnly(const LinkStatus(state: 'linked')), isFalse);
    });

    test('members manage, share and pair only where allowed', () {
      final a = member([('group', 'g1', 'admin')]);
      expect(canManageMembers(a), isTrue);
      expect(canCreateSpace(a, false), isFalse);
      expect(canPairDevices(a, false), isFalse);
      expect(canPairDevices(null, true), isFalse);
      expect(isShareableSpace(const Space(id: 's', name: 'Personal', position: 0, isDefault: true, groupsCount: 0)), isFalse);
    });
  });

  group('secret parser (desktop lib/secretParser.ts)', () {
    List<(String, String)> parse(String s) => [for (final p in parseSecretText(s)) (p.name, p.value)];

    test('env lines, quotes, comments and export', () {
      expect(parse('# comment\nexport A=1\nB="two words"\nC: three'), [('A', '1'), ('B', 'two words'), ('C', 'three')]);
    });

    test('separators outside quotes only', () {
      expect(parse('A=1, B=2; C="x;y,z"'), [('A', '1'), ('B', '2'), ('C', 'x;y,z')]);
      expect(parse('URL=postgres://u:p@h:5432/db'), [('URL', 'postgres://u:p@h:5432/db')]);
      expect(parse('"key one": "v"'), [('key one', 'v')]);
    });
  });

  group('formatting', () {
    test('plural, initials, bytes', () {
      expect(plural(1, 'env'), '1 env');
      expect(plural(2, 'secret'), '2 secrets');
      expect(initialOf('  payments api'), 'P');
      expect(initialOf('…'), '#');
      expect(formatBytes(0), '0 Bytes');
      expect(formatBytes(1536), '1.5 KB');
      expect(formatBytes(2 * 1024 * 1024), '2 MB');
    });

    test('relative time like the desktop short style', () {
      final now = DateTime(2026, 10, 29, 12);
      int ago(Duration d) => now.subtract(d).millisecondsSinceEpoch ~/ 1000;
      expect(formatAgo(ago(const Duration(seconds: 20)), now: now), 'Just now');
      expect(formatAgo(ago(const Duration(minutes: 15)), now: now), '15 min. ago');
      expect(formatAgo(ago(const Duration(hours: 1)), now: now), '1 hr. ago');
      expect(formatAgo(ago(const Duration(days: 1)), now: now), 'yesterday');
      expect(formatAgo(ago(const Duration(days: 3)), now: now), '3 days ago');
    });
  });

  group('note HTML', () {
    test('reads desktop markup and writes it back', () {
      const html = '<h1>Title</h1><p>Some <b>bold</b> and <i>it</i> <a href="https://x.y">link</a></p>'
          '<ul><li>one</li><li>two</li></ul><ol><li>first</li></ol><blockquote>quote</blockquote>'
          '<pre>a\n  b</pre><table><thead><tr><th>H1</th><th>H2</th></tr></thead><tbody><tr><td>c1</td><td>c2</td></tr></tbody></table>';
      final doc = parseNoteHtml(html);
      expect(doc.lines, ['Title', 'Some bold and it link', '• one', '• two', '1. first', 'quote', 'a', '  b', 'H1 | H2', 'c1 | c2']);
      expect(doc.blocks, [
        BlockKind.h1,
        BlockKind.paragraph,
        BlockKind.bullet,
        BlockKind.bullet,
        BlockKind.numbered,
        BlockKind.quote,
        BlockKind.code,
        BlockKind.code,
        BlockKind.tableRow,
        BlockKind.tableRow,
      ]);
      expect(noteHtml(doc), html);
    });

    test('entities, divs and breaks from contenteditable', () {
      final doc = parseNoteHtml('<div>a &amp; b&nbsp;c</div><div><br></div><div>d<br>e</div>');
      expect(doc.lines, ['a & b c', '', 'd', 'e']);
      expect(parseNoteHtml('plain\ntext').lines, ['plain', 'text']);
      expect(noteHtml(parseNoteHtml('<p>x &lt; y</p>')), '<p>x &lt; y</p>');
    });

    test('plain text keeps the structure like the desktop copy', () {
      final doc = parseNoteHtml('<h2>T</h2><p>p</p><ul><li>a</li></ul><table><tr><td>x</td><td>y</td></tr></table><pre>c</pre>');
      expect(notePlainText(doc), '## T\n\np\n\n• a\nx | y\n```\nc\n```');
    });
  });

  group('rich text controller', () {
    TextEditingValue typed(RichTextController c, String text) =>
        TextEditingValue(text: text, selection: TextSelection.collapsed(offset: text.length));

    test('typing carries bold from the toolbar into the HTML', () {
      final c = RichTextController(RichDoc.empty());
      c.value = typed(c, 'Hi ');
      c.toggleInline((s) => s.bold, (s, on) => s.copyWith(bold: on));
      c.value = typed(c, 'Hi there');
      expect(noteHtml(c.doc), '<p>Hi <b>there</b></p>');
    });

    test('bullet list continues on enter and ends on an empty item', () {
      final c = RichTextController(RichDoc.empty());
      c.value = typed(c, 'a');
      c.setBlock(BlockKind.bullet);
      expect(c.text, '• a');
      c.value = typed(c, '• a\n');
      expect(c.text, '• a\n• ');
      c.value = typed(c, '• a\n• b');
      c.value = typed(c, '• a\n• b\n');
      c.value = typed(c, '• a\n• b\n• \n');
      expect(c.text, '• a\n• b\n');
      expect(noteHtml(c.doc), '<ul><li>a</li><li>b</li></ul><p><br></p>');
    });

    test('numbered lists renumber and undo restores', () {
      final c = RichTextController(parseNoteHtml('<p>x</p><p>y</p>'));
      c.selection = const TextSelection(baseOffset: 0, extentOffset: 3);
      c.setBlock(BlockKind.numbered);
      expect(c.text, '1. x\n2. y');
      c.undo();
      expect(c.text, 'x\ny');
      c.redo();
      expect(c.text, '1. x\n2. y');
    });

    test('a heading line is followed by a paragraph', () {
      final c = RichTextController(parseNoteHtml('<h1>T</h1>'));
      c.value = typed(c, 'T\nbody');
      expect(noteHtml(c.doc), '<h1>T</h1><p>body</p>');
    });

    test('table and link commands', () {
      final c = RichTextController(RichDoc.empty());
      c.insertTable();
      expect(noteHtml(c.doc),
          '<table><thead><tr><th>Header 1</th><th>Header 2</th></tr></thead><tbody><tr><td>Cell 1</td><td>Cell 2</td></tr></tbody></table><p><br></p>');
      final d = RichTextController(RichDoc.empty());
      d.setLink('https://secwet.app');
      expect(noteHtml(d.doc), '<p><a href="https://secwet.app">https://secwet.app</a></p>');
    });
  });
}
