import 'package:flutter/material.dart' show Material, MaterialType, TextField, InputDecoration, InputBorder;
import 'package:flutter/services.dart' show TextInputAction;
import 'package:flutter/widgets.dart';

import '../../../app/secwet_scope.dart';
import '../../../app/shell.dart';
import '../../../core/secwet_api.dart';
import '../../../theme/secwet_theme.dart';
import '../../../theme/secwet_tokens.dart';
import '../../../widgets/controls.dart';
import '../../../widgets/icon.dart';
import '../../../widgets/layout.dart';
import '../../../widgets/overlays.dart';
import '../common.dart';
import 'rich_text.dart';
import 'rich_text_controller.dart';

/// Rich-text note editor (desktop screens/items/RichTextEditor.tsx): title,
/// formatting toolbar (headings, bold, italic, underline, strikethrough,
/// lists, quote, code, table, link, undo, redo), the formatted body, and
/// Copy as plain text. [note] null creates a new note in [environmentId].
class NoteEditorScreen extends StatefulWidget {
  const NoteEditorScreen({
    super.key,
    this.note,
    required this.itemId,
    required this.itemName,
    this.environmentId,
    this.readOnly = false,
    this.canDelete = false,
  });

  final Note? note;
  final String itemId;
  final String itemName;
  final String? environmentId;

  /// Viewer role or read-only archive: the note without editing controls.
  final bool readOnly;
  final bool canDelete;

  @override
  State<NoteEditorScreen> createState() => _NoteEditorScreenState();
}

class _NoteEditorScreenState extends State<NoteEditorScreen> {
  late final _title = TextEditingController(text: widget.note?.title ?? '');
  late final _body = RichTextController(parseNoteHtml(widget.note?.content ?? ''));
  final _bodyFocus = FocusNode();
  String? _error;
  bool _saving = false;
  bool _copied = false;
  bool _dirty = false;
  late final String _originalBody;

  SecwetApi get _api => SecwetScope.read(context).api;

  @override
  void initState() {
    super.initState();
    _originalBody = _body.text;
    _body.addListener(_onBody);
    _title.addListener(_onBody);
  }

  void _onBody() {
    if (!_dirty && (_title.text != (widget.note?.title ?? '') || _body.text != _originalBody)) {
      _dirty = true;
    }
    setState(() {});
  }

  @override
  void dispose() {
    _body.removeListener(_onBody);
    _title.removeListener(_onBody);
    _title.dispose();
    _body.dispose();
    _bodyFocus.dispose();
    super.dispose();
  }

  Future<void> _copyPlain() async {
    try {
      final note = widget.note;
      if (note != null && !_dirty) {
        await _api.copyNotePlain(note.id);
      } else {
        await _api.copyText(notePlainText(_body.doc));
      }
      if (!mounted) return;
      setState(() => _copied = true);
      showToast(context, 'Copied as plain text. Clears in 30 seconds.', tone: BadgeTone.success);
      Future.delayed(const Duration(milliseconds: 1500), () {
        if (mounted) setState(() => _copied = false);
      });
    } catch (e) {
      if (mounted) showError(context, e, "Couldn't copy this note.");
    }
  }

  Future<void> _save() async {
    if (widget.readOnly || _saving) return;
    final title = _title.text.trim();
    if (title.isEmpty) return setState(() => _error = 'Enter a title for this note.');
    final content = noteHtml(_body.doc);
    setState(() => _saving = true);
    try {
      if (widget.note != null) {
        await _api.updateNote(widget.note!.id, title: title, content: content);
      } else {
        await _api.createNote(widget.itemId, title, content, environmentId: widget.environmentId);
      }
      if (mounted) Navigator.of(context).pop(true);
    } catch (e) {
      if (mounted) {
        setState(() {
          _saving = false;
          _error = errorText(e, 'Failed to save note.');
        });
      }
    }
  }

  Future<void> _delete() async {
    final note = widget.note!;
    final ok = await showConfirmDialog(
      context,
      title: 'Delete "${note.title}"?',
      message: 'Are you sure you want to permanently delete this note?',
      confirmLabel: 'Delete note',
    );
    if (!ok) return;
    try {
      await _api.deleteNote(note.id);
      if (mounted) Navigator.of(context).pop(true);
    } catch (e) {
      if (mounted) showError(context, e, "Couldn't delete this note.");
    }
  }

  Future<void> _link() async {
    final url = await showNameDialog(
      context,
      title: 'Insert link',
      label: 'Link URL',
      initial: 'https://',
      confirmLabel: 'Insert link',
      validate: (v) => v.trim().isEmpty || v.trim() == 'https://' ? 'Enter a link.' : null,
    );
    if (url != null) _body.setLink(url);
    _bodyFocus.requestFocus();
  }

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    final note = widget.note;
    return ShellPage(
      topBar: TopBar(
        title: note?.title.isNotEmpty == true ? note!.title : 'New note',
        crumbs: [Crumb(widget.itemName, () => Navigator.of(context).maybePop(false))],
        actions: [
          SecwetMenuButton(
            label: _copied ? 'Copied to clipboard' : 'Copy note',
            icon: _copied ? SecwetIcons.check : SecwetIcons.copy,
            entries: [MenuEntry('Plain text', icon: SecwetIcons.file, onSelected: _copyPlain)],
          ),
          if (note != null && widget.canDelete)
            SecwetIconButton(icon: SecwetIcons.trash, label: 'Delete note', onPressed: _delete),
        ],
      ),
      children: [
        Material(
          type: MaterialType.transparency,
          child: TextField(
            controller: _title,
            readOnly: widget.readOnly,
            autofocus: note == null && !widget.readOnly,
            style: SecwetText.title(p).copyWith(fontSize: SecwetFontSize.xl),
            cursorColor: p.accent,
            textInputAction: TextInputAction.next,
            onSubmitted: (_) => _bodyFocus.requestFocus(),
            onChanged: (_) {
              if (_error != null) setState(() => _error = null);
            },
            decoration: InputDecoration(
              isCollapsed: true,
              filled: false,
              border: InputBorder.none,
              enabledBorder: InputBorder.none,
              focusedBorder: InputBorder.none,
              hintText: 'Note title...',
              hintStyle: SecwetText.title(p).copyWith(fontSize: SecwetFontSize.xl, color: p.textTertiary),
              contentPadding: const EdgeInsets.symmetric(vertical: SecwetSpace.s2),
            ),
          ),
        ),
        if (_error != null) Text(_error!, style: SecwetText.sm(p, color: p.danger)),
        const SizedBox(height: SecwetSpace.s2),
        if (!widget.readOnly) ...[
          TextFieldTapRegion(child: _Toolbar(controller: _body, onLink: _link)),
          const SizedBox(height: SecwetSpace.s2),
        ],
        GestureDetector(
          behavior: HitTestBehavior.opaque,
          onTap: widget.readOnly ? null : _bodyFocus.requestFocus,
          child: Container(
            constraints: const BoxConstraints(minHeight: 240),
            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: SecwetSpace.s3),
            decoration: BoxDecoration(
              color: p.surface,
              border: Border.all(color: p.border),
              borderRadius: BorderRadius.circular(SecwetRadius.card),
            ),
            child: Material(
              type: MaterialType.transparency,
              child: TextField(
                controller: _body,
                focusNode: _bodyFocus,
                readOnly: widget.readOnly,
                maxLines: null,
                keyboardType: TextInputType.multiline,
                style: SecwetText.body(p),
                cursorColor: p.accent,
                // Collapsed still takes the theme's fill and enabled/focused
                // borders, so they are cleared here.
                decoration: InputDecoration.collapsed(
                  hintText: widget.readOnly ? '' : 'Write your note...',
                  hintStyle: SecwetText.body(p).copyWith(color: p.textTertiary),
                ).copyWith(filled: false, enabledBorder: InputBorder.none, focusedBorder: InputBorder.none),
              ),
            ),
          ),
        ),
        const SizedBox(height: SecwetSpace.s4),
        Row(
          mainAxisAlignment: MainAxisAlignment.end,
          children: [
            SecwetButton(
              label: widget.readOnly ? 'Close' : 'Cancel',
              variant: ButtonVariant.secondary,
              onPressed: () => Navigator.of(context).pop(false),
            ),
            if (!widget.readOnly) ...[
              const SizedBox(width: SecwetSpace.s2),
              SecwetButton(
                label: _saving ? 'Saving...' : (note != null ? 'Save changes' : 'Create note'),
                onPressed: _saving ? null : _save,
              ),
            ],
          ],
        ),
      ],
    );
  }
}

/// Opens a note full screen; resolves true when it was saved or deleted.
Future<bool?> openNoteEditor(
  BuildContext context, {
  Note? note,
  required String itemId,
  required String itemName,
  String? environmentId,
  required bool readOnly,
  required bool canDelete,
}) =>
    pushScreen<bool>(
      context,
      NoteEditorScreen(
        note: note,
        itemId: itemId,
        itemName: itemName,
        environmentId: environmentId,
        readOnly: readOnly,
        canDelete: canDelete,
      ),
    );

/// The formatting toolbar, one row that scrolls sideways. Active formats
/// show in the accent color; size and weight never change.
class _Toolbar extends StatelessWidget {
  const _Toolbar({required this.controller, required this.onLink});

  final RichTextController controller;
  final VoidCallback onLink;

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    final block = controller.currentBlock;
    Widget tool(String label, String semantics, VoidCallback onTap, {bool active = false, TextStyle? style, bool enabled = true}) {
      return TouchTarget(
        child: Opacity(
          opacity: enabled ? 1 : 0.4,
          child: Tappable(
            label: semantics,
            selected: active,
            onTap: enabled ? onTap : null,
            child: Container(
              height: SecwetControl.height,
              constraints: const BoxConstraints(minWidth: SecwetControl.height),
              padding: const EdgeInsets.symmetric(horizontal: SecwetSpace.s2),
              alignment: Alignment.center,
              decoration: BoxDecoration(
                color: active ? p.accentTintSoft : null,
                borderRadius: BorderRadius.circular(SecwetRadius.small),
              ),
              child: Text(
                label,
                style: SecwetText.md(p, color: active ? p.accent : p.textSecondary, weight: FontWeight.w500).merge(style),
              ),
            ),
          ),
        ),
      );
    }

    Widget sep() => Container(width: 1, height: 18, margin: const EdgeInsets.symmetric(horizontal: SecwetSpace.s1), color: p.border);

    return Container(
      padding: const EdgeInsets.all(SecwetSpace.s1),
      decoration: BoxDecoration(
        color: p.surface,
        border: Border.all(color: p.border),
        borderRadius: BorderRadius.circular(SecwetRadius.control),
      ),
      child: SingleChildScrollView(
        scrollDirection: Axis.horizontal,
        child: Row(
          children: [
            tool('H1', 'Heading 1', () => controller.setBlock(BlockKind.h1), active: block == BlockKind.h1),
            tool('H2', 'Heading 2', () => controller.setBlock(BlockKind.h2), active: block == BlockKind.h2),
            tool('H3', 'Heading 3', () => controller.setBlock(BlockKind.h3), active: block == BlockKind.h3),
            tool('P', 'Paragraph', () => controller.setBlock(BlockKind.paragraph), active: block == BlockKind.paragraph),
            sep(),
            tool('B', 'Bold', () => controller.toggleInline((s) => s.bold, (s, on) => s.copyWith(bold: on)),
                active: controller.hasInline((s) => s.bold), style: const TextStyle(fontWeight: FontWeight.w700)),
            tool('I', 'Italic', () => controller.toggleInline((s) => s.italic, (s, on) => s.copyWith(italic: on)),
                active: controller.hasInline((s) => s.italic), style: const TextStyle(fontStyle: FontStyle.italic)),
            tool('U', 'Underline', () => controller.toggleInline((s) => s.underline, (s, on) => s.copyWith(underline: on)),
                active: controller.hasInline((s) => s.underline), style: const TextStyle(decoration: TextDecoration.underline)),
            tool('S', 'Strikethrough', () => controller.toggleInline((s) => s.strike, (s, on) => s.copyWith(strike: on)),
                active: controller.hasInline((s) => s.strike), style: const TextStyle(decoration: TextDecoration.lineThrough)),
            sep(),
            tool('• List', 'Bulleted list', () => controller.setBlock(BlockKind.bullet), active: block == BlockKind.bullet),
            tool('1. List', 'Numbered list', () => controller.setBlock(BlockKind.numbered), active: block == BlockKind.numbered),
            tool('” Quote', 'Blockquote', () => controller.setBlock(BlockKind.quote), active: block == BlockKind.quote),
            tool('</> Code', 'Code block', () => controller.setBlock(BlockKind.code), active: block == BlockKind.code),
            tool('Table', 'Insert table', controller.insertTable),
            tool('Link', 'Insert link', onLink),
            sep(),
            tool('Undo', 'Undo', controller.undo, enabled: controller.canUndo),
            tool('Redo', 'Redo', controller.redo, enabled: controller.canRedo),
          ],
        ),
      ),
    );
  }
}
