import 'package:flutter/widgets.dart';

import '../../../app/secwet_scope.dart';
import '../../../core/secwet_api.dart';
import '../../../theme/secwet_theme.dart';
import '../../../theme/secwet_tokens.dart';
import '../../../widgets/controls.dart';
import '../../../widgets/icon.dart';
import '../../../widgets/layout.dart';
import '../../../widgets/overlays.dart';
import '../access.dart';
import '../common.dart';
import 'note_editor.dart';

/// The Notes tab of an entry: search, New note, and note cards that open the editor.
class NotesSection extends StatefulWidget {
  const NotesSection({
    super.key,
    required this.item,
    required this.environmentId,
    required this.notes,
    required this.perms,
    required this.onChanged,
  });

  final Item item;
  final String? environmentId;
  final List<NoteMeta> notes;
  final Permissions perms;
  final VoidCallback onChanged;

  @override
  State<NotesSection> createState() => _NotesSectionState();
}

class _NotesSectionState extends State<NotesSection> {
  final _search = TextEditingController();

  @override
  void dispose() {
    _search.dispose();
    super.dispose();
  }

  Future<void> _open(NoteMeta? meta) async {
    final api = SecwetScope.read(context).api;
    Note? note;
    if (meta != null) {
      try {
        note = await api.note(meta.id);
      } on SecwetException {
        note = Note(
          id: meta.id,
          itemId: meta.itemId,
          environmentId: meta.environmentId,
          title: meta.title,
          content: meta.snippet,
          updatedAt: meta.updatedAt,
          position: meta.position,
        );
      }
    }
    if (!mounted) return;
    final changed = await openNoteEditor(
      context,
      note: note,
      itemId: widget.item.id,
      itemName: widget.item.name,
      environmentId: widget.environmentId,
      readOnly: !widget.perms.canWrite,
      canDelete: widget.perms.canDelete,
    );
    if (changed == true) widget.onChanged();
  }

  Future<void> _delete(NoteMeta n) async {
    final ok = await showConfirmDialog(
      context,
      title: 'Delete "${n.title}"?',
      message: 'Are you sure you want to permanently delete this note?',
      confirmLabel: 'Delete note',
    );
    if (!ok || !mounted) return;
    try {
      await SecwetScope.read(context).api.deleteNote(n.id);
      widget.onChanged();
    } catch (e) {
      if (mounted) showError(context, e, "Couldn't delete this note.");
    }
  }

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    final notes = widget.notes;
    final q = _search.text.trim().toLowerCase();
    final filtered = [
      for (final n in notes)
        if (q.isEmpty || n.title.toLowerCase().contains(q) || n.snippet.toLowerCase().contains(q)) n,
    ];
    final newButton = widget.perms.canWrite
        ? SecwetButton(label: 'New note', icon: SecwetIcons.plus, onPressed: () => _open(null))
        : null;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        if (notes.isNotEmpty || q.isNotEmpty) ...[
          Row(
            children: [
              Expanded(child: SearchField(hint: 'Search notes...', controller: _search, onChanged: (_) => setState(() {}))),
              if (widget.perms.canWrite) ...[
                const SizedBox(width: SecwetSpace.s2),
                SecwetIconButton(icon: SecwetIcons.plus, label: 'New note', filled: true, onPressed: () => _open(null)),
              ],
            ],
          ),
          const SizedBox(height: SecwetSpace.s3),
        ],
        if (notes.isEmpty)
          EmptyState(
            icon: SecwetIcons.pencil,
            title: 'No rich-text notes yet',
            body: 'Create formatted notes with headings, tables, code blocks, and lists.',
            action: newButton,
          )
        else if (filtered.isEmpty)
          EmptyState(icon: SecwetIcons.search, title: 'No matching notes', body: 'No notes matching "${_search.text}".')
        else
          for (final n in filtered)
            Padding(
              padding: const EdgeInsets.only(bottom: SecwetSpace.s3),
              child: Tappable(
                label: n.title,
                onTap: () => _open(n),
                child: Container(
                  padding: const EdgeInsets.fromLTRB(14, 10, 6, 12),
                  decoration: BoxDecoration(
                    color: p.surface,
                    border: Border.all(color: p.border),
                    borderRadius: BorderRadius.circular(SecwetRadius.card),
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: [
                          Expanded(
                            child: Text(n.title, maxLines: 1, overflow: TextOverflow.ellipsis, style: SecwetText.md(p, weight: FontWeight.w600)),
                          ),
                          if (widget.perms.canDelete)
                            SecwetIconButton(icon: SecwetIcons.trash, label: 'Delete ${n.title}', small: true, onPressed: () => _delete(n))
                          else
                            const SizedBox(height: SecwetControl.height),
                        ],
                      ),
                      Padding(
                        padding: const EdgeInsets.only(right: 8),
                        child: Text(
                          n.snippet.isEmpty ? 'Empty note' : n.snippet,
                          maxLines: 3,
                          overflow: TextOverflow.ellipsis,
                          style: SecwetText.md(p, color: p.textSecondary),
                        ),
                      ),
                      const SizedBox(height: SecwetSpace.s2),
                      Text('Updated ${formatAgo(n.updatedAt)}', style: SecwetText.xs(p)),
                    ],
                  ),
                ),
              ),
            ),
      ],
    );
  }
}
