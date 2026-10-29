import 'package:flutter/widgets.dart';

import '../../app/shell.dart';
import '../../core/secwet_api.dart';
import '../../theme/secwet_theme.dart';
import '../../theme/secwet_tokens.dart';
import '../../widgets/controls.dart';
import '../../widgets/icon.dart';
import '../../widgets/layout.dart';
import '../../widgets/overlays.dart';
import 'common.dart';
import 'group_dialogs.dart';
import 'item_screen.dart';
import 'workspace_model.dart';

/// A group's entries as cards with the desktop pills (screens/groups/GroupScreen.tsx),
/// with search, New, and Rename, reorder, move to space and Delete in the menu.
class GroupScreen extends StatefulWidget {
  const GroupScreen({super.key, required this.groupId});

  final String groupId;

  @override
  State<GroupScreen> createState() => _GroupScreenState();
}

class _GroupScreenState extends State<GroupScreen> {
  WorkspaceModel? _model;
  final _search = TextEditingController();

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    _model ??= WorkspaceModel.of(context)..ensureLoaded();
  }

  @override
  void dispose() {
    _search.dispose();
    super.dispose();
  }

  Future<void> _open(Item item) async {
    _model!.selectItem(item.id);
    await pushScreen(context, ItemScreen(itemId: item.id));
  }

  Future<void> _newItem(Group group) async {
    final item = await showNewItemDialog(context, _model!, groups: [group], initialGroupId: group.id);
    if (item != null && mounted) await _open(item);
  }

  Future<void> _rename(Group group) async {
    final model = _model!;
    await showNameDialog(
      context,
      title: 'Rename',
      label: 'Name',
      initial: group.name,
      confirmLabel: 'Rename',
      validate: (v) {
        final t = v.trim();
        if (t.isEmpty) return 'Enter a name.';
        final siblings = [for (final g in model.groups) if (g.spaceId == group.spaceId) g];
        if (siblings.any((g) => g.id != group.id && g.name.toLowerCase() == t.toLowerCase())) {
          return 'A category called "$t" already exists.';
        }
        return null;
      },
      onSubmit: (name) async {
        await model.api.renameGroup(group.id, name, icon: group.icon);
        await model.reload();
      },
    );
  }

  Future<void> _delete(Group group, int count) async {
    final model = _model!;
    final ok = await showConfirmDialog(
      context,
      title: 'Delete "${group.name}"?',
      message: 'Deleting ${group.name} will also permanently delete all ${plural(count, 'entry')} and their '
          'secrets, assets, and notes.\n\nThis action cannot be undone.',
      confirmLabel: 'Delete',
      typedName: count > 0 ? group.name : null,
    );
    if (!ok) return;
    try {
      await model.api.deleteGroup(group.id);
      await model.reload();
      if (mounted) Navigator.of(context).pop();
    } catch (e) {
      if (mounted) showError(context, e, "Couldn't delete this group. Try again.");
    }
  }

  Future<void> _move(Group group, int direction) async {
    try {
      await _model!.moveGroup(group.id, direction);
    } catch (e) {
      if (mounted) showError(context, e, "Couldn't reorder groups. Try again.");
    }
  }

  @override
  Widget build(BuildContext context) {
    final model = _model!;
    return ListenableBuilder(
      listenable: Listenable.merge([model, _search]),
      builder: (context, _) {
        final group = model.groupById(widget.groupId);
        if (group == null) {
          return ShellPage(
            topBar: const TopBar(title: 'Group'),
            children: [
              if (model.loaded) const EmptyState(icon: SecwetIcons.folder, title: 'This group no longer exists'),
            ],
          );
        }
        final canManage = model.groupPerms(group.id).canManage;
        final items = model.itemsOf(group.id);
        final q = _search.text.trim().toLowerCase();
        final filtered = q.isEmpty
            ? items
            : [
                for (final i in items)
                  if (i.name.toLowerCase().contains(q) || (i.description?.toLowerCase().contains(q) ?? false)) i,
              ];
        final siblings = [for (final g in model.groups) if (g.spaceId == group.spaceId) g]
          ..sort((a, b) => a.position.compareTo(b.position));
        final index = siblings.indexWhere((g) => g.id == group.id);
        final canMove = model.manageableSpaces.any((s) => s.id != group.spaceId);

        return ShellPage(
          topBar: TopBar(
            title: group.name,
            crumbs: [Crumb('Groups', () => openCrumb(context))],
            actions: [
              if (canManage) ...[
                SecwetButton(label: 'New', icon: SecwetIcons.plus, small: true, onPressed: () => _newItem(group)),
                SecwetMenuButton(
                  label: 'Actions',
                  entries: [
                    MenuEntry('Rename', icon: SecwetIcons.pencil, onSelected: () => _rename(group)),
                    if (index > 0) MenuEntry('Move up', icon: SecwetIcons.layers, onSelected: () => _move(group, -1)),
                    if (index >= 0 && index < siblings.length - 1)
                      MenuEntry('Move down', icon: SecwetIcons.layers, onSelected: () => _move(group, 1)),
                    if (canMove)
                      MenuEntry('Move to space…', icon: SecwetIcons.folder, onSelected: () => showMoveGroupDialog(context, model, group)),
                    const MenuEntry.separator(),
                    MenuEntry('Delete', icon: SecwetIcons.trash, danger: true, onSelected: () => _delete(group, items.length)),
                  ],
                ),
              ],
            ],
          ),
          children: [
            if (model.readOnly) const UnlinkedNotice(),
            if (items.isNotEmpty) ...[
              SearchField(hint: 'Search ${group.name}...', controller: _search),
              const SizedBox(height: SecwetSpace.s3),
            ],
            if (items.isEmpty)
              EmptyState(
                icon: SecwetIcons.folder,
                title: 'No entries yet',
                body: canManage
                    ? 'Store secrets, encrypted assets, and notes for your apps and services here.'
                    : 'Nothing here is shared with you yet.',
                action: canManage
                    ? SecwetButton(label: 'New', icon: SecwetIcons.plus, onPressed: () => _newItem(group))
                    : null,
              )
            else if (filtered.isEmpty)
              EmptyState(icon: SecwetIcons.search, title: 'No entries found', body: 'No entries matching "${_search.text}".')
            else
              SecwetCard(
                children: [for (final item in filtered) ItemCardRow(item: item, onTap: () => _open(item))],
              ),
          ],
        );
      },
    );
  }
}

/// An entry with its description and pills: envs (accent), secrets, assets, notes.
class ItemCardRow extends StatelessWidget {
  const ItemCardRow({super.key, required this.item, required this.onTap});

  final Item item;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    return ListRow(
      title: item.name,
      meta: item.description,
      alignTop: true,
      leading: itemTile(item.name),
      below: PillRow(
        children: [
          if (item.environmentsCount > 0) SecwetBadge(plural(item.environmentsCount, 'env'), tone: BadgeTone.accent),
          SecwetBadge(plural(item.secretsCount, 'secret')),
          if (item.assetsCount > 0) SecwetBadge(plural(item.assetsCount, 'asset')),
          if (item.notesCount > 0) SecwetBadge(plural(item.notesCount, 'note')),
        ],
      ),
      trailing: Padding(
        padding: const EdgeInsets.only(top: 4),
        child: SecwetIcon(SecwetIcons.chevronRight, size: 16, color: context.palette.textTertiary),
      ),
      onTap: onTap,
    );
  }
}
