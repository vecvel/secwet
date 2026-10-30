import 'package:flutter/widgets.dart';

import '../../app/shell.dart';
import '../../core/secwet_api.dart';
import '../../theme/secwet_theme.dart';
import '../../theme/secwet_tokens.dart';
import '../../widgets/controls.dart';
import '../../widgets/icon.dart';
import '../../widgets/layout.dart';
import 'common.dart';
import 'group_dialogs.dart';
import 'group_screen.dart';
import 'item_screen.dart';
import 'space_switcher.dart';
import 'workspace_model.dart';

/// The Groups tab: the desktop sidebar as a screen on
/// the sidebar color. Space switcher, then each group of the active space
/// with its entries, then New. Group and entry screens push inside the tab.
class GroupsScreen extends StatefulWidget {
  const GroupsScreen({super.key});

  @override
  State<GroupsScreen> createState() => _GroupsScreenState();
}

class _GroupsScreenState extends State<GroupsScreen> {
  WorkspaceModel? _model;

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    if (_model == null) {
      _model = WorkspaceModel.of(context);
      _model!.ensureLoaded();
    }
  }

  Future<void> _openItem(Item item) async {
    final model = _model!;
    model.selectItem(item.id);
    await pushScreen(context, ItemScreen(itemId: item.id));
  }

  Future<void> _newItem(String groupId) async {
    final model = _model!;
    final item = await showNewItemDialog(context, model, groups: model.visibleGroups, initialGroupId: groupId);
    if (item != null && mounted) await _openItem(item);
  }

  Future<void> _newGroup() async {
    final group = await showNewGroupDialog(context, _model!);
    if (group != null && mounted) await pushScreen(context, GroupScreen(groupId: group.id), name: groupRouteName(group.id));
  }

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    final model = _model!;
    return ListenableBuilder(
      listenable: model,
      builder: (context, _) {
        final groups = model.visibleGroups;
        // The sidebar color is a surface: its switcher and New row use the
        // page background so they stand out, like the inputs in Settings.
        return InputSurface(
          child: ShellPage(
          background: p.sidebarBg,
          topBar: const TopBar(title: 'Groups'),
          children: [
            if (model.spaces.isNotEmpty) SpaceSwitcher(model: model),
            if (model.readOnly) ...[const SizedBox(height: SecwetSpace.s3), const UnlinkedNotice()],
            for (final g in groups) ..._group(context, model, g),
            if (model.loaded && groups.isEmpty && !model.canCreateGroupHere)
              const Padding(
                padding: EdgeInsets.only(top: SecwetSpace.s4),
                child: EmptyState(
                  icon: SecwetIcons.folder,
                  title: 'No groups in this space',
                  body: 'Nothing in this space is shared with you yet.',
                ),
              ),
            if (model.canCreateGroupHere) _NewRow(onTap: _newGroup),
          ],
          ),
        );
      },
    );
  }

  List<Widget> _group(BuildContext context, WorkspaceModel model, Group g) {
    final p = context.palette;
    final items = model.itemsOf(g.id);
    final canAdd = model.groupPerms(g.id).canManage;
    return [
      Padding(
        // The 44 px row keeps the label where the old 32 px row with 14/2
        // padding put it.
        padding: const EdgeInsets.only(top: 8),
        child: Row(
          children: [
            Expanded(
              child: Tappable(
                label: 'View ${g.name}',
                onTap: () => pushScreen(context, GroupScreen(groupId: g.id), name: groupRouteName(g.id)),
                child: Container(
                  height: SecwetControl.touchTarget,
                  // Same left edge as the entry tiles below (6 px).
                  padding: const EdgeInsets.only(left: 6),
                  alignment: Alignment.centerLeft,
                  child: Text(g.name, maxLines: 1, overflow: TextOverflow.ellipsis, style: SecwetText.sm(p)),
                ),
              ),
            ),
            if (canAdd)
              SecwetIconButton(icon: SecwetIcons.plus, label: 'Add to ${g.name}', onPressed: () => _newItem(g.id)),
          ],
        ),
      ),
      for (final item in items)
        _NavRow(
          label: item.name,
          selected: item.id == model.selectedItemId,
          onTap: () => _openItem(item),
        ),
      if (items.isEmpty && canAdd)
        Tappable(
          label: 'Add to ${g.name}',
          onTap: () => _newItem(g.id),
          child: Container(
            height: _rowHeight,
            padding: const EdgeInsets.symmetric(horizontal: 10),
            child: Row(
              children: [
                SecwetIcon(SecwetIcons.plus, size: 12, color: p.textTertiary),
                const SizedBox(width: 6),
                Text('Add', style: SecwetText.sm(p)),
              ],
            ),
          ),
        ),
    ];
  }
}

/// Sidebar entry row: 36 px like the desktop sidebar, tile with the initial, name, chevron; selected
/// rows get the soft tint and a filled tile.
/// Entry rows in the Groups tab, as the desktop sidebar's `.item`.
const double _rowHeight = 36;

class _NavRow extends StatelessWidget {
  const _NavRow({required this.label, required this.selected, required this.onTap});

  final String label;
  final bool selected;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    return Tappable(
      label: label,
      selected: selected,
      onTap: onTap,
      child: Container(
        height: _rowHeight,
        // 24 px tile in a 36 px row: 6 px on every side of the tile.
        padding: const EdgeInsets.symmetric(horizontal: 6),
        decoration: BoxDecoration(
          color: selected ? p.accentTintSoft : null,
          borderRadius: BorderRadius.circular(SecwetRadius.control),
        ),
        child: Row(
          children: [
            itemTile(label, selected: selected),
            const SizedBox(width: 10),
            Expanded(
              child: Text(label, maxLines: 1, overflow: TextOverflow.ellipsis, style: SecwetText.body(p)),
            ),
            SecwetIcon(SecwetIcons.chevronRight, size: 16, color: p.textTertiary),
          ],
        ),
      ),
    );
  }
}

class _NewRow extends StatelessWidget {
  const _NewRow({required this.onTap});

  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    return Padding(
      padding: const EdgeInsets.only(top: SecwetSpace.s3),
      child: TouchTarget(child: Tappable(
        label: 'New',
        onTap: onTap,
        child: Container(
          height: MobileControl.height,
          padding: const EdgeInsets.symmetric(horizontal: 10),
          decoration: BoxDecoration(
            color: InputSurface.background(context),
            border: Border.all(color: p.borderStrong),
            borderRadius: BorderRadius.circular(SecwetRadius.control),
          ),
          child: Row(
            children: [
              SecwetIcon(SecwetIcons.plus, size: 16, color: p.textTertiary),
              const SizedBox(width: 10),
              Text('New', style: SecwetText.md(p, color: p.textTertiary)),
            ],
          ),
        ),
      )),
    );
  }
}
