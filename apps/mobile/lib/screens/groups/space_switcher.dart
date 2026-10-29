import 'package:flutter/widgets.dart';

import '../../app/shell.dart';
import '../../core/secwet_api.dart';
import '../../theme/secwet_theme.dart';
import '../../theme/secwet_tokens.dart';
import '../../widgets/controls.dart';
import '../../widgets/icon.dart';
import '../../widgets/layout.dart';
import '../../widgets/overlays.dart';
import '../sharing/share_screen.dart';
import '../sharing/sharing_screen.dart';
import 'common.dart';
import 'workspace_model.dart';

/// Icon of a space: its own, else a person for Personal and a folder for the rest.
SecwetIcons spaceIcon(Space? s) {
  for (final i in SecwetIcons.values) {
    if (i.name == s?.icon) return i;
  }
  return s?.isDefault ?? false ? SecwetIcons.user : SecwetIcons.folder;
}

/// The space switcher at the top of the Groups tab (desktop layout/SpaceSwitcher):
/// the current space; tapping it lists the spaces with their group counts,
/// Global, and New space, each space with Edit, Share, Members and Delete.
class SpaceSwitcher extends StatelessWidget {
  const SpaceSwitcher({super.key, required this.model});

  final WorkspaceModel model;

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    final global = model.activeSpaceId == null;
    final name = global ? 'Global' : (model.activeSpace?.name ?? 'Personal');
    return Tappable(
      label: 'Current space: $name',
      onTap: () => showSecwetDialog<void>(context, builder: (_) => _SpaceSheet(model: model, outer: context)),
      child: Container(
        height: SecwetControl.touchTarget,
        padding: const EdgeInsets.symmetric(horizontal: SecwetSpace.s3),
        decoration: BoxDecoration(
          color: InputSurface.background(context),
          border: Border.all(color: p.borderStrong),
          borderRadius: BorderRadius.circular(SecwetRadius.control),
        ),
        child: Row(
          children: [
            SecwetIcon(global ? SecwetIcons.globe : spaceIcon(model.activeSpace), size: 16, color: p.textPrimary),
            const SizedBox(width: SecwetSpace.s2),
            Expanded(
              child: Text(name, maxLines: 1, overflow: TextOverflow.ellipsis, style: SecwetText.md(p, weight: FontWeight.w500)),
            ),
            SecwetIcon(SecwetIcons.chevronDown, size: 16, color: p.textTertiary),
          ],
        ),
      ),
    );
  }
}

class _SpaceSheet extends StatelessWidget {
  const _SpaceSheet({required this.model, required this.outer});

  final WorkspaceModel model;

  /// The Groups screen's context, for pushing screens and dialogs after the sheet closes.
  final BuildContext outer;

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: model,
      builder: (context, _) {
        final global = model.activeSpaceId == null;
        void pick(String? id) {
          model.selectSpace(id);
          Navigator.of(context).pop();
        }

        return SecwetDialog(
          title: 'Spaces',
          children: [
            SecwetCard(
              children: [
                for (final s in model.spaces)
                  _SpaceRow(
                    icon: spaceIcon(s),
                    name: s.name,
                    count: s.groupsCount,
                    selected: !global && s.id == model.activeSpaceId,
                    onTap: () => pick(s.id),
                    menu: _menuFor(context, s),
                  ),
                _SpaceRow(
                  icon: SecwetIcons.globe,
                  name: 'Global',
                  count: model.groups.length,
                  selected: global,
                  onTap: () => pick(null),
                ),
              ],
            ),
            if (model.canCreateSpaceHere)
              SecwetButton(
                label: 'New space…',
                icon: SecwetIcons.plus,
                variant: ButtonVariant.secondary,
                expand: true,
                onPressed: () {
                  Navigator.of(context).pop();
                  showSpaceDialog(outer, model: model);
                },
              ),
          ],
        );
      },
    );
  }

  List<MenuEntry> _menuFor(BuildContext sheet, Space s) {
    final canEdit = model.canCreateSpaceHere;
    final canShare = model.canShareSpace(s);
    final canMembers = model.canManageMembersHere && canShare;
    final canDelete = !s.isDefault && canEdit;
    void close() => Navigator.of(sheet).pop();
    return [
      if (canEdit)
        MenuEntry('Edit space', icon: SecwetIcons.pencil, onSelected: () {
          close();
          showSpaceDialog(outer, model: model, space: s);
        }),
      if (canShare)
        MenuEntry('Share space…', icon: SecwetIcons.user, onSelected: () {
          close();
          pushScreen(
            outer,
            ShareScreen(
              spaces: [for (final x in model.spaces) if (model.canShareSpace(x)) x],
              initialSpaceId: s.id,
              access: model.access,
            ),
          );
        }),
      if (canMembers)
        MenuEntry('Members…', icon: SecwetIcons.users, onSelected: () {
          close();
          pushScreen(outer, SharingScreen(spaceId: s.id));
        }),
      if (canDelete)
        MenuEntry('Delete space', icon: SecwetIcons.trash, danger: true, onSelected: () {
          close();
          confirmDeleteSpace(outer, model, s);
        }),
    ];
  }
}

class _SpaceRow extends StatelessWidget {
  const _SpaceRow({
    required this.icon,
    required this.name,
    required this.count,
    required this.selected,
    required this.onTap,
    this.menu = const [],
  });

  final SecwetIcons icon;
  final String name;
  final int count;
  final bool selected;
  final VoidCallback onTap;
  final List<MenuEntry> menu;

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    return Container(
      color: selected ? p.accentTintSoft : null,
      child: Row(
        children: [
          Expanded(
            child: Tappable(
              label: name,
              selected: selected,
              onTap: onTap,
              child: SizedBox(
                height: SecwetControl.touchTarget,
                child: Padding(
                  padding: const EdgeInsets.only(left: 14),
                  child: Row(
                    children: [
                      SecwetIcon(icon, size: 16, color: selected ? p.accent : p.textSecondary),
                      const SizedBox(width: 10),
                      Flexible(
                        child: Text(
                          name,
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: SecwetText.md(p, color: selected ? p.textPrimary : p.textSecondary),
                        ),
                      ),
                      const SizedBox(width: SecwetSpace.s2),
                      _Count(count),
                      const SizedBox(width: SecwetSpace.s2),
                    ],
                  ),
                ),
              ),
            ),
          ),
          if (menu.isNotEmpty)
            SecwetMenuButton(entries: menu, label: 'Options for $name')
          else
            const SizedBox(width: SecwetSpace.s2),
        ],
      ),
    );
  }
}

class _Count extends StatelessWidget {
  const _Count(this.count);

  final int count;

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6),
      decoration: BoxDecoration(
        color: p.surface,
        border: Border.all(color: p.border),
        borderRadius: BorderRadius.circular(SecwetRadius.count),
      ),
      child: Text(
        '$count',
        style: TextStyle(
          fontSize: SecwetFontSize.xs,
          height: 16 / SecwetFontSize.xs,
          color: p.textTertiary,
          fontFeatures: const [FontFeature.tabularFigures()],
        ),
      ),
    );
  }
}

const _spaceIcons = [
  Choice(SecwetIcons.briefcase, 'Work'),
  Choice(SecwetIcons.user, 'Personal'),
  Choice(SecwetIcons.folder, 'Folder'),
  Choice(SecwetIcons.globe, 'Global'),
  Choice(SecwetIcons.layers, 'Layers'),
  Choice(SecwetIcons.key, 'Security'),
];

/// New Space (no [space]) or Edit Space dialog (desktop NewSpaceDialog / EditSpaceDialog).
Future<void> showSpaceDialog(BuildContext context, {required WorkspaceModel model, Space? space}) =>
    showSecwetDialog<void>(context, builder: (_) => _SpaceDialog(model: model, space: space, outer: context));

class _SpaceDialog extends StatefulWidget {
  const _SpaceDialog({required this.model, this.space, required this.outer});

  final WorkspaceModel model;
  final Space? space;
  final BuildContext outer;

  @override
  State<_SpaceDialog> createState() => _SpaceDialogState();
}

class _SpaceDialogState extends State<_SpaceDialog> {
  late final _name = TextEditingController(text: widget.space?.name ?? '');
  late SecwetIcons _icon = widget.space == null
      ? SecwetIcons.briefcase
      : (SecwetIcons.values.where((i) => i.name == widget.space!.icon).firstOrNull ??
          (widget.space!.isDefault ? SecwetIcons.user : SecwetIcons.briefcase));
  String? _error;
  bool _busy = false;

  bool get _editing => widget.space != null;

  @override
  void dispose() {
    _name.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    final trimmed = _name.text.trim();
    if (trimmed.isEmpty) return setState(() => _error = 'Space name cannot be empty');
    if (trimmed.length > 64) return setState(() => _error = 'Space name cannot exceed 64 characters');
    setState(() => _busy = true);
    try {
      if (_editing) {
        await widget.model.api.renameSpace(widget.space!.id, trimmed, icon: _icon.name);
        await widget.model.reload();
      } else {
        await widget.model.createSpace(trimmed, _icon.name);
      }
      if (mounted) Navigator.of(context).pop();
    } catch (e) {
      if (mounted) {
        setState(() {
          _busy = false;
          _error = errorText(e, _editing ? 'Failed to save space' : 'Failed to create space');
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    final space = widget.space;
    return SecwetDialog(
      title: _editing ? 'Edit Space' : 'New Space',
      description: _editing
          ? 'Update space name and icon.'
          : 'Create a top-level workspace container to organize your groups, projects, and secrets.',
      actions: [
        SecwetButton(label: 'Cancel', variant: ButtonVariant.secondary, onPressed: _busy ? null : () => Navigator.of(context).pop()),
        SecwetButton(
          label: _busy ? (_editing ? 'Saving...' : 'Creating...') : (_editing ? 'Save Changes' : 'Create Space'),
          onPressed: _busy || _name.text.trim().isEmpty ? null : _submit,
        ),
      ],
      children: [
        SecwetField(
          label: 'Space Name',
          controller: _name,
          hint: 'e.g. Work, Freelance, Family, Startup',
          error: _error,
          autofocus: true,
          onChanged: (_) => setState(() => _error = null),
          onSubmitted: (_) => _submit(),
        ),
        Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Icon', style: SecwetText.sm(p, color: p.textSecondary).copyWith(fontWeight: FontWeight.w500)),
            const SizedBox(height: SecwetSpace.s2),
            Wrap(
              spacing: SecwetSpace.s2,
              runSpacing: SecwetSpace.s2,
              children: [
                for (final c in _spaceIcons)
                  Tappable(
                    label: c.label,
                    selected: c.value == _icon,
                    onTap: () => setState(() => _icon = c.value),
                    child: Container(
                      width: SecwetControl.touchTarget,
                      height: SecwetControl.touchTarget,
                      alignment: Alignment.center,
                      decoration: BoxDecoration(
                        color: c.value == _icon ? p.accentTintSoft : p.bg,
                        border: Border.all(color: c.value == _icon ? p.accent : p.borderStrong),
                        borderRadius: BorderRadius.circular(SecwetRadius.control),
                      ),
                      child: SecwetIcon(c.value, size: 18, color: c.value == _icon ? p.accent : p.textSecondary),
                    ),
                  ),
              ],
            ),
          ],
        ),
        if (_editing && !space!.isDefault && widget.model.canCreateSpaceHere)
          Align(
            alignment: Alignment.centerLeft,
            child: SecwetButton(
              label: 'Delete Space',
              variant: ButtonVariant.danger,
              onPressed: _busy
                  ? null
                  : () {
                      Navigator.of(context).pop();
                      confirmDeleteSpace(widget.outer, widget.model, space);
                    },
            ),
          ),
      ],
    );
  }
}

/// Typed-name confirmation, then deletes the space; its groups move to Personal.
Future<void> confirmDeleteSpace(BuildContext context, WorkspaceModel model, Space space) async {
  final ok = await showConfirmDialog(
    context,
    title: 'Delete ${space.name}?',
    message: 'Its groups move to your ${model.personalSpace?.name ?? 'Personal'} space.',
    confirmLabel: 'Delete space',
    typedName: space.name,
  );
  if (!ok) return;
  try {
    await model.deleteSpace(space.id);
  } catch (e) {
    if (context.mounted) showError(context, e, "Couldn't delete this space. Try again.");
  }
}
