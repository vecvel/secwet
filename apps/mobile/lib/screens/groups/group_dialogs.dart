import 'package:flutter/widgets.dart';

import '../../core/secwet_api.dart';
import '../../widgets/controls.dart';
import '../../widgets/layout.dart';
import '../../widgets/overlays.dart';
import 'common.dart';
import 'space_switcher.dart';
import 'workspace_model.dart';

/// New Group dialog: name and parent space. Resolves
/// with the created group.
Future<Group?> showNewGroupDialog(BuildContext context, WorkspaceModel model) =>
    showSecwetDialog<Group>(context, builder: (_) => _NewGroupDialog(model: model));

class _NewGroupDialog extends StatefulWidget {
  const _NewGroupDialog({required this.model});

  final WorkspaceModel model;

  @override
  State<_NewGroupDialog> createState() => _NewGroupDialogState();
}

class _NewGroupDialogState extends State<_NewGroupDialog> {
  final _name = TextEditingController();
  late String? _spaceId = widget.model.defaultSpaceForNewGroup;
  String? _error;
  bool _busy = false;

  @override
  void dispose() {
    _name.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    final trimmed = _name.text.trim();
    if (trimmed.isEmpty) return setState(() => _error = 'Name cannot be empty');
    final siblings = [for (final g in widget.model.groups) if (g.spaceId == _spaceId) g];
    if (siblings.any((g) => g.name.toLowerCase() == trimmed.toLowerCase())) {
      return setState(() => _error = 'A group called "$trimmed" already exists in this space.');
    }
    setState(() => _busy = true);
    try {
      final group = await widget.model.createGroup(trimmed, _spaceId);
      if (mounted) Navigator.of(context).pop(group);
    } catch (e) {
      if (mounted) {
        setState(() {
          _busy = false;
          _error = errorText(e, 'Failed to create');
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final spaces = widget.model.manageableSpaces;
    return SecwetDialog(
      title: 'New Group',
      description: 'Create a section to organize your projects, credentials, and services.',
      actions: [
        SecwetButton(label: 'Cancel', variant: ButtonVariant.secondary, onPressed: _busy ? null : () => Navigator.of(context).pop()),
        SecwetButton(label: _busy ? 'Creating...' : 'Create Group', onPressed: _busy || _name.text.trim().isEmpty ? null : _submit),
      ],
      children: [
        SecwetField(
          label: 'Name',
          controller: _name,
          hint: 'e.g. Backend Services, Mobile Apps, Infrastructure',
          error: _error,
          autofocus: true,
          onChanged: (_) => setState(() => _error = null),
          onSubmitted: (_) => _submit(),
        ),
        if (spaces.isNotEmpty)
          ChoiceField<String?>(
            label: 'Parent Space',
            value: _spaceId,
            choices: [for (final s in spaces) Choice(s.id, s.name, icon: spaceIcon(s))],
            onChanged: (v) => setState(() {
              _spaceId = v;
              _error = null;
            }),
          ),
      ],
    );
  }
}

/// New entry dialog: group, name, description; no
/// environments. Resolves with the created item.
Future<Item?> showNewItemDialog(
  BuildContext context,
  WorkspaceModel model, {
  required List<Group> groups,
  String? initialGroupId,
}) =>
    showSecwetDialog<Item>(
      context,
      builder: (_) => _NewItemDialog(model: model, groups: groups, initialGroupId: initialGroupId),
    );

class _NewItemDialog extends StatefulWidget {
  const _NewItemDialog({required this.model, required this.groups, this.initialGroupId});

  final WorkspaceModel model;
  final List<Group> groups;
  final String? initialGroupId;

  @override
  State<_NewItemDialog> createState() => _NewItemDialogState();
}

class _NewItemDialogState extends State<_NewItemDialog> {
  final _name = TextEditingController();
  final _description = TextEditingController();
  late String? _groupId = widget.groups.any((g) => g.id == widget.initialGroupId)
      ? widget.initialGroupId
      : (widget.groups.isEmpty ? null : widget.groups.first.id);
  String? _error;
  bool _busy = false;

  @override
  void dispose() {
    _name.dispose();
    _description.dispose();
    super.dispose();
  }

  String get _groupName => widget.groups.where((g) => g.id == _groupId).firstOrNull?.name ?? 'this group';

  Future<void> _submit() async {
    final trimmed = _name.text.trim();
    if (trimmed.isEmpty) return setState(() => _error = 'Enter a name.');
    final groupId = _groupId;
    if (groupId == null) return;
    if (widget.model.itemsOf(groupId).any((i) => i.name.trim().toLowerCase() == trimmed.toLowerCase())) {
      return setState(() => _error = 'An entry called "$trimmed" already exists under $_groupName.');
    }
    setState(() => _busy = true);
    try {
      final desc = _description.text.trim();
      final item = await widget.model.api.createItem(groupId, trimmed, description: desc.isEmpty ? null : desc);
      await widget.model.reload();
      if (mounted) Navigator.of(context).pop(item);
    } catch (e) {
      if (mounted) {
        setState(() {
          _busy = false;
          _error = errorText(e, 'Failed to create');
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return SecwetDialog(
      title: 'New',
      description: 'Add an entry to $_groupName.',
      actions: [
        SecwetButton(label: 'Cancel', variant: ButtonVariant.secondary, onPressed: _busy ? null : () => Navigator.of(context).pop()),
        SecwetButton(label: 'Create', onPressed: _busy ? null : _submit),
      ],
      children: [
        if (widget.groups.length > 1)
          ChoiceField<String?>(
            label: 'Group',
            value: _groupId,
            choices: [for (final g in widget.groups) Choice(g.id, g.name)],
            onChanged: (v) => setState(() {
              _groupId = v;
              _error = null;
            }),
          ),
        SecwetField(
          label: 'Name',
          controller: _name,
          hint: 'e.g. Payments API, Client App, Credentials',
          error: _error,
          autofocus: widget.groups.length <= 1,
          autocorrect: false,
          onChanged: (_) {
            if (_error != null) setState(() => _error = null);
          },
        ),
        SecwetField(
          label: 'Description (optional)',
          controller: _description,
          hint: 'Brief summary or purpose',
          onSubmitted: (_) => _submit(),
        ),
      ],
    );
  }
}

/// Rename an entry and its description, with the
/// duplicate-name check inside its group.
Future<void> showEditItemDialog(BuildContext context, WorkspaceModel model, Item item) =>
    showSecwetDialog<void>(context, builder: (_) => _EditItemDialog(model: model, item: item));

class _EditItemDialog extends StatefulWidget {
  const _EditItemDialog({required this.model, required this.item});

  final WorkspaceModel model;
  final Item item;

  @override
  State<_EditItemDialog> createState() => _EditItemDialogState();
}

class _EditItemDialogState extends State<_EditItemDialog> {
  late final _name = TextEditingController(text: widget.item.name);
  late final _description = TextEditingController(text: widget.item.description ?? '');
  String? _error;
  bool _saving = false;

  @override
  void dispose() {
    _name.dispose();
    _description.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    final trimmed = _name.text.trim();
    if (trimmed.isEmpty) return setState(() => _error = 'Enter a name.');
    final dup = widget.model
        .itemsOf(widget.item.groupId)
        .any((i) => i.id != widget.item.id && i.name.trim().toLowerCase() == trimmed.toLowerCase());
    if (dup) return setState(() => _error = 'An entry called "$trimmed" already exists in this group.');
    setState(() => _saving = true);
    try {
      final desc = _description.text.trim();
      await widget.model.api.renameItem(widget.item.id, trimmed, description: desc.isEmpty ? null : desc);
      await widget.model.reload();
      if (mounted) Navigator.of(context).pop();
    } catch (e) {
      if (mounted) {
        setState(() {
          _saving = false;
          _error = errorText(e, 'Failed to save');
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return SecwetDialog(
      title: 'Rename',
      description: 'Update details for this entry.',
      actions: [
        SecwetButton(label: 'Cancel', variant: ButtonVariant.secondary, onPressed: _saving ? null : () => Navigator.of(context).pop()),
        SecwetButton(label: _saving ? 'Saving' : 'Save', onPressed: _saving ? null : _submit),
      ],
      children: [
        SecwetField(
          label: 'Name',
          controller: _name,
          hint: 'e.g. Payments API, Client App',
          error: _error,
          autofocus: true,
          autocorrect: false,
          onChanged: (_) {
            if (_error != null) setState(() => _error = null);
          },
        ),
        SecwetField(
          label: 'Description (optional)',
          controller: _description,
          hint: 'Brief summary or purpose',
          onSubmitted: (_) => _submit(),
        ),
      ],
    );
  }
}

/// Moves a group to another space the user can manage.
Future<void> showMoveGroupDialog(BuildContext context, WorkspaceModel model, Group group) =>
    showSecwetDialog<void>(context, builder: (_) => _MoveGroupDialog(model: model, group: group));

class _MoveGroupDialog extends StatefulWidget {
  const _MoveGroupDialog({required this.model, required this.group});

  final WorkspaceModel model;
  final Group group;

  @override
  State<_MoveGroupDialog> createState() => _MoveGroupDialogState();
}

class _MoveGroupDialogState extends State<_MoveGroupDialog> {
  late final List<Space> _targets = [
    for (final s in widget.model.manageableSpaces)
      if (s.id != widget.group.spaceId) s,
  ];
  late String? _spaceId = _targets.isEmpty ? null : _targets.first.id;
  String? _error;
  bool _busy = false;

  Future<void> _submit() async {
    final target = _spaceId;
    if (target == null) return;
    final name = widget.group.name.toLowerCase();
    if (widget.model.groups.any((g) => g.spaceId == target && g.name.toLowerCase() == name)) {
      final space = widget.model.spaceById(target)?.name ?? 'that space';
      return setState(() => _error = 'A group called "${widget.group.name}" already exists in $space.');
    }
    setState(() => _busy = true);
    try {
      await widget.model.api.moveGroupToSpace(widget.group.id, target);
      await widget.model.reload();
      if (mounted) Navigator.of(context).pop();
    } catch (e) {
      if (mounted) {
        setState(() {
          _busy = false;
          _error = errorText(e, "Couldn't move this group. Try again.");
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return SecwetDialog(
      title: 'Move ${widget.group.name}',
      description: 'The group keeps its entries, secrets, assets and notes.',
      actions: [
        SecwetButton(label: 'Cancel', variant: ButtonVariant.secondary, onPressed: _busy ? null : () => Navigator.of(context).pop()),
        SecwetButton(label: 'Move', onPressed: _busy || _spaceId == null ? null : _submit),
      ],
      children: [
        if (_targets.isEmpty)
          const SecwetNotice(text: 'There is no other space you can move it to.')
        else
          ChoiceField<String?>(
            label: 'Move to',
            value: _spaceId,
            error: _error,
            choices: [for (final s in _targets) Choice(s.id, s.name, icon: spaceIcon(s))],
            onChanged: (v) => setState(() {
              _spaceId = v;
              _error = null;
            }),
          ),
      ],
    );
  }
}

/// Icon tile used by group and item rows.
Widget itemTile(String name, {bool selected = false}) => IconTile(initial: initialOf(name), selected: selected);
