import 'dart:async';

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
import 'access.dart';
import 'assets/assets_section.dart';
import 'common.dart';
import 'group_dialogs.dart';
import 'group_screen.dart';
import 'notes/notes_section.dart';
import 'secrets/secrets_section.dart';
import 'workspace_model.dart';

enum ContentTab { secrets, assets, notes }

/// An entry (desktop screens/items/ItemScreen.tsx): environment tabs
/// (General plus each environment, with rename and delete), Secrets / Assets /
/// Notes tabs with count pills, and the entry menu (Share, Rename, Add
/// environment, Delete). Roles decide every control.
class ItemScreen extends StatefulWidget {
  const ItemScreen({super.key, required this.itemId, this.environmentId, this.initialTab = ContentTab.secrets});

  final String itemId;

  /// Environment to open on (null: General).
  final String? environmentId;
  final ContentTab initialTab;

  @override
  State<ItemScreen> createState() => _ItemScreenState();
}

class _ItemScreenState extends State<ItemScreen> {
  WorkspaceModel? _model;
  StreamSubscription<SecwetEvent>? _changes;

  List<Environment> _environments = const [];
  List<SecretMeta> _secrets = const [];
  List<AssetMeta> _assets = const [];
  List<NoteMeta> _notes = const [];
  List<ActiveSession> _sessions = const [];
  bool _loaded = false;

  late String? _environmentId = widget.environmentId;
  late ContentTab _tab = widget.initialTab;

  SecwetApi get _api => _model!.api;

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    if (_model == null) {
      _model = WorkspaceModel.of(context)..ensureLoaded();
      _changes = _api.events.where((e) => e.isChanged).listen((_) => _load());
      _load();
    }
  }

  @override
  void dispose() {
    _changes?.cancel();
    super.dispose();
  }

  Future<void> _load() async {
    final id = widget.itemId;
    try {
      final results = await Future.wait([
        _api.environments(id),
        _api.secrets(itemId: id),
        _api.assets(id),
        _api.notes(id),
      ]);
      List<ActiveSession> sessions;
      try {
        sessions = await _api.activeSessions();
      } on SecwetException {
        sessions = const [];
      }
      if (!mounted) return;
      setState(() {
        _environments = results[0] as List<Environment>;
        _secrets = results[1] as List<SecretMeta>;
        _assets = results[2] as List<AssetMeta>;
        _notes = results[3] as List<NoteMeta>;
        _sessions = sessions;
        if (_environmentId != null && !_environments.any((e) => e.id == _environmentId)) _environmentId = null;
        _loaded = true;
      });
    } on SecwetException {
      // Locked or the entry is gone; the model and the gate handle both.
    }
  }

  /// Content of the open scope: General shows item-wide content, or
  /// everything when the entry has no environments.
  List<T> _scoped<T>(List<T> all, String? Function(T) env) => [
        for (final x in all)
          if (_environmentId == null ? (_environments.isEmpty || env(x) == null) : env(x) == _environmentId) x,
      ];

  Future<void> _afterChange([String? showEnvironmentId]) async {
    await _load();
    await _model!.reload();
    if (mounted && showEnvironmentId != _environmentId && _environments.any((e) => e.id == showEnvironmentId)) {
      setState(() => _environmentId = showEnvironmentId);
    }
  }

  Future<void> _addEnvironment(Item item) async {
    String? createdId;
    await showNameDialog(
      context,
      title: 'Add environment',
      label: 'Environment name',
      placeholder: 'e.g. Production, Staging, Development',
      confirmLabel: 'Add environment',
      validate: (v) {
        final t = v.trim();
        if (t.isEmpty) return 'Enter an environment name.';
        if (_environments.any((e) => e.name.toLowerCase() == t.toLowerCase())) return 'An environment called "$t" already exists.';
        return null;
      },
      onSubmit: (name) async => createdId = (await _api.addEnvironment(item.id, name)).id,
    );
    if (createdId != null) {
      await _afterChange();
      if (mounted) setState(() => _environmentId = createdId);
    }
  }

  Future<void> _renameEnvironment(Environment env) async {
    final renamed = await showNameDialog(
      context,
      title: 'Rename environment',
      label: 'Environment name',
      initial: env.name,
      confirmLabel: 'Rename',
      validate: (v) {
        final t = v.trim();
        if (t.isEmpty) return 'Enter an environment name.';
        if (_environments.any((e) => e.id != env.id && e.name.toLowerCase() == t.toLowerCase())) {
          return 'An environment called "$t" already exists.';
        }
        return null;
      },
      onSubmit: (name) => _api.renameEnvironment(env.id, name),
    );
    if (renamed != null) await _afterChange();
  }

  Future<void> _deleteEnvironment(Environment env) async {
    final preserve = await showSecwetDialog<bool>(context, builder: (_) => _DeleteEnvironmentDialog(env: env));
    if (preserve == null) return;
    try {
      await _api.deleteEnvironment(env.id, preserveContent: preserve);
      if (mounted) setState(() => _environmentId = null);
      await _afterChange();
    } catch (e) {
      if (mounted) showError(context, e, "Couldn't delete this environment.");
    }
  }

  Future<void> _deleteItem(Item item) async {
    final ok = await showConfirmDialog(
      context,
      title: 'Delete "${item.name}"?',
      message: 'Deleting ${item.name} will permanently delete all environments, secrets, assets, and notes inside it.'
          '\n\nThis action cannot be undone.',
      confirmLabel: 'Delete',
      typedName: item.name,
    );
    if (!ok) return;
    try {
      await _api.deleteItem(item.id);
      await _model!.reload();
      if (mounted) Navigator.of(context).pop();
    } catch (e) {
      if (mounted) showError(context, e, "Couldn't delete this entry.");
    }
  }

  @override
  Widget build(BuildContext context) {
    final model = _model!;
    return ListenableBuilder(
      listenable: model,
      builder: (context, _) {
        final item = model.itemById(widget.itemId);
        if (item == null) {
          return ShellPage(
            topBar: const TopBar(title: 'Entry'),
            children: [if (model.loaded) const EmptyState(icon: SecwetIcons.folder, title: 'This entry no longer exists')],
          );
        }
        return _body(context, model, item);
      },
    );
  }

  Widget _body(BuildContext context, WorkspaceModel model, Item item) {
    final p = context.palette;
    final group = model.groupById(item.groupId);
    final space = model.spaceById(group?.spaceId);
    final itemPerms = model.itemPerms(item);
    final scopePerms = model.scopePerms(item, _environmentId);
    final canShareHere = isShareableSpace(space) && (_environmentId != null ? scopePerms.canShare : itemPerms.canShare);

    final scopedSecrets = _scoped(_secrets, (s) => s.environmentId);
    final scopedAssets = _scoped(_assets, (a) => a.environmentId);
    final scopedNotes = _scoped(_notes, (n) => n.environmentId);
    final activeEnv = _environments.where((e) => e.id == _environmentId).firstOrNull;

    final menu = [
      if (canShareHere)
        MenuEntry(_environmentId != null ? 'Share this environment…' : 'Share this item…', icon: SecwetIcons.user,
            onSelected: () => pushScreen(
                  context,
                  ShareScreen(
                    spaces: [for (final s in model.spaces) if (model.canShareSpace(s)) s],
                    initialSpaceId: space!.id,
                    focus: _environmentId != null ? ShareFocus.environment(_environmentId!) : ShareFocus.item(item.id),
                    access: model.access,
                  ),
                )),
      if (itemPerms.canManage) ...[
        MenuEntry('Rename', icon: SecwetIcons.pencil, onSelected: () => showEditItemDialog(context, model, item)),
        MenuEntry('Add environment', icon: SecwetIcons.plus, onSelected: () => _addEnvironment(item)),
        const MenuEntry.separator(),
        MenuEntry('Delete', icon: SecwetIcons.trash, danger: true, onSelected: () => _deleteItem(item)),
      ],
    ];

    return ShellPage(
      topBar: TopBar(
        title: item.name,
        crumbs: [
          if (group != null)
            Crumb(
              group.name,
              () => openCrumb(context, name: groupRouteName(group.id), screen: () => GroupScreen(groupId: group.id)),
            ),
        ],
        actions: [if (menu.isNotEmpty) SecwetMenuButton(label: 'Actions', entries: menu)],
      ),
      children: [
        if (model.readOnly) const UnlinkedNotice(),
        if (item.description?.isNotEmpty == true)
          Padding(
            padding: const EdgeInsets.only(bottom: SecwetSpace.s1),
            child: Text(item.description!, style: SecwetText.sm(p)),
          ),
        if (_environments.isNotEmpty) ...[
          SegmentedTabs<String?>(
            tabs: [const TabSpec(null, 'General'), for (final e in _environments) TabSpec(e.id, e.name)],
            selected: _environmentId,
            onChanged: (id) => setState(() => _environmentId = id),
            trailing: activeEnv != null && scopePerms.canManage
                ? SecwetMenuButton(
                    label: 'Actions for ${activeEnv.name}',
                    entries: [
                      MenuEntry('Rename environment', icon: SecwetIcons.pencil, onSelected: () => _renameEnvironment(activeEnv)),
                      MenuEntry('Delete environment', icon: SecwetIcons.trash, danger: true, onSelected: () => _deleteEnvironment(activeEnv)),
                    ],
                  )
                : null,
          ),
          const SizedBox(height: SecwetSpace.s3),
        ],
        SegmentedTabs<ContentTab>(
          tabs: [
            TabSpec(ContentTab.secrets, 'Secrets', count: scopedSecrets.length),
            TabSpec(ContentTab.assets, 'Assets', count: scopedAssets.length),
            TabSpec(ContentTab.notes, 'Notes', count: scopedNotes.length),
          ],
          selected: _tab,
          onChanged: (t) => setState(() => _tab = t),
        ),
        const SizedBox(height: SecwetSpace.s3),
        if (_loaded)
          switch (_tab) {
            ContentTab.secrets => SecretsSection(
                key: ValueKey('secrets:$_environmentId'),
                item: item,
                environments: _environments,
                environmentId: _environmentId,
                secrets: _secrets,
                scoped: scopedSecrets,
                sessions: _sessions,
                perms: scopePerms,
                onChanged: _afterChange,
              ),
            ContentTab.assets => AssetsSection(
                key: ValueKey('assets:$_environmentId'),
                item: item,
                environmentId: _environmentId,
                assets: scopedAssets,
                perms: scopePerms,
                onChanged: _afterChange,
              ),
            ContentTab.notes => NotesSection(
                key: ValueKey('notes:$_environmentId'),
                item: item,
                environmentId: _environmentId,
                notes: scopedNotes,
                perms: scopePerms,
                onChanged: _afterChange,
              ),
          },
      ],
    );
  }
}

/// Delete an environment, keeping its content in General or deleting it too.
/// Resolves with the preserve choice, or null when cancelled.
class _DeleteEnvironmentDialog extends StatefulWidget {
  const _DeleteEnvironmentDialog({required this.env});

  final Environment env;

  @override
  State<_DeleteEnvironmentDialog> createState() => _DeleteEnvironmentDialogState();
}

class _DeleteEnvironmentDialogState extends State<_DeleteEnvironmentDialog> {
  bool _preserve = true;

  @override
  Widget build(BuildContext context) {
    return SecwetDialog(
      title: 'Delete "${widget.env.name}"?',
      description: 'Choose how to handle the secrets, assets, and notes inside this environment.',
      actions: [
        SecwetButton(label: 'Cancel', variant: ButtonVariant.secondary, onPressed: () => Navigator.of(context).pop()),
        SecwetButton(label: 'Delete environment', variant: ButtonVariant.danger, onPressed: () => Navigator.of(context).pop(_preserve)),
      ],
      children: [
        Column(
          children: [
            RadioRow(
              label: 'Move secrets, assets, and notes to General (preserve content)',
              selected: _preserve,
              onTap: () => setState(() => _preserve = true),
            ),
            RadioRow(
              label: 'Permanently delete all content in this environment',
              selected: !_preserve,
              onTap: () => setState(() => _preserve = false),
            ),
          ],
        ),
      ],
    );
  }
}
