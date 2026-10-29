import 'dart:async';

import 'package:flutter/cupertino.dart' show CupertinoPageRoute;
import 'package:flutter/widgets.dart';

import '../../app/shell.dart';
import '../../core/secwet_api.dart';
import '../../theme/secwet_theme.dart';
import '../../theme/secwet_tokens.dart';
import '../../widgets/controls.dart';
import '../../widgets/icon.dart';
import '../../widgets/layout.dart';
import '../groups/access.dart';
import '../groups/common.dart';
import '../groups/group_dialogs.dart';
import '../groups/item_screen.dart';
import '../groups/workspace_model.dart';
import '../settings/settings_screen.dart';
import 'customize_dashboard.dart';

/// Shows Settings on [tabName] (`devices`, `recovery`, `plan`, ...):
/// switches to the Settings tab and opens that tab of the screen. Unknown
/// names open General.
void openSettingsTab(BuildContext context, String tabName) {
  final shell = SecwetShell.of(context);
  final tab = SettingsTab.values.where((t) => t.name == tabName).firstOrNull ?? SettingsTab.general;
  shell.select(ShellTab.settings);
  final nav = shell.navigatorFor(ShellTab.settings);
  nav?.popUntil((r) => r.isFirst);
  if (tab != SettingsTab.general) {
    nav?.push(CupertinoPageRoute<void>(builder: (_) => SettingsScreen(initialTab: tab)));
  }
}

/// The Overview tab (desktop screens/overview/OverviewScreen.tsx): KPI tiles,
/// recently changed secrets, recent notes, quick actions and the setup and
/// safety checklist, in the order the dashboard config sets. Counts follow
/// the active space like the desktop.
class OverviewScreen extends StatefulWidget {
  const OverviewScreen({super.key});

  @override
  State<OverviewScreen> createState() => _OverviewScreenState();
}

class _OverviewScreenState extends State<OverviewScreen> {
  WorkspaceModel? _model;
  StreamSubscription<SecwetEvent>? _changes;

  Overview? _overview;
  DashboardConfig _dashboard = const DashboardConfig(
    homeLabel: 'Overview',
    visibleKpis: ['secrets', 'assets', 'notes', 'devices'],
    widgets: ['recent_secrets', 'recent_notes', 'quick_actions', 'checklist'],
  );
  KeyStatus? _keyStatus;
  PlanStatus? _plan;
  String _deviceName = '';
  List<NoteMeta> _recentNotes = const [];

  SecwetApi get _api => _model!.api;

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    if (_model == null) {
      _model = WorkspaceModel.of(context);
      _model!.addListener(_onModel);
      _changes = _api.events.where((e) => e.isChanged).listen((_) => _load());
      _model!.ensureLoaded().then((_) => _load());
    }
  }

  @override
  void dispose() {
    _changes?.cancel();
    _model?.removeListener(_onModel);
    super.dispose();
  }

  String? _notesKey;

  void _onModel() {
    // Recent notes depend on which entries are visible in the active space.
    final key = [for (final i in _model!.visibleItems) if (i.notesCount > 0) '${i.id}:${i.notesCount}'].join(',');
    if (key != _notesKey) _loadNotes();
    if (mounted) setState(() {});
  }

  /// Null when the read fails; waits out a sync that holds the store.
  Future<T?> _try<T>(Future<T> Function() f) => readWhenIdle(f);

  Future<void> _load() async {
    final overview = await _try(_api.overview);
    if (overview == null) return; // Locked meanwhile.
    final dashboard = await _try(_api.dashboard);
    final key = await _try(_api.keyStatus);
    final plan = await _try(_api.planStatus);
    final settings = await _try(_api.settings);
    var name = settings?.deviceName ?? '';
    if (name.isEmpty || name == 'desktop' || name == 'default-device') name = await _try(_api.systemDeviceName) ?? 'This phone';
    if (!mounted) return;
    setState(() {
      _overview = overview;
      if (dashboard != null) _dashboard = dashboard;
      _keyStatus = key;
      _plan = plan;
      _deviceName = name;
    });
    await _loadNotes();
  }

  Future<void> _loadNotes() async {
    final model = _model!;
    final items = [for (final i in model.visibleItems) if (i.notesCount > 0) i];
    _notesKey = [for (final i in items) '${i.id}:${i.notesCount}'].join(',');
    final all = <NoteMeta>[];
    for (final i in items.take(30)) {
      final notes = await _try(() => _api.notes(i.id));
      if (notes != null) all.addAll(notes);
    }
    all.sort((a, b) => b.updatedAt.compareTo(a.updatedAt));
    if (mounted) setState(() => _recentNotes = all.take(5).toList());
  }

  // ---------------------------------------------------------------------------
  // Actions (desktop App.tsx wiring)
  // ---------------------------------------------------------------------------

  Item? get _activeItem {
    final model = _model!;
    final visible = model.visibleItems;
    return visible.where((i) => i.id == model.selectedItemId).firstOrNull ?? visible.firstOrNull;
  }

  bool get _canAddSecret {
    final model = _model!;
    final item = _activeItem;
    if (item == null) return model.canCreateFromTopBar;
    return model.scopePerms(item, null).canWrite || model.canCreateFromTopBar;
  }

  Future<void> _openItem(String itemId, [String? environmentId]) async {
    _model!.selectItem(itemId);
    await pushScreen(context, ItemScreen(itemId: itemId, environmentId: environmentId));
  }

  Future<void> _newEntry() async {
    final model = _model!;
    if (!model.canCreateFromTopBar) return;
    if (model.visibleGroups.isEmpty) {
      await showNewGroupDialog(context, model);
      return;
    }
    final item = await showNewItemDialog(context, model, groups: model.visibleGroups, initialGroupId: model.newTargetGroupId);
    if (item != null && mounted) await _openItem(item.id);
  }

  Future<void> _addSecret() async {
    final model = _model!;
    final item = _activeItem;
    if (item != null) {
      await _openItem(item.id);
    } else if (model.canCreateGroupHere) {
      await showNewGroupDialog(context, model);
    }
  }

  Future<void> _customize() async {
    final saved = await showCustomizeDashboard(context, _dashboard, _api.setDashboard);
    if (saved != null && mounted) setState(() => _dashboard = saved);
  }

  @override
  Widget build(BuildContext context) {
    final model = _model!;
    final o = _overview;
    final home = _dashboard.homeLabel.isEmpty ? 'Overview' : _dashboard.homeLabel;
    final canCreate = model.canCreateFromTopBar;
    return ShellPage(
      topBar: TopBar(
        title: home,
        large: true,
        actions: [
          SecwetIconButton(icon: SecwetIcons.customize, label: 'Customize', small: true, onPressed: _customize),
          if (canCreate) SecwetButton(label: 'New', icon: SecwetIcons.plus, small: true, onPressed: _newEntry),
        ],
      ),
      children: [
        if (model.readOnly) const UnlinkedNotice(),
        ..._kpis(model, o),
        for (final w in _dashboard.widgets) ?_widget(context, w, model, o),
      ],
    );
  }

  List<Widget> _kpis(WorkspaceModel model, Overview? o) {
    final kpis = _dashboard.visibleKpis;
    if (kpis.isEmpty) return const [];
    final filtered = model.activeSpaceId != null;
    final items = model.visibleItems;
    int sum(int Function(Item) f) => items.fold(0, (a, i) => a + f(i));
    String n(int? v) => v == null ? '–' : '$v';
    final tiles = [
      if (kpis.contains('secrets'))
        StatTile(label: 'Secrets', value: n(filtered ? sum((i) => i.secretsCount) : o?.secretsCount)),
      if (kpis.contains('assets') || kpis.contains('files'))
        StatTile(label: 'Assets', value: n(filtered ? sum((i) => i.assetsCount) : o?.assetsCount)),
      if (kpis.contains('notes')) StatTile(label: 'Notes', value: n(filtered ? sum((i) => i.notesCount) : o?.notesCount)),
      if (kpis.contains('devices'))
        StatTile(label: 'Devices', value: n(o == null ? null : (o.activeDevicesCount == 0 ? 1 : o.activeDevicesCount))),
    ];
    // Rows of two tiles sized to their content (an odd last tile keeps its
    // half width), not a fixed aspect ratio that follows the screen width.
    return [
      for (var i = 0; i < tiles.length; i += 2) ...[
        if (i > 0) const SizedBox(height: 10),
        IntrinsicHeight(
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Expanded(child: tiles[i]),
              const SizedBox(width: 10),
              Expanded(child: i + 1 < tiles.length ? tiles[i + 1] : const SizedBox.shrink()),
            ],
          ),
        ),
      ],
      const SizedBox(height: 14),
    ];
  }

  Widget? _widget(BuildContext context, String id, WorkspaceModel model, Overview? o) {
    final p = context.palette;
    Widget empty(String text) => Padding(
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: SecwetSpace.s3),
          child: Text(text, style: SecwetText.md(p, color: p.textTertiary)),
        );
    switch (id) {
      case 'recent_secrets':
        final visibleIds = {for (final i in model.visibleItems) i.id};
        final recent = [
          for (final s in o?.recent ?? const <RecentSecret>[])
            if (model.activeSpaceId == null || visibleIds.contains(s.itemId)) s,
        ].take(5).toList();
        return SecwetCard(
          title: 'Recently changed secrets',
          children: recent.isEmpty
              ? [empty('Secrets you add or edit show up here.')]
              : [
                  for (final s in recent)
                    ListRow(
                      title: s.name,
                      meta: [s.itemName, s.environmentName.isEmpty ? 'General' : s.environmentName]
                          .where((x) => x.isNotEmpty)
                          .join(' · '),
                      trailing: Text(formatAgo(s.updatedAt), style: SecwetText.sm(p)),
                      onTap: () => _openItem(s.itemId, s.environmentId.isEmpty ? null : s.environmentId),
                    ),
                ],
        );
      case 'recent_notes':
        return SecwetCard(
          title: 'Recent notes',
          children: _recentNotes.isEmpty
              ? [empty('Notes you create appear here.')]
              : [
                  for (final n in _recentNotes)
                    ListRow(
                      title: n.title,
                      meta: '${model.itemById(n.itemId)?.name ?? ''}${n.snippet.isNotEmpty ? ' — ${n.snippet}' : ''}',
                      trailing: Text(formatAgo(n.updatedAt), style: SecwetText.sm(p)),
                      onTap: () => _openNote(n),
                    ),
                ],
        );
      case 'quick_actions':
        final canPair = canPairDevices(model.access, model.readOnly);
        final actions = [
          if (model.canCreateFromTopBar)
            SecwetButton(label: 'New entry', icon: SecwetIcons.plus, variant: ButtonVariant.secondary, expand: true, onPressed: _newEntry),
          if (_canAddSecret)
            SecwetButton(label: 'Add secret', icon: SecwetIcons.key, variant: ButtonVariant.secondary, expand: true, onPressed: _addSecret),
          if (canPair)
            SecwetButton(
              label: 'Pair device',
              icon: SecwetIcons.device,
              variant: ButtonVariant.secondary,
              expand: true,
              onPressed: () => openSettingsTab(context, 'devices'),
            ),
          SecwetButton(
            label: 'Backup key',
            icon: SecwetIcons.recovery,
            variant: ButtonVariant.secondary,
            expand: true,
            onPressed: () => openSettingsTab(context, 'recovery'),
          ),
        ];
        return SecwetCard(
          title: 'Quick actions',
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: SecwetSpace.s3),
          children: [
            LayoutBuilder(
              builder: (context, c) {
                final w = (c.maxWidth - SecwetSpace.s2) / 2;
                return Wrap(
                  spacing: SecwetSpace.s2,
                  runSpacing: SecwetSpace.s2,
                  children: [for (final a in actions) SizedBox(width: w, child: a)],
                );
              },
            ),
          ],
        );
      case 'checklist':
        return _Checklist(steps: _steps(context, model, o));
    }
    return null;
  }

  Future<void> _openNote(NoteMeta n) => pushScreen(
        context,
        ItemScreen(itemId: n.itemId, environmentId: n.environmentId, initialTab: ContentTab.notes),
      );

  List<_Step> _steps(BuildContext context, WorkspaceModel model, Overview? o) {
    final checklist = o?.checklist;
    final canPair = canPairDevices(model.access, model.readOnly);
    final rotationReason = _keyStatus?.rotationRecommended == true && canRotateMasterKey(model.access, model.readOnly)
        ? ((_keyStatus!.pendingReason?.trim().isNotEmpty ?? false) ? _keyStatus!.pendingReason!.trim() : 'A device was revoked.')
        : null;
    final pro = _plan?.plan == 'pro';
    final recoveryDone = checklist?.recoveryKeyCreated ?? false;
    void open(String tab) => openSettingsTab(context, tab);
    return [
      if (rotationReason != null)
        _Step(
          title: 'Rotate encryption key',
          detail: '$rotationReason Rotating stops revoked devices reading changes made from now on.',
          done: false,
          actions: [SecwetButton(label: 'Rotate', small: true, onPressed: () => open('security'))],
        ),
      _Step(title: 'Initialized on this device', detail: '$_deviceName holds your device key.', done: true),
      _Step(
        title: 'Create a recovery key',
        detail: recoveryDone ? 'Stored by you, away from this device.' : 'The only way back in if you lose every device.',
        done: recoveryDone,
        actions: [SecwetButton(label: 'Create', small: true, onPressed: () => open('recovery'))],
      ),
      // No "Connect the command line" step: the CLI runs on a computer and
      // connects to that computer's own store, so this phone can never
      // complete it (the desktop shows it with its CLI guide).
      if (canPair)
        _Step(
          title: 'Add another device',
          detail: pro ? 'Approve a phone or laptop from this device.' : 'Needs Pro. Works the same on local device.',
          done: pro && ((checklist?.addDeviceDone ?? false) || (o?.activeDevicesCount ?? 0) > 1),
          actions: [
            if (pro)
              SecwetButton(label: 'Pair a device', variant: ButtonVariant.secondary, small: true, onPressed: () => open('devices'))
            else
              SecwetButton(label: 'Compare plans', variant: ButtonVariant.tertiary, small: true, onPressed: () => open('plan')),
          ],
        ),
    ];
  }
}

class _Step {
  const _Step({required this.title, required this.detail, required this.done, this.actions = const []});

  final String title;
  final String detail;
  final bool done;
  final List<Widget> actions;
}

/// "Setup and safety": numbered steps, a check when done, and the step's
/// action under its text so narrow rows never squeeze the words.
class _Checklist extends StatelessWidget {
  const _Checklist({required this.steps});

  final List<_Step> steps;

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    final remaining = steps.where((s) => !s.done).length;
    return SecwetCard(
      title: 'Setup and safety',
      headerTrailing: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(
            width: 6,
            height: 6,
            decoration: BoxDecoration(color: remaining == 0 ? p.success : p.warning, shape: BoxShape.circle),
          ),
          const SizedBox(width: 6),
          Text(remaining == 0 ? 'All set' : '${plural(remaining, 'step')} left', style: SecwetText.sm(p, color: p.textSecondary)),
        ],
      ),
      children: [
        for (final (i, s) in steps.indexed)
          Semantics(
            label: '${s.title}, ${s.done ? 'done' : 'to do'}',
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 14, vertical: SecwetSpace.s3),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Container(
                    width: 24,
                    height: 24,
                    alignment: Alignment.center,
                    decoration: BoxDecoration(
                      color: s.done ? p.accentFill : p.bg,
                      border: Border.all(color: s.done ? p.accentFill : p.borderStrong),
                      shape: BoxShape.circle,
                    ),
                    child: s.done
                        ? SecwetIcon(SecwetIcons.check, size: 14, color: p.onAccentFill)
                        : Text('${i + 1}', style: SecwetText.sm(p, color: p.textSecondary).copyWith(height: 1)),
                  ),
                  const SizedBox(width: SecwetSpace.s3),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(s.title, style: SecwetText.md(p, weight: FontWeight.w500)),
                        Text(s.detail, style: SecwetText.sm(p)),
                        if (!s.done && s.actions.isNotEmpty) ...[
                          const SizedBox(height: SecwetSpace.s2),
                          Wrap(spacing: SecwetSpace.s2, runSpacing: SecwetSpace.s2, children: s.actions),
                        ],
                      ],
                    ),
                  ),
                ],
              ),
            ),
          ),
      ],
    );
  }
}
