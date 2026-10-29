import 'dart:async';

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
import 'secret_dialogs.dart';

const _mask = '••••••••••••';

/// The Secrets tab of an entry (desktop ItemScreen secrets section): search,
/// add, type filter tabs with counts, and the secret rows.
class SecretsSection extends StatefulWidget {
  const SecretsSection({
    super.key,
    required this.item,
    required this.environments,
    required this.environmentId,
    required this.secrets,
    required this.scoped,
    required this.sessions,
    required this.perms,
    required this.onChanged,
  });

  final Item item;
  final List<Environment> environments;
  final String? environmentId;

  /// Every secret of the entry (for duplicate checks) and the ones in this scope.
  final List<SecretMeta> secrets;
  final List<SecretMeta> scoped;
  final List<ActiveSession> sessions;
  final Permissions perms;

  /// Called after a change, with the environment to show (copy and save can move there).
  final void Function(String? showEnvironmentId) onChanged;

  @override
  State<SecretsSection> createState() => _SecretsSectionState();
}

class _SecretsSectionState extends State<SecretsSection> {
  final _search = TextEditingController();
  Object _kind = 'all';

  @override
  void dispose() {
    _search.dispose();
    super.dispose();
  }

  String? get _envName => widget.environments.where((e) => e.id == widget.environmentId).firstOrNull?.name;

  Future<void> _add() async {
    final saved = await showSecretDialog(
      context,
      item: widget.item,
      environments: widget.environments,
      defaultEnvironmentId: widget.environmentId,
      existing: widget.secrets,
    );
    if (saved) widget.onChanged(widget.environmentId);
  }

  Future<void> _edit(SecretMeta s) async {
    final saved = await showSecretDialog(
      context,
      item: widget.item,
      environments: widget.environments,
      defaultEnvironmentId: widget.environmentId,
      existing: widget.secrets,
      initial: s,
    );
    if (saved) widget.onChanged(widget.environmentId);
  }

  Future<void> _copyTo(SecretMeta s) async {
    final target = await showCopySecretDialog(context, secret: s, environments: widget.environments, existing: widget.secrets);
    if (target != null) widget.onChanged(target);
  }

  Future<void> _delete(SecretMeta s) async {
    final ok = await showConfirmDialog(
      context,
      title: 'Delete "${s.name}"?',
      message: 'Are you sure you want to permanently delete this secret?',
      confirmLabel: 'Delete secret',
    );
    if (!ok || !mounted) return;
    try {
      await SecwetScope.read(context).api.deleteSecret(s.id);
      widget.onChanged(widget.environmentId);
    } catch (e) {
      if (mounted) showError(context, e, "Couldn't delete this secret.");
    }
  }

  @override
  Widget build(BuildContext context) {
    final scoped = widget.scoped;
    final q = _search.text.trim().toLowerCase();
    final filtered = [
      for (final s in scoped)
        if ((_kind == 'all' || s.kind == _kind) &&
            (q.isEmpty || s.name.toLowerCase().contains(q) || (s.note?.toLowerCase().contains(q) ?? false)))
          s,
    ];
    final filtering = q.isNotEmpty || _kind != 'all';
    final kindLabel = _kind is SecretKind ? (_kind as SecretKind).label : '';
    final addButton = widget.perms.canWrite
        ? SecwetButton(label: 'Add secret', icon: SecwetIcons.plus, onPressed: _add)
        : null;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        if (scoped.isNotEmpty || filtering) ...[
          Row(
            children: [
              Expanded(child: SearchField(hint: 'Search secrets...', controller: _search, onChanged: (_) => setState(() {}))),
              if (widget.perms.canWrite) ...[
                const SizedBox(width: SecwetSpace.s2),
                SecwetIconButton(icon: SecwetIcons.plus, label: 'Add secret', filled: true, onPressed: _add),
              ],
            ],
          ),
          const SizedBox(height: SecwetSpace.s3),
          SegmentedTabs<Object>(
            tabs: [
              TabSpec('all', 'All', count: scoped.length),
              for (final k in secretKindOrder) TabSpec(k, k.label, count: scoped.where((s) => s.kind == k).length),
            ],
            selected: _kind,
            onChanged: (k) => setState(() => _kind = k),
          ),
          const SizedBox(height: SecwetSpace.s3),
        ],
        if (scoped.isEmpty && !filtering)
          EmptyState(
            icon: SecwetIcons.key,
            title: 'No secrets yet',
            body: 'Secrets are encrypted on this device and sealed with strict record binding.',
            action: addButton,
          )
        else if (filtered.isEmpty)
          EmptyState(
            icon: SecwetIcons.search,
            title: 'No matching secrets',
            body: q.isNotEmpty
                ? 'No secrets matching "${_search.text}"${_kind != 'all' ? ' in $kindLabel' : ''}.'
                : 'No $kindLabel secrets found in this environment.',
            action: SecwetButton(
              label: 'Clear filter',
              variant: ButtonVariant.secondary,
              onPressed: () => setState(() {
                _search.clear();
                _kind = 'all';
              }),
            ),
          )
        else
          SecwetCard(
            children: [
              for (final s in filtered)
                SecretRow(
                  key: ValueKey(s.id),
                  secret: s,
                  session: widget.sessions.where((x) => x.secretIds.contains(s.id)).firstOrNull,
                  itemName: widget.item.name,
                  environmentName: _envName,
                  canEdit: widget.perms.canWrite,
                  canCopyToEnvironment: widget.perms.canWrite && widget.environments.any((e) => e.id != s.environmentId),
                  canDelete: widget.perms.canDelete,
                  onEdit: () => _edit(s),
                  onCopyToEnvironment: () => _copyTo(s),
                  onDelete: () => _delete(s),
                  onSessionStopped: () => widget.onChanged(widget.environmentId),
                ),
            ],
          ),
      ],
    );
  }
}

/// One secret (desktop SecretRow): name with In use, type and note, the masked
/// value with copy, and reveal plus the actions menu. A revealed value lives
/// only in this row's state and is dropped on hide, dispose and lock.
class SecretRow extends StatefulWidget {
  const SecretRow({
    super.key,
    required this.secret,
    this.session,
    this.itemName,
    this.environmentName,
    required this.canEdit,
    required this.canCopyToEnvironment,
    required this.canDelete,
    required this.onEdit,
    required this.onCopyToEnvironment,
    required this.onDelete,
    required this.onSessionStopped,
  });

  final SecretMeta secret;
  final ActiveSession? session;
  final String? itemName;
  final String? environmentName;
  final bool canEdit;
  final bool canCopyToEnvironment;
  final bool canDelete;
  final VoidCallback onEdit;
  final VoidCallback onCopyToEnvironment;
  final VoidCallback onDelete;
  final VoidCallback onSessionStopped;

  @override
  State<SecretRow> createState() => _SecretRowState();
}

class _SecretRowState extends State<SecretRow> {
  String? _revealed;
  bool _copiedValue = false;
  StreamSubscription<SecwetEvent>? _locked;
  Timer? _reset;

  SecwetApi get _api => SecwetScope.read(context).api;

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    _locked ??= _api.events.where((e) => e.isLocked).listen((_) {
      if (mounted) setState(() => _revealed = null);
    });
  }

  @override
  void dispose() {
    _locked?.cancel();
    _reset?.cancel();
    _revealed = null;
    super.dispose();
  }

  Future<void> _toggleReveal() async {
    if (_revealed != null) return setState(() => _revealed = null);
    try {
      final v = await _api.revealSecret(widget.secret.id);
      if (mounted) setState(() => _revealed = v);
    } catch (e) {
      if (mounted) showError(context, e, "Couldn't reveal this secret.");
    }
  }

  Future<void> _copyValue() async {
    try {
      await _api.copySecret(widget.secret.id);
      if (!mounted) return;
      setState(() => _copiedValue = true);
      showToast(context, '${widget.secret.name} copied. Clears in 30 seconds.', tone: BadgeTone.success);
      _reset?.cancel();
      _reset = Timer(const Duration(seconds: 2), () {
        if (mounted) setState(() => _copiedValue = false);
      });
    } catch (e) {
      if (mounted) showError(context, e, "Couldn't copy this secret.");
    }
  }

  Future<void> _copyName() async {
    try {
      await _api.copyText(widget.secret.name);
      if (mounted) showToast(context, 'Name copied.');
    } catch (e) {
      if (mounted) showError(context, e, "Couldn't copy the name.");
    }
  }

  Future<void> _stopSession() async {
    try {
      await _api.stopActiveSession(widget.session!.sessionId);
      widget.onSessionStopped();
    } catch (e) {
      if (mounted) showError(context, e, "Couldn't stop the process.");
    }
  }

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    final s = widget.secret;
    final session = widget.session;
    final name = s.name.trim().isEmpty ? '(Untitled secret)' : s.name;
    final meta = s.note?.isNotEmpty == true ? '${s.kind.label}, ${s.note}' : s.kind.label;
    final menu = [
      if (session != null)
        MenuEntry('Stop process (${session.command})', icon: SecwetIcons.stop, danger: true, onSelected: _stopSession),
      MenuEntry('Copy name', icon: SecwetIcons.copy, onSelected: _copyName),
      MenuEntry('Usage info & command', icon: SecwetIcons.terminal, onSelected: () {
        showSecretUsage(context, secret: s, session: session, itemName: widget.itemName, environmentName: widget.environmentName)
            .then((_) => widget.onSessionStopped());
      }),
      if (widget.canEdit) MenuEntry('Edit secret', icon: SecwetIcons.pencil, onSelected: widget.onEdit),
      if (widget.canCopyToEnvironment)
        MenuEntry('Copy to environment', icon: SecwetIcons.layers, onSelected: widget.onCopyToEnvironment),
      if (widget.canDelete) ...[
        const MenuEntry.separator(),
        MenuEntry('Delete secret', icon: SecwetIcons.trash, danger: true, onSelected: widget.onDelete),
      ],
    ];
    return Padding(
      padding: const EdgeInsets.fromLTRB(14, 10, 6, 10),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Flexible(
                      child: Text(name, maxLines: 1, overflow: TextOverflow.ellipsis, style: SecwetText.md(p, weight: FontWeight.w500)),
                    ),
                    if (session != null) ...[
                      const SizedBox(width: SecwetSpace.s2),
                      const SecwetBadge('In use', tone: BadgeTone.success),
                    ],
                  ],
                ),
                Text(meta, maxLines: 1, overflow: TextOverflow.ellipsis, style: SecwetText.sm(p)),
                Row(
                  crossAxisAlignment: CrossAxisAlignment.center,
                  children: [
                    Flexible(
                      child: Semantics(
                        label: _revealed != null ? 'Secret value' : 'Hidden secret value',
                        child: Text(
                          _revealed ?? '$_mask${s.valueTail}',
                          maxLines: _revealed != null ? 8 : 1,
                          overflow: TextOverflow.ellipsis,
                          style: SecwetText.sm(p, color: _revealed != null ? p.textPrimary : p.textTertiary),
                        ),
                      ),
                    ),
                    SecwetIconButton(
                      icon: _copiedValue ? SecwetIcons.check : SecwetIcons.copy,
                      label: _copiedValue ? 'Value copied' : 'Copy ${s.name} value',
                      color: _copiedValue ? p.success : null,
                      onPressed: _copyValue,
                    ),
                  ],
                ),
                Text(formatAgo(s.updatedAt), style: SecwetText.xs(p)),
              ],
            ),
          ),
          SecwetIconButton(
            icon: _revealed != null ? SecwetIcons.eyeOff : SecwetIcons.eye,
            label: _revealed != null ? 'Hide ${s.name}' : 'Reveal ${s.name}',
            onPressed: _toggleReveal,
          ),
          SecwetMenuButton(entries: menu, label: 'Actions for ${s.name}'),
        ],
      ),
    );
  }
}
