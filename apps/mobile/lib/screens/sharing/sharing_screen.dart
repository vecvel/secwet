import 'dart:async';

import 'package:flutter/widgets.dart';

import '../../app/secwet_scope.dart';
import '../../app/shell.dart';
import '../../core/secwet_api.dart';
import '../../theme/secwet_theme.dart';
import '../../theme/secwet_tokens.dart';
import '../../widgets/controls.dart';
import '../../widgets/icon.dart';
import '../../widgets/layout.dart';
import '../../widgets/overlays.dart';
import '../settings/plan_tab.dart';
import '../settings/settings_widgets.dart';
import 'access.dart';
import 'share_screen.dart';

const _status = {
  'invited': ('Invited', BadgeTone.warning),
  'accepted': ('Joining', BadgeTone.accent),
  'active': ('Active', BadgeTone.success),
  'removed': ('Removed', BadgeTone.neutral),
  'expired': ('Expired', BadgeTone.neutral),
};

/// Members of one space (desktop MembersDialog): who has access, invite,
/// change access, remove (erase their copy or leave a read-only one) and
/// revoke invitations. Open it with
/// `pushScreen(context, SharingScreen(spaceId: id))`; without a space it
/// lists everyone and the invite asks which space.
class SharingScreen extends StatefulWidget {
  const SharingScreen({super.key, this.spaceId});

  final String? spaceId;

  @override
  State<SharingScreen> createState() => _SharingScreenState();
}

class _SharingScreenState extends State<SharingScreen> {
  List<Member>? _members;
  List<Space> _spaces = const [];
  List<Group> _groups = const [];
  List<Item> _items = const [];
  Access? _access;
  PlanStatus? _plan;
  bool _needsSync = false;
  String? _error;
  String? _notice;
  StreamSubscription<SecwetEvent>? _changes;

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    if (_changes != null) return;
    final api = SecwetScope.read(context).api;
    _changes = api.events.where((e) => e.isChanged && (e.scope == 'members' || e.scope == 'all')).listen((_) => _load());
    _load();
  }

  @override
  void dispose() {
    _changes?.cancel();
    super.dispose();
  }

  Future<T?> _read<T>(Future<T> Function() f) => readWhenIdle(f);

  Future<void> _load() async {
    final api = SecwetScope.read(context).api;
    final r = await Future.wait<Object?>([
      _read(api.spaces),
      _read(api.groups),
      _read(() => api.items()),
      _read(api.myAccess),
      _read(api.planStatus),
    ]);
    _spaces = r[0] as List<Space>? ?? _spaces;
    _groups = r[1] as List<Group>? ?? _groups;
    _items = r[2] as List<Item>? ?? _items;
    _access = r[3] as Access? ?? _access;
    _plan = r[4] as PlanStatus? ?? _plan;
    try {
      // A sync in flight holds the store; wait for it like the reads above.
      var members = <Member>[];
      for (var attempt = 0;; attempt++) {
        try {
          members = await api.members();
          break;
        } on SecwetException catch (e) {
          if (e.code != 'busy' || attempt >= 40) rethrow;
          await Future<void>.delayed(const Duration(milliseconds: 250));
        }
      }
      _error = null;
      _needsSync = false;
      _members = members;
    } on SecwetException catch (e) {
      // The plan explains plan errors; no error on top.
      if (isRelayNotConfigured(e)) {
        _needsSync = true;
      } else if (!isPlanError(e)) {
        _error = e.message.isEmpty ? "Couldn't load members." : e.message;
      }
      _members ??= const [];
    }
    if (mounted) setState(() {});
  }

  Space? get _space => _spaces.where((s) => s.id == widget.spaceId).firstOrNull;

  List<Space> _shareable(bool readOnly) => [for (final s in _spaces) if (canShareSpace(_access, s, readOnly: readOnly)) s];

  String _meta(Member m) {
    final access = summarizeGrants(m.grants);
    if (m.status == 'invited') return '$access. Invited ${formatAgo(m.invitedAt).toLowerCase()}.';
    if (m.status == 'expired') return '$access. The invite expired.';
    return '$access. ${plural(m.devices.where((d) => !d.revoked).length, 'device')}.';
  }

  Future<void> _openShare({Member? member}) async {
    final readOnly = SecwetScope.read(context).session.readOnly;
    final changed = await pushScreen<bool>(
      context,
      ShareScreen(
        spaces: _shareable(readOnly),
        initialSpaceId: widget.spaceId,
        member: member,
        access: _access,
        plan: _plan,
      ),
    );
    if (changed == true) {
      if (member != null && mounted) setState(() => _notice = 'Access for ${member.email ?? 'the member'} updated.');
      await _load();
    }
  }

  Future<void> _copyLink(Member m) async {
    if (m.invitationId == null) return;
    try {
      await SecwetScope.read(context).api.copyInviteLink(m.invitationId!);
      if (mounted) setState(() => _notice = 'Copied. Clears in 30 seconds.');
    } on SecwetException catch (e) {
      if (!mounted) return;
      setState(() => _error = e.code.toLowerCase() == 'not_found'
          ? "This link is only kept on the device that created it until it locks. Revoke the invitation and invite again."
          : (e.message.isEmpty ? "Couldn't copy the link." : e.message));
    }
  }

  Future<void> _revokeInvite(Member m) async {
    final ok = await showConfirmDialog(
      context,
      title: 'Revoke invitation?',
      message: 'The invite link for ${m.email ?? 'this person'} stops working.',
      confirmLabel: 'Revoke invitation',
    );
    if (!ok || m.invitationId == null || !mounted) return;
    try {
      await SecwetScope.read(context).api.revokeInvitation(m.invitationId!);
      if (mounted) setState(() => _notice = 'Invitation revoked. The link no longer works.');
      await _load();
    } on SecwetException catch (e) {
      if (mounted) setState(() => _error = e.message.isEmpty ? "Couldn't revoke this invitation." : e.message);
    }
  }

  Future<void> _remove(Member m) async {
    final wipe = await showSecwetDialog<bool>(
      context,
      builder: (_) => _RemoveMemberSheet(api: SecwetScope.read(context).api, member: m),
    );
    if (wipe == null || !mounted) return;
    setState(() {
      _notice = wipe
          ? '${m.email ?? 'The member'} was removed. Their devices erase this workspace when they next connect.'
          : '${m.email ?? 'The member'} was removed. Their devices keep a read-only copy of what was shared.';
    });
    await _load();
  }

  List<MenuEntry> _menu(Member m) => [
        MenuEntry('Change access', icon: SecwetIcons.pencil, onSelected: () => _openShare(member: m)),
        if (m.status == 'invited') ...[
          if (m.invitationId != null) MenuEntry('Copy invite link', icon: SecwetIcons.copy, onSelected: () => _copyLink(m)),
          if (m.invitationId != null) ...[
            const MenuEntry.separator(),
            MenuEntry('Revoke invitation', icon: SecwetIcons.close, danger: true, onSelected: () => _revokeInvite(m)),
          ],
        ] else ...[
          const MenuEntry.separator(),
          MenuEntry('Remove member', icon: SecwetIcons.trash, danger: true, onSelected: () => _remove(m)),
        ],
      ];

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    final readOnly = SecwetScope.of(context).session.readOnly;
    final space = _space;
    final block = sharingBlock(_plan) ?? (_needsSync ? SharingBlock.needsSync : null);
    final canManage = space == null ? _shareable(readOnly).isNotEmpty : canShareSpace(_access, space, readOnly: readOnly);
    final visible = [
      for (final m in _members ?? const <Member>[])
        if (m.status != 'removed' &&
            (widget.spaceId == null ||
                m.grants.any((g) => g.kind == 'workspace' || spaceOfGrant(g, _groups, _items) == widget.spaceId)))
          m,
    ];
    final title = space == null ? 'Members' : 'Members of ${space.name}';
    return ShellPage(
      topBar: TopBar(
        title: title,
        actions: [
          if (canManage && !(space?.isDefault ?? false))
            SecwetButton(
              label: 'Invite',
              icon: SecwetIcons.plus,
              onPressed: readOnly || block != null ? null : () => _openShare(),
            ),
        ],
      ),
      children: [
        Text(space == null ? 'People with access to your spaces.' : 'People with access to this space.', style: SecwetText.sm(p)),
        const SizedBox(height: SecwetSpace.s4),
        if (space != null && space.isDefault)
          const SettingsNotice(label: 'Personal', tone: BadgeTone.accent, text: 'The Personal space is only for you and is never shared.'),
        if (readOnly)
          const SettingsNotice(label: 'Read-only', text: 'This device was unlinked. Members can be viewed but not changed here.'),
        if (_error != null) SettingsNotice(label: 'Members', text: _error!),
        if (_notice != null)
          SettingsNotice(
            label: 'Done',
            tone: BadgeTone.success,
            text: _notice!,
            action: SecwetButton(
              label: 'Dismiss',
              variant: ButtonVariant.tertiary,
              onPressed: () => setState(() => _notice = null),
            ),
          ),
        if (block == SharingBlock.paused) SettingsNotice(label: 'Sync paused', text: sharingBlockCopy[block]!.body),
        if (block == SharingBlock.needsPro || block == SharingBlock.needsSync)
          EmptyState(
            icon: SecwetIcons.user,
            title: sharingBlockCopy[block]!.title,
            body: sharingBlockCopy[block]!.body,
            action: block == SharingBlock.needsPro && _plan != null
                ? SecwetButton(
                    label: 'Compare plans',
                    variant: ButtonVariant.secondary,
                    onPressed: () => showPlanDialog(
                      context,
                      plan: _plan!,
                      reason: 'Sharing a space needs Pro and sync. Everything in this space keeps working on this phone.',
                    ),
                  )
                : null,
          )
        else if (_members == null)
          Text('Loading members…', style: SecwetText.sm(p))
        else if (visible.isEmpty)
          const EmptyState(
            icon: SecwetIcons.user,
            title: 'Only you so far',
            body: 'Invite people to this space. Each person gets their own key and only sees what you share.',
          )
        else
          SecwetCard(
            children: [
              for (final m in visible)
                SettingRow(
                  title: m.email ?? 'Invited member',
                  muted: m.status == 'expired',
                  badges: [
                    SecwetBadge(_status[m.status]?.$1 ?? m.status, tone: _status[m.status]?.$2 ?? BadgeTone.neutral),
                  ],
                  meta: _meta(m),
                  trailing: readOnly || !canManage ? null : SecwetMenuButton(label: 'Actions for ${m.email ?? 'member'}', entries: _menu(m)),
                ),
            ],
          ),
      ],
    );
  }
}

/// M8 remove: their devices erase this workspace on next contact, or keep a
/// read-only copy of what was shared. Pops with the wipe choice once removed.
class _RemoveMemberSheet extends StatefulWidget {
  const _RemoveMemberSheet({required this.api, required this.member});

  final SecwetApi api;
  final Member member;

  @override
  State<_RemoveMemberSheet> createState() => _RemoveMemberSheetState();
}

class _RemoveMemberSheetState extends State<_RemoveMemberSheet> {
  bool _wipe = true;
  bool _busy = false;
  String? _error;

  Future<void> _confirm() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await widget.api.removeMember(widget.member.memberId, wipe: _wipe);
      if (mounted) Navigator.of(context).pop(_wipe);
    } on SecwetException catch (e) {
      if (mounted) {
        setState(() {
          _error = e.message.isEmpty ? "Couldn't remove this member. Try again." : e.message;
          _busy = false;
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    return SecwetDialog(
      title: 'Remove ${widget.member.email ?? 'this member'}?',
      description: "They lose access right away. Shared spaces get new keys, so they can't read changes made from now on.",
      actions: [
        SecwetButton(label: 'Cancel', variant: ButtonVariant.secondary, onPressed: _busy ? null : () => Navigator.of(context).pop()),
        SecwetButton(
          label: _busy ? 'Removing…' : (_wipe ? 'Remove and erase' : 'Remove member'),
          variant: ButtonVariant.danger,
          onPressed: _busy ? null : _confirm,
        ),
      ],
      children: [
        ChoiceCards<bool>(
          label: 'What happens to shared data on their devices',
          value: _wipe,
          onChanged: _busy ? null : (v) => setState(() => _wipe = v),
          choices: const [
            Choice(
              value: true,
              title: 'Remove and erase',
              hint: 'Recommended',
              description: 'Their devices erase this workspace when they next connect, including anything they kept in it '
                  'only for themselves. If a device never connects again, it keeps what it has.',
            ),
            Choice(
              value: false,
              title: 'Remove and keep a read-only copy',
              description: 'Their devices keep a read-only copy of what was shared before now.',
            ),
          ],
        ),
        if (_error != null) Text(_error!, style: SecwetText.sm(p, color: p.danger)),
      ],
    );
  }
}
