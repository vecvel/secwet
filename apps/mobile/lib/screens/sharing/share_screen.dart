import 'package:flutter/widgets.dart';

import '../../app/secwet_scope.dart';
import '../../app/shell.dart';
import '../../core/secwet_api.dart';
import '../../theme/secwet_theme.dart';
import '../../theme/secwet_tokens.dart';
import '../../widgets/controls.dart';
import '../../widgets/icon.dart';
import '../../widgets/layout.dart';
import '../settings/settings_widgets.dart';
import 'access.dart';

/// Invite someone to a space, or change a member's access (desktop
/// ShareDialog). Access is a tree: the space, its groups, their items, and
/// each item's General scope and environments; a row inherits from its
/// parent unless a role is set on it. Pops `true` when something changed.
class ShareScreen extends StatefulWidget {
  const ShareScreen({super.key, required this.spaces, this.initialSpaceId, this.focus, this.member, this.access, this.plan});

  /// Spaces this phone may share (Personal and spaces without Admin left out by the caller).
  final List<Space> spaces;
  final String? initialSpaceId;

  /// The item or environment being shared ("Share this item…"): an invite
  /// starts as Viewer on it instead of on the whole space.
  final ShareFocus? focus;

  /// Set to change this member's access instead of inviting.
  final Member? member;
  final Access? access;

  /// Loaded by the screen when not given.
  final PlanStatus? plan;

  @override
  State<ShareScreen> createState() => _ShareScreenState();
}

/// A node of the access tree to start an invite on (desktop ShareDialog `focus`).
class ShareFocus {
  const ShareFocus.item(this.id) : kind = 'item';
  const ShareFocus.environment(this.id) : kind = 'environment';

  final String kind;
  final String id;
}

class _ItemBlock {
  _ItemBlock(this.item);

  final ScopeNode item;

  /// General first, then environments.
  final children = <ScopeNode>[];
}

class _GroupBlock {
  _GroupBlock(this.group);

  final ScopeNode group;
  final items = <_ItemBlock>[];
}

class _ShareScreenState extends State<ShareScreen> {
  late String _spaceId = widget.spaces.any((s) => s.id == widget.initialSpaceId)
      ? widget.initialSpaceId!
      : widget.spaces.firstOrNull?.id ?? '';
  final _email = TextEditingController();
  String? _emailError;
  String? _scopeError;
  String? _error;
  bool _busy = false;
  bool _showRoles = false;
  bool _loadingNodes = false;
  bool _copied = false;
  InviteResult? _result;
  late PlanStatus? _plan = widget.plan;

  // Per space, so switching spaces while changing access never drops edits.
  final _nodes = <String, List<ScopeNode>>{};
  final _drafts = <String, GrantDraft>{};
  final _touched = <String>{};
  final _expanded = <String, bool>{};

  bool get _editing => widget.member != null;

  List<GrantInput> get _memberGrants => [for (final g in widget.member?.grants ?? const <Grant>[]) g.toInput()];

  /// The member's grants outside every loaded space (other spaces, the workspace).
  List<GrantInput> get _kept => _editing ? grantsOutside([for (final l in _nodes.values) ...l], _memberGrants) : const [];

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _loadSpace(_spaceId);
      if (_plan == null) _loadPlan();
    });
  }

  @override
  void dispose() {
    _email.dispose();
    super.dispose();
  }

  Future<void> _loadPlan() async {
    final plan = await readWhenIdle(SecwetScope.read(context).api.planStatus);
    if (mounted && plan != null) setState(() => _plan = plan);
  }

  Future<void> _loadSpace(String spaceId) async {
    if (spaceId.isEmpty || _nodes.containsKey(spaceId)) return;
    setState(() => _loadingNodes = true);
    try {
      final list = await SecwetScope.read(context).api.scopeNodes(spaceId);
      if (!mounted) return;
      final GrantDraft initial;
      final focus = widget.focus;
      final focused = focus == null ? null : list.where((n) => n.kind == focus.kind && n.id == focus.id).firstOrNull;
      if (widget.member != null) {
        initial = grantsToDraft(list, _memberGrants);
      } else if (focused != null) {
        initial = {scopeKey(focused): 'viewer'};
      } else {
        final root = list.where((n) => n.kind == 'space').firstOrNull;
        initial = root == null ? {} : {scopeKey(root): 'viewer'};
      }
      setState(() {
        _nodes[spaceId] = list;
        _drafts.putIfAbsent(spaceId, () => initial);
      });
    } on SecwetException catch (e) {
      if (mounted) setState(() => _error = e.message.isEmpty ? "Couldn't load this space." : e.message);
    } finally {
      if (mounted) setState(() => _loadingNodes = false);
    }
  }

  ({ScopeNode? space, List<_GroupBlock> groups}) _tree(List<ScopeNode> nodes) {
    ScopeNode? space;
    final groups = <_GroupBlock>[];
    for (final n in nodes) {
      switch (n.kind) {
        case 'space':
          space ??= n;
        case 'group':
          groups.add(_GroupBlock(n));
        case 'item':
          groups.lastOrNull?.items.add(_ItemBlock(n));
        case 'general' || 'environment':
          groups.lastOrNull?.items.lastOrNull?.children.add(n);
      }
    }
    return (space: space, groups: groups);
  }

  String _itemSummary(List<ScopeNode> children, GrantDraft draft) {
    var restricted = 0;
    var custom = 0;
    for (final c in children) {
      final role = draft[scopeKey(c)];
      if (role == 'no_access') {
        restricted++;
      } else if (role != null) {
        custom++;
      }
    }
    final parts = [if (restricted > 0) '$restricted restricted', if (custom > 0) '$custom set separately'];
    if (parts.isNotEmpty) return parts.join(', ');
    final envs = children.where((c) => c.kind == 'environment').length;
    if (envs == 0) return 'General inherits';
    return 'General and ${plural(envs, 'environment')} inherit';
  }

  void _setRole(ScopeNode node, String? role) {
    setState(() {
      _scopeError = null;
      _touched.add(_spaceId);
      final draft = _drafts.putIfAbsent(_spaceId, () => {});
      if (role == null) {
        draft.remove(scopeKey(node));
      } else {
        draft[scopeKey(node)] = role;
      }
    });
  }

  /// Editing: every loaded space. Inviting: the open space plus any the user
  /// changed, so a default Viewer on a space only glanced at is never granted.
  List<String> _submitted() => [
        for (final id in _nodes.keys)
          if (_editing || id == _spaceId || _touched.contains(id)) id,
      ];

  Future<void> _submit() async {
    if (_busy) return;
    final email = _email.text.trim();
    var ok = true;
    if (!_editing && !isValidEmail(email)) {
      _emailError = 'Enter a valid email address.';
      ok = false;
    }
    final ids = _submitted();
    final readable = ids.any((id) => hasReadableGrant(_nodes[id]!, _drafts[id] ?? {}, _kept)) ||
        _kept.any((g) => g.role != 'no_access');
    if (!readable) {
      _scopeError = 'Give access to at least one part of this space.';
      ok = false;
    }
    if (!ok) {
      setState(() {});
      return;
    }
    final grants = [..._kept, for (final id in ids) ...draftToGrants(_nodes[id]!, _drafts[id] ?? {})];
    final api = SecwetScope.read(context).api;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      if (widget.member != null) {
        await api.setGrants(widget.member!.memberId, grants);
        if (mounted) Navigator.of(context).pop(true);
      } else {
        final r = await api.invite(email, grants);
        if (mounted) setState(() => _result = r);
      }
    } on SecwetException catch (e) {
      if (mounted) {
        setState(() => _error = e.message.isNotEmpty
            ? e.message
            : _editing
                ? "Couldn't save access. Try again."
                : "Couldn't create the invite. Try again.");
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  /// The link carries the invite token, so it goes through the clipboard
  /// that clears itself after 30 seconds.
  Future<void> _copyLink() async {
    final r = _result;
    if (r == null) return;
    try {
      await SecwetScope.read(context).api.copyInviteLink(r.invitationId);
      if (mounted) setState(() => _copied = true);
    } on SecwetException catch (e) {
      if (mounted) setState(() => _error = e.message.isEmpty ? "Couldn't copy the link." : e.message);
    }
  }

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    final result = _result;
    if (result != null) {
      final email = _email.text.trim();
      return ShellPage(
        topBar: const TopBar(title: 'Invite created'),
        children: [
          Text('Send this link to $email. It works once and expires in 7 days.', style: SecwetText.md(p, color: p.textSecondary)),
          const SizedBox(height: SecwetSpace.s4),
          Container(
            padding: const EdgeInsets.all(SecwetSpace.s3),
            decoration: BoxDecoration(
              color: p.surfaceSunken,
              border: Border.all(color: p.border),
              borderRadius: BorderRadius.circular(SecwetRadius.card),
            ),
            child: Text(result.link, style: SecwetText.sm(p, color: p.textPrimary)),
          ),
          const SizedBox(height: SecwetSpace.s3),
          SecwetButton(
            label: _copied ? 'Copied' : 'Copy link',
            icon: _copied ? SecwetIcons.check : SecwetIcons.copy,
            variant: ButtonVariant.secondary,
            expand: true,
            onPressed: _copyLink,
          ),
          if (_copied) ...[
            const SizedBox(height: SecwetSpace.s2),
            Text('Copied. Clears in 30 seconds.', style: SecwetText.sm(p)),
          ],
          const SizedBox(height: SecwetSpace.s3),
          Text(
            "Secwet doesn't send email. The link is the only way in, so send it somewhere only $email can read. "
            'They open it on a phone or computer without a Secwet.',
            style: SecwetText.sm(p),
          ),
          if (_error != null) ...[
            const SizedBox(height: SecwetSpace.s3),
            Text(_error!, style: SecwetText.sm(p, color: p.danger)),
          ],
          const SizedBox(height: SecwetSpace.s6),
          SecwetButton(label: 'Done', expand: true, onPressed: () => Navigator.of(context).pop(true)),
        ],
      );
    }

    final space = widget.spaces.where((s) => s.id == _spaceId).firstOrNull;
    final block = sharingBlock(_plan);
    final nodes = _nodes[_spaceId] ?? const <ScopeNode>[];
    final tree = _tree(nodes);
    final draft = _drafts[_spaceId] ?? const <String, String>{};
    final title = _editing ? 'Change access' : (space != null && widget.initialSpaceId != null ? 'Share ${space.name}' : 'Invite');
    return ShellPage(
      topBar: TopBar(title: title),
      children: [
        Text(
          _editing
              ? 'Choose what ${widget.member!.email ?? 'they'} can see and change in each space.'
              : 'They get their own key. You choose what they can see and change.',
          style: SecwetText.md(p, color: p.textSecondary),
        ),
        const SizedBox(height: SecwetSpace.s4),
        if (block != null)
          SettingsNotice(label: sharingBlockCopy[block]!.title, text: sharingBlockCopy[block]!.body),
        if (!_editing) ...[
          SecwetField(
            label: 'Email',
            hint: 'name@example.com',
            controller: _email,
            autocorrect: false,
            keyboardType: TextInputType.emailAddress,
            error: _emailError,
            onChanged: (_) {
              if (_emailError != null) setState(() => _emailError = null);
            },
          ),
          const SizedBox(height: SecwetSpace.s4),
        ],
        if (widget.spaces.length > 1 && (_editing || widget.initialSpaceId == null)) ...[
          Text('Space', style: SecwetText.md(p, weight: FontWeight.w500)),
          const SizedBox(height: SecwetSpace.s2),
          SelectControl<String>(
            label: 'Space',
            value: _spaceId,
            options: [for (final s in widget.spaces) SelectOption(s.id, s.name)],
            onChanged: _busy
                ? null
                : (id) {
                    setState(() {
                      _spaceId = id;
                      _error = null;
                    });
                    _loadSpace(id);
                  },
          ),
          const SizedBox(height: SecwetSpace.s4),
        ],
        if (space == null)
          const SettingsNotice(label: 'No space to share', text: 'Create a space to share. The Personal space is only for you.')
        else ...[
          Row(
            children: [
              Text('Access', style: SecwetText.md(p, weight: FontWeight.w500)),
              const SizedBox(width: SecwetSpace.s1),
              SecwetIconButton(
                icon: SecwetIcons.info,
                label: 'What the roles allow',
                onPressed: () => setState(() => _showRoles = !_showRoles),
              ),
            ],
          ),
          Text('Rows inherit from their parent unless you set them.', style: SecwetText.sm(p)),
          const SizedBox(height: SecwetSpace.s3),
          if (_showRoles)
            SecwetCard(
              children: [
                for (final r in roles) SettingRow(title: roleLabels[r]!, meta: roleDescriptions[r]),
              ],
            ),
          if (_loadingNodes && nodes.isEmpty) Text('Loading…', style: SecwetText.sm(p)),
          if (tree.space != null)
            _Card(
              children: [_nodeRow(tree.space!, draft, nodes, title: tree.space!.label, subtitle: 'Whole space')],
            ),
          for (final g in tree.groups) ...[
            Padding(
              padding: const EdgeInsets.only(top: SecwetSpace.s2, bottom: SecwetSpace.s2),
              child: _nodeRow(g.group, draft, nodes, title: 'Group · ${g.group.label}', dim: true),
            ),
            for (final i in g.items) _itemCard(i, draft, nodes),
          ],
          if (_scopeError != null) Text(_scopeError!, style: SecwetText.sm(p, color: p.danger)),
        ],
        if (_error != null) ...[
          const SizedBox(height: SecwetSpace.s3),
          Text(_error!, style: SecwetText.sm(p, color: p.danger)),
        ],
        const SizedBox(height: SecwetSpace.s6),
        SecwetButton(
          label: _busy ? (_editing ? 'Saving…' : 'Creating invite…') : (_editing ? 'Save access' : 'Create invite'),
          expand: true,
          onPressed: _busy || space == null || _loadingNodes || block != null ? null : _submit,
        ),
        const SizedBox(height: SecwetSpace.s2),
        SecwetButton(
          label: 'Cancel',
          variant: ButtonVariant.secondary,
          expand: true,
          onPressed: _busy ? null : () => Navigator.of(context).pop(false),
        ),
      ],
    );
  }

  Widget _itemCard(_ItemBlock block, GrantDraft draft, List<ScopeNode> nodes) {
    final p = context.palette;
    final key = scopeKey(block.item);
    final open = _expanded[key] ?? block.children.any((c) => draft[scopeKey(c)] != null);
    return _Card(
      children: [
        Row(
          children: [
            Expanded(
              child: Tappable(
                label: block.item.label,
                onTap: () => setState(() => _expanded[key] = !open),
                child: ConstrainedBox(
                  constraints: const BoxConstraints(minHeight: SecwetControl.touchTarget),
                  child: Row(
                    children: [
                      SecwetIcon(open ? SecwetIcons.chevronDown : SecwetIcons.chevronRight, size: 16, color: p.textTertiary),
                      const SizedBox(width: SecwetSpace.s2),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Text(block.item.label, style: SecwetText.md(p, weight: FontWeight.w500)),
                            Text(_itemSummary(block.children, draft), style: SecwetText.xs(p)),
                          ],
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ),
            const SizedBox(width: SecwetSpace.s2),
            _roleSelect(block.item, draft, nodes),
          ],
        ),
        if (open)
          for (final (i, child) in block.children.indexed)
            Row(
              children: [
                const SizedBox(width: 7),
                // Branch line, rounded on the last child.
                SizedBox(
                  width: 16,
                  height: SecwetControl.touchTarget + SecwetSpace.s1,
                  child: CustomPaint(painter: _Branch(color: p.treeGuide, last: i == block.children.length - 1)),
                ),
                const SizedBox(width: SecwetSpace.s2),
                Expanded(child: Text(child.label, style: SecwetText.md(p))),
                _roleSelect(child, draft, nodes),
              ],
            ),
      ],
    );
  }

  Widget _nodeRow(ScopeNode node, GrantDraft draft, List<ScopeNode> nodes, {required String title, String? subtitle, bool dim = false}) {
    final p = context.palette;
    return Row(
      children: [
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(title, style: dim ? SecwetText.sm(p) : SecwetText.md(p, weight: FontWeight.w500)),
              if (subtitle != null) Text(subtitle, style: SecwetText.xs(p)),
            ],
          ),
        ),
        const SizedBox(width: SecwetSpace.s2),
        _roleSelect(node, draft, nodes),
      ],
    );
  }

  Widget _roleSelect(ScopeNode node, GrantDraft draft, List<ScopeNode> nodes) {
    final explicit = draft[scopeKey(node)];
    final inherited = inheritedRole(nodes, draft, node, _kept);
    final root = node.kind == 'space';
    return SizedBox(
      width: 148,
      child: SelectControl<String>(
        label: 'Role for ${node.label}',
        value: explicit ?? '',
        options: [
          SelectOption('', root && inherited == 'no_access' ? 'Not shared' : 'Inherit (${roleLabels[inherited]})'),
          for (final r in roles)
            if (!(root && r == 'no_access')) SelectOption(r, roleLabels[r]!),
        ],
        onChanged: _busy ? null : (v) => _setRole(node, v.isEmpty ? null : v),
      ),
    );
  }
}

class _Card extends StatelessWidget {
  const _Card({required this.children});

  final List<Widget> children;

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    return Container(
      margin: const EdgeInsets.only(bottom: SecwetSpace.s2),
      padding: const EdgeInsets.symmetric(horizontal: SecwetSpace.s3, vertical: SecwetSpace.s1),
      decoration: BoxDecoration(
        color: p.surface,
        border: Border.all(color: p.border),
        borderRadius: BorderRadius.circular(SecwetRadius.card),
      ),
      child: InputSurface(child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: children)),
    );
  }
}

/// Tree connector from the item down to a child row.
class _Branch extends CustomPainter {
  _Branch({required this.color, required this.last});

  final Color color;
  final bool last;

  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()
      ..color = color
      ..style = PaintingStyle.stroke
      ..strokeWidth = 1;
    final mid = size.height / 2;
    final path = Path()..moveTo(0.5, 0);
    if (last) {
      path
        ..lineTo(0.5, mid - 6)
        ..quadraticBezierTo(0.5, mid, 6.5, mid)
        ..lineTo(size.width, mid);
    } else {
      path
        ..lineTo(0.5, size.height)
        ..moveTo(0.5, mid)
        ..lineTo(size.width, mid);
    }
    canvas.drawPath(path, paint);
  }

  @override
  bool shouldRepaint(_Branch old) => old.color != color || old.last != last;
}
