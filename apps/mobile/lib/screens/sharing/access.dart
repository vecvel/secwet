// Role and permission helpers for member mode (docs/m7-m8-architecture.md
// §4), ported from apps/desktop/src/lib/access.ts. Pure functions over the
// app-layer DTOs so they can be unit tested.
import '../../core/secwet_api.dart';

const roles = ['admin', 'editor', 'viewer', 'no_access'];

const roleLabels = {'admin': 'Admin', 'editor': 'Editor', 'viewer': 'Viewer', 'no_access': 'No access'};

const roleDescriptions = {
  'admin': 'Full control and can invite',
  'editor': "Add and edit secrets, notes, files. Can't delete.",
  'viewer': 'Read, reveal, copy, download',
  'no_access': 'Hidden',
};

int roleRank(String role) => switch (role) {
      'admin' => 3,
      'editor' => 2,
      'viewer' => 1,
      _ => 0,
    };

/// Where an action happens, from the space down.
class NodePath {
  NodePath({this.spaceId, this.groupId, this.itemId, this.environmentId, this.general = false});

  String? spaceId;
  String? groupId;
  String? itemId;
  String? environmentId;

  /// Item-wide content (the "General" scope).
  bool general;
}

/// Tree nodes from the workspace down to the deepest node [path] names.
List<(String, String?)> pathNodes(NodePath path) {
  final nodes = <(String, String?)>[('workspace', null)];
  if (path.spaceId != null) nodes.add(('space', path.spaceId));
  if (path.groupId != null) nodes.add(('group', path.groupId));
  if (path.itemId != null) {
    nodes.add(('item', path.itemId));
    if (path.environmentId != null) {
      nodes.add(('environment', path.environmentId));
    } else if (path.general) {
      nodes.add(('general', path.itemId));
    }
  }
  return nodes;
}

bool _sameNode(GrantInput g, String kind, String? id) => g.kind == kind && (kind == 'workspace' || g.id == id);

/// The most specific explicit grant on the path wins (mirrors
/// `secwet_proto::collab::effective_role`).
String roleFromGrants(List<GrantInput> grants, NodePath path) {
  var role = 'no_access';
  for (final (kind, id) in pathNodes(path)) {
    for (final g in grants) {
      if (_sameNode(g, kind, id)) {
        role = g.role;
        break;
      }
    }
  }
  return role;
}

/// Owners (and a missing access view) are Admin everywhere.
String effectiveRole(Access? access, NodePath path) {
  if (access == null || access.isOwner) return 'admin';
  return roleFromGrants([for (final g in access.grants) g.toInput()], path);
}

/// Inviting and changing access needs Admin on the space; never on Personal
/// or from a read-only (unlinked) device.
bool canShareSpace(Access? access, Space space, {required bool readOnly}) =>
    !readOnly && !space.isDefault && roleRank(effectiveRole(access, NodePath(spaceId: space.id))) >= 3;

/// Pairing adds an owner device; the relay refuses it from a member's device.
bool canPairDevices(Access? access, {required bool readOnly}) => !readOnly && (access == null || access.isOwner);

// ---------------------------------------------------------------------------
// Share sheet
// ---------------------------------------------------------------------------

/// Explicit role per scope node; a missing key means "inherit".
typedef GrantDraft = Map<String, String>;

String nodeKey(String kind, String? id) => '$kind:${id ?? ''}';

String scopeKey(ScopeNode n) => nodeKey(n.kind, n.id);

/// Path of a scope node from the space down, built from the parent links.
NodePath scopeNodePath(List<ScopeNode> nodes, ScopeNode node) {
  final byId = <String, ScopeNode>{
    // General shares its id with the item, so index containers only.
    for (final n in nodes)
      if (n.kind == 'space' || n.kind == 'group' || n.kind == 'item') n.id: n,
  };
  final path = NodePath();
  ScopeNode? cur = node;
  while (cur != null) {
    switch (cur.kind) {
      case 'space':
        path.spaceId = cur.id;
      case 'group':
        path.groupId = cur.id;
      case 'item':
        path.itemId = cur.id;
      case 'environment':
        path.environmentId = cur.id;
      case 'general':
        path.general = true;
    }
    cur = cur.parentId == null ? null : byId[cur.parentId];
  }
  return path;
}

List<GrantInput> draftToGrants(List<ScopeNode> nodes, GrantDraft draft) => [
      for (final n in nodes)
        if (draft[scopeKey(n)] != null) GrantInput(kind: n.kind, id: n.id, role: draft[scopeKey(n)]!),
    ];

GrantDraft grantsToDraft(List<ScopeNode> nodes, List<GrantInput> grants) {
  final draft = <String, String>{};
  for (final n in nodes) {
    for (final g in grants) {
      if (_sameNode(g, n.kind, n.id)) {
        draft[scopeKey(n)] = g.role;
        break;
      }
    }
  }
  return draft;
}

/// Role [node] gets from its ancestors when it has no explicit grant.
/// [base] are grants outside this space that still apply (a workspace grant).
String inheritedRole(List<ScopeNode> nodes, GrantDraft draft, ScopeNode node, [List<GrantInput> base = const []]) {
  final path = scopeNodePath(nodes, node);
  switch (node.kind) {
    case 'space':
      path.spaceId = null;
    case 'group':
      path.groupId = null;
    case 'item':
      path.itemId = null;
    case 'environment':
      path.environmentId = null;
    case 'general':
      path.general = false;
  }
  return roleFromGrants([...base, ...draftToGrants(nodes, draft)], path);
}

/// At least one node in the space ends up readable.
bool hasReadableGrant(List<ScopeNode> nodes, GrantDraft draft, [List<GrantInput> base = const []]) {
  final grants = [...base, ...draftToGrants(nodes, draft)];
  return nodes.any((n) => roleRank(roleFromGrants(grants, scopeNodePath(nodes, n))) >= 1);
}

/// Grants on nodes outside [nodes] (other spaces, the workspace) stay as they are.
List<GrantInput> grantsOutside(List<ScopeNode> nodes, List<GrantInput> grants) {
  final keys = {for (final n in nodes) scopeKey(n)};
  return [for (final g in grants) if (!keys.contains(nodeKey(g.kind, g.id))) g];
}

final _email = RegExp(r'^[^\s@]+@[^\s@]+\.[^\s@]+$');

bool isValidEmail(String email) => _email.hasMatch(email.trim());

/// "Editor on Work, Viewer on Work / Backend".
String summarizeGrants(List<Grant> grants) {
  if (grants.isEmpty) return 'No access yet';
  return grants.map((g) => '${roleLabels[g.role] ?? g.role} on ${g.label}').join(', ');
}

/// The space a grant lives in, for filtering a space's members.
String? spaceOfGrant(Grant g, List<Group> groups, List<Item> items) {
  if (g.spaceId != null) return g.spaceId;
  if (g.kind == 'space') return g.id;
  if (g.kind == 'group') return groups.where((x) => x.id == g.id).firstOrNull?.spaceId;
  if (g.kind == 'item' || g.kind == 'general') {
    final item = items.where((x) => x.id == g.id).firstOrNull;
    return groups.where((x) => x.id == item?.groupId).firstOrNull?.spaceId;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Plans (F13)
// ---------------------------------------------------------------------------

/// Why sharing is unavailable, or null when it is available.
enum SharingBlock { needsPro, paused, needsSync }

SharingBlock? sharingBlock(PlanStatus? plan) {
  if (plan == null) return null;
  if (plan.isFree) return SharingBlock.needsPro;
  if (plan.isPaused) return SharingBlock.paused;
  if (!plan.relayConfigured) return SharingBlock.needsSync;
  return null;
}

const sharingBlockCopy = {
  SharingBlock.needsPro: (
    title: 'Sharing needs Pro and sync',
    body: 'People get their own key through the sync relay, which comes with Pro. Everything here keeps working on this phone.',
  ),
  SharingBlock.paused: (
    title: 'Sync is paused',
    body: 'Pro ended, so sharing and sync are paused. Everything stays on this phone and you can still export it. '
        'Renew Pro to invite people again.',
  ),
  SharingBlock.needsSync: (
    title: 'Set up sync to share',
    body: 'Members get access through the sync relay. Set it up in Settings > Sync, then invite people here.',
  ),
};

bool isPlanError(SecwetException e) => const {'needs_pro', 'sync_paused', 'relay_not_entitled'}.contains(e.code.toLowerCase());

bool isRelayNotConfigured(SecwetException e) =>
    const {'relay_not_configured', 'relay_relay_not_configured'}.contains(e.code.toLowerCase());
