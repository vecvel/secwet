// Role and permission helpers for member mode, ported 1:1 from the desktop
// (apps/desktop/src/lib/access.ts, docs/m7-m8-architecture.md §4). Pure
// functions over plain data so they can be unit tested.
import '../../core/models.dart';

/// Where an action happens, from the space down. Leave deeper levels unset
/// for container actions.
class NodePath {
  const NodePath({this.spaceId, this.groupId, this.itemId, this.environmentId, this.general = false});

  final String? spaceId;
  final String? groupId;
  final String? itemId;

  /// Set for content inside an environment.
  final String? environmentId;

  /// True for item-wide content (the "General" scope, environment null).
  final bool general;
}

/// What this device may do at one node.
class Permissions {
  const Permissions({
    required this.role,
    required this.readOnly,
    required this.canView,
    required this.canWrite,
    required this.canDelete,
    required this.canManage,
    required this.canShare,
  });

  factory Permissions.fromRole(String role, bool readOnly) {
    final rank = roleRank(role);
    return Permissions(
      role: role,
      readOnly: readOnly,
      canView: rank >= 1,
      canWrite: !readOnly && rank >= 2,
      canDelete: !readOnly && rank >= 3,
      canManage: !readOnly && rank >= 3,
      canShare: !readOnly && rank >= 3,
    );
  }

  final String role;
  final bool readOnly;

  /// Read, reveal, copy, download.
  final bool canView;

  /// Create or update secrets, notes and files.
  final bool canWrite;

  /// Delete secrets, notes and files.
  final bool canDelete;

  /// Create, rename and delete groups, items and environments.
  final bool canManage;

  /// Invite people and change their access.
  final bool canShare;
}

int roleRank(String role) => switch (role) {
      'admin' => 3,
      'editor' => 2,
      'viewer' => 1,
      _ => 0,
    };

/// This device was unlinked (sync-only revoke): the store is a read-only archive.
bool isReadOnly(LinkStatus? link) => link?.state == 'unlinked';

List<(String, String?)> _pathNodes(NodePath path) {
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

bool _sameNode(Grant g, String kind, String? id) {
  if (g.kind != kind) return false;
  if (kind == 'workspace') return true;
  return g.id == id;
}

/// Role at the deepest node of [path]: the most specific explicit grant on the
/// path wins. Owners (and a missing access view) are Admin everywhere.
String effectiveRole(Access? access, NodePath path) {
  if (access == null || access.isOwner) return 'admin';
  var role = 'no_access';
  for (final (kind, id) in _pathNodes(path)) {
    for (final g in access.grants) {
      if (_sameNode(g, kind, id)) {
        role = g.role;
        break;
      }
    }
  }
  return role;
}

Permissions permissionsFor(Access? access, bool readOnly, NodePath path) =>
    Permissions.fromRole(effectiveRole(access, path), readOnly);

/// Owners and anyone holding Admin on some node can open the Members section.
bool canManageMembers(Access? access) => access == null || access.isOwner || access.grants.any((g) => g.role == 'admin');

/// Creating spaces needs Admin at the workspace level (the owner, in practice).
bool canCreateSpace(Access? access, bool readOnly) => !readOnly && effectiveRole(access, const NodePath()) == 'admin';

/// Pairing adds an owner device; the relay refuses it from a member's device.
bool canPairDevices(Access? access, bool readOnly) => !readOnly && (access == null || access.isOwner);

/// Rotating the master key is for owner devices only.
bool canRotateMasterKey(Access? access, bool readOnly) => !readOnly && (access == null || access.isOwner);

/// The Personal space is never shared.
bool isShareableSpace(Space? space) => space != null && !space.isDefault;
