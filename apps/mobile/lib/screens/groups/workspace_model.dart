import 'dart:async';

import 'package:flutter/widgets.dart';

import '../../app/secwet_scope.dart';
import '../../core/secwet_api.dart';
import '../../core/session.dart';
import 'access.dart';

/// The workspace tree the Groups and Overview tabs share (the desktop store's
/// spaces, groups, items, active space, access and link state). One per
/// session; it reloads on every `changed` event and empties when Secwet locks,
/// so nothing outlives the unlocked session.
class WorkspaceModel extends ChangeNotifier {
  WorkspaceModel._(this._session) {
    _events = api.events.listen(_onEvent);
    _session.addListener(_onSession);
  }

  static final _bySession = Expando<WorkspaceModel>('workspace');

  /// The model for the current session; screens rebuild through
  /// `ListenableBuilder` or [watch].
  static WorkspaceModel of(BuildContext context) {
    final session = SecwetScope.read(context).session;
    return _bySession[session] ??= WorkspaceModel._(session);
  }

  final SessionController _session;
  late final StreamSubscription<SecwetEvent> _events;

  SecwetApi get api => _session.api;

  List<Space> spaces = const [];
  List<Group> groups = const [];
  List<Item> items = const [];
  Access? access;
  LinkStatus? link;

  /// Null means Global (every space). Defaults to the Personal space until the
  /// user picks one, like the desktop.
  String? activeSpaceId;
  bool _chosenSpace = false;

  /// The item last opened from the Groups tab, highlighted in the list.
  String? selectedItemId;

  bool loaded = false;
  Future<void>? _loading;
  bool _again = false;

  bool get readOnly => isReadOnly(link);

  Space? get activeSpace => activeSpaceId == null ? null : spaceById(activeSpaceId);

  Space? spaceById(String? id) {
    for (final s in spaces) {
      if (s.id == id) return s;
    }
    return null;
  }

  Group? groupById(String? id) {
    for (final g in groups) {
      if (g.id == id) return g;
    }
    return null;
  }

  Item? itemById(String? id) {
    for (final i in items) {
      if (i.id == id) return i;
    }
    return null;
  }

  Space? get personalSpace {
    for (final s in spaces) {
      if (s.isDefault || s.name.toLowerCase() == 'personal') return s;
    }
    return null;
  }

  /// Groups in the active space (all of them in Global).
  List<Group> get visibleGroups =>
      activeSpaceId == null ? groups : [for (final g in groups) if (g.spaceId == activeSpaceId) g];

  List<Item> get visibleItems {
    if (activeSpaceId == null) return items;
    final ids = {for (final g in visibleGroups) g.id};
    return [for (final i in items) if (ids.contains(i.groupId)) i];
  }

  List<Item> itemsOf(String groupId) => [for (final i in items) if (i.groupId == groupId) i];

  // ---------------------------------------------------------------------------
  // Permissions (desktop App.tsx)
  // ---------------------------------------------------------------------------

  Permissions spacePerms(String? spaceId) => permissionsFor(access, readOnly, NodePath(spaceId: spaceId));

  Permissions groupPerms(String? groupId) =>
      permissionsFor(access, readOnly, NodePath(spaceId: groupById(groupId)?.spaceId, groupId: groupId));

  NodePath itemPath(Item item) => NodePath(spaceId: groupById(item.groupId)?.spaceId, groupId: item.groupId, itemId: item.id);

  Permissions itemPerms(Item item) => permissionsFor(access, readOnly, itemPath(item));

  /// Permissions for content in [environmentId] of [item] (null: General).
  Permissions scopePerms(Item item, String? environmentId) {
    final base = itemPath(item);
    return permissionsFor(
      access,
      readOnly,
      NodePath(
        spaceId: base.spaceId,
        groupId: base.groupId,
        itemId: item.id,
        environmentId: environmentId,
        general: environmentId == null,
      ),
    );
  }

  List<Space> get manageableSpaces => [for (final s in spaces) if (spacePerms(s.id).canManage) s];

  bool get canCreateGroupHere =>
      activeSpaceId != null ? spacePerms(activeSpaceId).canManage : manageableSpaces.isNotEmpty;

  bool get canCreateSpaceHere => canCreateSpace(access, readOnly);

  bool get canManageMembersHere => canManageMembers(access);

  bool canShareSpace(Space s) => isShareableSpace(s) && spacePerms(s.id).canShare;

  /// The group a new entry goes into from Overview's New.
  String? get newTargetGroupId => visibleGroups.isEmpty ? null : visibleGroups.first.id;

  bool get canCreateFromTopBar =>
      visibleGroups.isEmpty ? canCreateGroupHere : groupPerms(newTargetGroupId).canManage;

  /// The space a new group defaults to.
  String? get defaultSpaceForNewGroup {
    final manageable = manageableSpaces;
    bool ok(String? id) => id != null && manageable.any((s) => s.id == id);
    if (ok(activeSpaceId)) return activeSpaceId;
    if (ok(personalSpace?.id)) return personalSpace!.id;
    return manageable.isEmpty ? null : manageable.first.id;
  }

  // ---------------------------------------------------------------------------
  // Loading
  // ---------------------------------------------------------------------------

  /// Loads once per session; later calls reuse the data.
  Future<void> ensureLoaded() => loaded ? Future.value() : reload();

  /// Re-reads the tree. Overlapping calls coalesce into one extra pass.
  Future<void> reload() {
    if (_loading != null) {
      _again = true;
      return _loading!;
    }
    return _loading = _load().whenComplete(() {
      _loading = null;
      if (_again) {
        _again = false;
        reload();
      }
    });
  }

  Future<void> _load() async {
    if (_session.state != SessionState.unlocked) return;
    // Auto-sync on open holds the store for a moment; wait it out.
    final results = await Future.wait([readWhenIdle(api.spaces), readWhenIdle(api.groups), readWhenIdle(api.items)]);
    if (results.any((r) => r == null)) return; // Locked meanwhile.
    spaces = results[0] as List<Space>;
    groups = results[1] as List<Group>;
    items = results[2] as List<Item>;
    try {
      access = await api.myAccess();
    } on SecwetException {
      access = null; // No member mode on this store: owner everywhere.
    }
    try {
      link = await api.linkStatus();
    } on SecwetException {
      link = null;
    }
    final fallback = personalSpace ?? (spaces.isEmpty ? null : spaces.first);
    if (!_chosenSpace) {
      activeSpaceId = fallback?.id;
    } else if (activeSpaceId != null && spaceById(activeSpaceId) == null) {
      activeSpaceId = fallback?.id;
    }
    loaded = true;
    notifyListeners();
  }

  void selectSpace(String? id) {
    _chosenSpace = true;
    activeSpaceId = id;
    notifyListeners();
  }

  void selectItem(String? id) {
    selectedItemId = id;
    notifyListeners();
  }

  // ---------------------------------------------------------------------------
  // Mutations that change the active space (desktop store)
  // ---------------------------------------------------------------------------

  Future<Space> createSpace(String name, String icon) async {
    final space = await api.createSpace(name, icon: icon);
    await reload();
    selectSpace(space.id);
    return space;
  }

  Future<void> deleteSpace(String id) async {
    await api.deleteSpace(id);
    if (activeSpaceId == id) activeSpaceId = personalSpace?.id;
    await reload();
  }

  Future<Group> createGroup(String name, String? spaceId) async {
    final group = await api.createGroup(name, icon: 'folder', spaceId: spaceId);
    if (group.spaceId != null && activeSpaceId != null && activeSpaceId != group.spaceId) {
      _chosenSpace = true;
      activeSpaceId = group.spaceId;
    }
    await reload();
    return group;
  }

  /// Moves [groupId] one place up (-1) or down (+1) inside its space.
  Future<void> moveGroup(String groupId, int direction) async {
    final group = groupById(groupId);
    if (group == null) return;
    final ordered = [for (final g in groups) g]..sort((a, b) => a.position.compareTo(b.position));
    final siblings = [for (final g in ordered) if (g.spaceId == group.spaceId) g];
    final i = siblings.indexWhere((g) => g.id == groupId);
    final j = i + direction;
    if (i < 0 || j < 0 || j >= siblings.length) return;
    final other = siblings[j];
    final ids = [for (final g in ordered) g.id];
    final a = ids.indexOf(groupId);
    final b = ids.indexOf(other.id);
    ids[a] = other.id;
    ids[b] = groupId;
    await api.reorderGroups(ids);
    await reload();
  }

  void _onEvent(SecwetEvent e) {
    if (e.isChanged && loaded) reload();
  }

  void _onSession() {
    if (_session.state == SessionState.unlocked) return;
    // Locked, wiped or signed out: drop the tree and the space choice.
    spaces = const [];
    groups = const [];
    items = const [];
    access = null;
    link = null;
    activeSpaceId = null;
    selectedItemId = null;
    _chosenSpace = false;
    loaded = false;
  }

  @override
  void dispose() {
    _events.cancel();
    _session.removeListener(_onSession);
    super.dispose();
  }
}
