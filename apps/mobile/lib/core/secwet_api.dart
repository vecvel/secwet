import 'dart:typed_data';

import 'bridge.dart';
import 'models.dart';
import 'platform_services.dart';

export 'bridge.dart' show SecwetBridge, SecwetEvent, SecwetException;
export 'models.dart';
export 'platform_services.dart' show PickedFile, PlatformServices;
export 'read_when_idle.dart';

/// The stable Dart API of the Secwet app layer. Every method maps to one
/// app-layer command (the same contract as the desktop Tauri commands)
/// and throws [SecwetException] on failure.
///
/// Screens get it with `SecwetScope.of(context).api`. Lists come back fresh
/// on every call; listen to [events] (`changed` with a scope) to refresh.
class SecwetApi {
  SecwetApi(this._bridge, {PlatformServices? platform}) : platform = platform ?? PlatformServices();

  final SecwetBridge _bridge;

  /// Native services that are not app-layer commands: device name, document
  /// picker, share sheet.
  final PlatformServices platform;

  Stream<SecwetEvent> get events => _bridge.events;

  Future<Object?> _call(String cmd, [Map<String, Object?> args = const {}]) => _bridge.call(cmd, args);

  Future<Json> _obj(String cmd, [Map<String, Object?> args = const {}]) async =>
      ((await _call(cmd, args)) as Map).cast<String, Object?>();

  Future<List<T>> _list<T>(String cmd, T Function(Json) f, [Map<String, Object?> args = const {}]) async =>
      [for (final e in (await _call(cmd, args)) as List) f((e as Map).cast<String, Object?>())];

  // -------------------------------------------------------------------------
  // Lifecycle
  // -------------------------------------------------------------------------

  Future<SecwetStatus> status() async => SecwetStatus.fromJson(await _obj('secwet_status'));

  /// Creates a new Secwet on this phone and opens it.
  Future<SecwetStatus> create({String? deviceName}) async =>
      SecwetStatus.fromJson(await _obj('secwet_create', {'device_name': deviceName}));

  /// Opens the store. Rust shows the system prompt first and fails with
  /// `biometric_cancelled` / `biometric_failed`; a phone without a screen
  /// lock is refused with `screen_lock_required`.
  Future<void> unlock() => _call('secwet_unlock', const {});

  Future<void> lock() => _call('secwet_lock');

  // -------------------------------------------------------------------------
  // Spaces
  // -------------------------------------------------------------------------

  Future<List<Space>> spaces() => _list('spaces_list', Space.fromJson);

  Future<Space> createSpace(String name, {String? icon}) async =>
      Space.fromJson(await _obj('space_create', {'name': name, 'icon': icon}));

  Future<Space> renameSpace(String id, String name, {String? icon}) async =>
      Space.fromJson(await _obj('space_rename', {'id': id, 'name': name, 'icon': icon}));

  Future<void> deleteSpace(String id) => _call('space_delete', {'id': id});

  Future<void> reorderSpaces(List<String> ids) => _call('space_reorder', {'ids': ids});

  // -------------------------------------------------------------------------
  // Groups
  // -------------------------------------------------------------------------

  Future<List<Group>> groups() => _list('groups_list', Group.fromJson);

  Future<Group> createGroup(String name, {String? icon, String? spaceId}) async =>
      Group.fromJson(await _obj('group_create', {'name': name, 'icon': icon, 'space_id': spaceId}));

  Future<void> renameGroup(String id, String name, {String? icon}) =>
      _call('group_rename', {'id': id, 'name': name, 'icon': icon});

  Future<void> deleteGroup(String id) => _call('group_delete', {'id': id});

  Future<void> reorderGroups(List<String> ids) => _call('group_reorder', {'ids': ids});

  Future<void> moveGroupToSpace(String id, String spaceId) =>
      _call('group_move_to_space', {'id': id, 'space_id': spaceId});

  // -------------------------------------------------------------------------
  // Items
  // -------------------------------------------------------------------------

  Future<List<Item>> items({String? groupId}) => _list('items_list', Item.fromJson, {'label_id': groupId});

  Future<Item> createItem(String groupId, String name, {String? description}) async =>
      Item.fromJson(await _obj('item_create', {'label_id': groupId, 'name': name, 'description': description}));

  Future<void> renameItem(String id, String name, {String? description}) =>
      _call('item_rename', {'id': id, 'name': name, 'description': description});

  Future<void> deleteItem(String id) => _call('item_delete', {'id': id});

  // -------------------------------------------------------------------------
  // Environments
  // -------------------------------------------------------------------------

  Future<List<Environment>> environments(String itemId) =>
      _list('environments_list', Environment.fromJson, {'item_id': itemId});

  Future<Environment> addEnvironment(String itemId, String name) async =>
      Environment.fromJson(await _obj('environment_add', {'item_id': itemId, 'name': name}));

  Future<void> renameEnvironment(String id, String name) => _call('environment_rename', {'id': id, 'name': name});

  /// With [preserveContent] the environment's secrets, assets and notes move
  /// to the item's General scope instead of being deleted.
  Future<void> deleteEnvironment(String id, {bool? preserveContent}) =>
      _call('environment_delete', {'id': id, 'preserve_content': preserveContent});

  // -------------------------------------------------------------------------
  // Secrets
  // -------------------------------------------------------------------------

  Future<List<SecretMeta>> secrets({String? itemId, String? environmentId}) =>
      _list('secrets_list', SecretMeta.fromJson, {'item_id': itemId, 'environment_id': environmentId});

  /// The secret value. Show it only while the user asks to see it.
  Future<String> revealSecret(String id) async => (await _call('secret_reveal', {'id': id})) as String;

  /// Copies the value natively (never through Dart); the clipboard clears
  /// itself after 30 seconds if it still holds the value.
  Future<void> copySecret(String id) => _call('secret_copy', {'id': id});

  Future<SecretMeta> createSecret(SecretDraft draft) async =>
      SecretMeta.fromJson(await _obj('secret_create', {'draft': draft.toJson()}));

  Future<SecretMeta> updateSecret(String id, SecretDraft draft) async =>
      SecretMeta.fromJson(await _obj('secret_update', {'id': id, 'draft': draft.toJson()}));

  Future<void> deleteSecret(String id) => _call('secret_delete', {'id': id});

  /// Copies a secret into another environment (null: the item's General scope).
  Future<SecretMeta> copySecretToEnvironment(String id, String? targetEnvironmentId) async => SecretMeta.fromJson(
      await _obj('secret_copy_to_environment', {'id': id, 'target_environment_id': targetEnvironmentId}));

  // -------------------------------------------------------------------------
  // Assets
  // -------------------------------------------------------------------------

  Future<List<AssetMeta>> assets(String itemId, {String? environmentId}) =>
      _list('assets_list', AssetMeta.fromJson, {'item_id': itemId, 'environment_id': environmentId});

  Future<AssetMeta> uploadAsset(String itemId, String name, Uint8List bytes, {String? environmentId, String? mime}) async =>
      AssetMeta.fromJson(await _obj('asset_upload', {
        'item_id': itemId,
        'environment_id': environmentId,
        'name': name,
        'mime': mime,
        'bytes': bytes,
      }));

  Future<AssetDownload> downloadAsset(String id) async => AssetDownload.fromJson(await _obj('asset_download', {'id': id}));

  Future<AssetMeta> renameAsset(String id, String name) async =>
      AssetMeta.fromJson(await _obj('asset_rename', {'id': id, 'name': name}));

  Future<void> deleteAsset(String id) => _call('asset_delete', {'id': id});

  // -------------------------------------------------------------------------
  // Notes
  // -------------------------------------------------------------------------

  Future<List<NoteMeta>> notes(String itemId, {String? environmentId}) =>
      _list('notes_list', NoteMeta.fromJson, {'item_id': itemId, 'environment_id': environmentId});

  Future<Note> note(String id) async => Note.fromJson(await _obj('note_get', {'id': id}));

  Future<Note> createNote(String itemId, String title, String content, {String? environmentId}) async =>
      Note.fromJson(await _obj('note_create', {
        'draft': {'item_id': itemId, 'environment_id': environmentId, 'title': title, 'content': content},
      }));

  Future<Note> updateNote(String id, {String? title, String? content}) async =>
      Note.fromJson(await _obj('note_update', {
        'id': id,
        'draft': {'title': title, 'content': content},
      }));

  Future<void> deleteNote(String id) => _call('note_delete', {'id': id});

  /// Copies the note as plain text (native clipboard, auto-cleared).
  Future<void> copyNotePlain(String id) => _call('note_copy_plain', {'id': id});

  /// Copies [text] with the same clipboard protection as secrets.
  Future<void> copyText(String text) => _call('clipboard_copy_text', {'text': text});

  // -------------------------------------------------------------------------
  // Overview and dashboard
  // -------------------------------------------------------------------------

  Future<Overview> overview() async => Overview.fromJson(await _obj('overview'));

  Future<DashboardConfig> dashboard() async => DashboardConfig.fromJson(await _obj('dashboard_get'));

  Future<void> setDashboard(DashboardConfig config) => _call('dashboard_set', {'config': config.toJson()});

  // -------------------------------------------------------------------------
  // Settings and biometrics
  // -------------------------------------------------------------------------

  Future<Settings> settings() async => Settings.fromJson(await _obj('settings_get'));

  Future<Settings> updateSettings({String? theme, int? lockTimeoutMinutes, String? deviceName}) async =>
      Settings.fromJson(await _obj('settings_set', {
        'settings': {'theme': theme, 'lock_timeout_minutes': lockTimeoutMinutes, 'device_name': deviceName},
      }));

  /// The device name the native side reported (UIDevice / Settings.Global).
  Future<String> systemDeviceName() async => (await _call('system_device_name')) as String;

  /// How this phone unlocks: screen lock and biometric.
  Future<BiometricStatus> biometricStatus() async => BiometricStatus.fromJson(await _obj('biometric_status'));

  // -------------------------------------------------------------------------
  // Recovery and backup
  // -------------------------------------------------------------------------

  /// Creates the recovery key and returns it once; show it, never store it.
  Future<String> createRecoveryKey() async => (await _call('recovery_key_create')) as String;

  Future<String> replaceRecoveryKey() async => (await _call('recovery_key_replace')) as String;

  Future<RecoveryStatus> recoveryStatus() async => RecoveryStatus.fromJson(await _obj('recovery_status'));

  /// Writes an encrypted `.secwet` archive to [path] (an app file; hand it to
  /// [PlatformServices.saveFile] afterwards so the user picks where it goes).
  Future<ExportSummary> exportWorkspace({required String path, required String recoveryKey}) async =>
      ExportSummary.fromJson(await _obj('workspace_export', {'path': path, 'recovery_key': recoveryKey}));

  /// Restores an archive picked with [PlatformServices.pickFile].
  Future<SecwetStatus> restoreWorkspace({required String path, required String recoveryKey, String? deviceName}) async =>
      SecwetStatus.fromJson(await _obj('workspace_restore', {
        'path': path,
        'recovery_key': recoveryKey,
        'device_name': deviceName,
      }));

  // -------------------------------------------------------------------------
  // Relay
  // -------------------------------------------------------------------------

  Future<RelayStatus> relayStatus() async => RelayStatus.fromJson(await _obj('relay_status'));

  Future<RelayRegistration> relayRegister() async => RelayRegistration.fromJson(await _obj('relay_register'));

  Future<void> setRelayUrl(String url) => _call('relay_set_url', {'url': url});

  // -------------------------------------------------------------------------
  // Devices and pairing
  // -------------------------------------------------------------------------

  Future<List<Device>> devices() => _list('devices_list', Device.fromJson);

  Future<PairingSession> startPairing() async => PairingSession.fromJson(await _obj('pairing_start'));

  Future<PairingPoll> pollPairing() async => PairingPoll.fromJson(await _obj('pairing_poll'));

  Future<Device> approvePairing() async => Device.fromJson(await _obj('pairing_approve'));

  Future<void> cancelPairing() => _call('pairing_cancel');

  /// This phone as the new device: joins the session in a scanned
  /// `secwet://pair` link and returns the code to compare.
  Future<PairingJoinInfo> joinPairing(String link, {String? deviceName}) async =>
      PairingJoinInfo.fromJson(await _obj('pairing_join_start', {'link': link, 'device_name': deviceName}));

  /// Approved: the Secwet now exists on this phone and is open.
  Future<PairingJoinPoll> pollPairingJoin() async => PairingJoinPoll.fromJson(await _obj('pairing_join_poll'));

  Future<void> cancelPairingJoin() => _call('pairing_join_cancel');

  // -------------------------------------------------------------------------
  // Plan
  // -------------------------------------------------------------------------

  /// The cached plan; never contacts the relay.
  Future<PlanStatus> planStatus() async => PlanStatus.fromJson(await _obj('plan_status'));

  /// Re-reads the entitlement on Pro and paused (Free: cached, no network).
  Future<PlanStatus> refreshPlan() async => PlanStatus.fromJson(await _obj('plan_refresh'));

  /// "Check for Pro": the one relay call a Free Secwet makes.
  Future<PlanStatus> activatePlan() async => PlanStatus.fromJson(await _obj('plan_activate'));

  // -------------------------------------------------------------------------
  // Sync
  // -------------------------------------------------------------------------

  Future<SyncResult> syncNow() async => SyncResult.fromJson(await _obj('sync_now'));

  Future<SyncStatus> syncStatus() async => SyncStatus.fromJson(await _obj('sync_status'));

  // -------------------------------------------------------------------------
  // Revocation and key rotation
  // -------------------------------------------------------------------------

  /// Revokes a device. With [wipe] the device erases its local copy (remote
  /// wipe); without, it keeps its data but stops syncing.
  Future<RevokeResult> revokeDevice(String deviceId, {bool wipe = false}) async =>
      RevokeResult.fromJson(await _obj('device_revoke', {'device_id': deviceId, 'wipe': wipe}));

  Future<KeyStatus> keyStatus() async => KeyStatus.fromJson(await _obj('key_status'));

  Future<KeyRotationReport> rotateKey() async => KeyRotationReport.fromJson(await _obj('key_rotate'));

  Future<LinkStatus> linkStatus() async => LinkStatus.fromJson(await _obj('link_status'));

  // -------------------------------------------------------------------------
  // Collaboration
  // -------------------------------------------------------------------------

  Future<List<Member>> members() => _list('members_list', Member.fromJson);

  Future<InviteResult> invite(String email, List<GrantInput> grants) async => InviteResult.fromJson(
      await _obj('member_invite', {'email': email, 'grants': [for (final g in grants) g.toJson()]}));

  Future<Member> setGrants(String memberId, List<GrantInput> grants) async => Member.fromJson(
      await _obj('member_set_grants', {'member_id': memberId, 'grants': [for (final g in grants) g.toJson()]}));

  Future<void> removeMember(String memberId, {bool wipe = false}) =>
      _call('member_remove', {'member_id': memberId, 'wipe': wipe});

  Future<void> revokeInvitation(String invitationId) => _call('invitation_revoke', {'invitation_id': invitationId});

  /// Joins a shared Secwet from an invite link on this phone.
  Future<SecwetStatus> acceptInvitation({required String link, required String email, String? deviceName}) async =>
      SecwetStatus.fromJson(await _obj('invitation_accept', {'link': link, 'email': email, 'device_name': deviceName}));

  Future<List<ScopeNode>> scopeNodes(String spaceId) => _list('scope_nodes', ScopeNode.fromJson, {'space_id': spaceId});

  Future<Access> myAccess() async => Access.fromJson(await _obj('my_access'));

  /// Copies a pending invitation's link again (kept in memory until lock).
  Future<void> copyInviteLink(String invitationId) => _call('invite_link_copy', {'invitation_id': invitationId});

  // -------------------------------------------------------------------------
  // Compatibility and CLI sessions
  // -------------------------------------------------------------------------

  Future<List<ProjectSummary>> projects() => _list('projects_list', ProjectSummary.fromJson);

  Future<List<ActiveSession>> activeSessions() => _list('active_sessions_list', ActiveSession.fromJson);

  Future<void> stopActiveSession(String sessionId) => _call('active_session_stop', {'session_id': sessionId});
}
