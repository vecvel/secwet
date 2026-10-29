// Typed models for the app-layer DTOs. Field names follow the Rust serde
// output (crates/secwet-proto, crates/secwet-app); ids are UUID strings and
// timestamps are Unix seconds unless noted.
import 'dart:typed_data';

typedef Json = Map<String, Object?>;

int _int(Object? v) => (v as num?)?.toInt() ?? 0;
int? _intOrNull(Object? v) => (v as num?)?.toInt();
String _str(Object? v) => v as String? ?? '';
List<T> _list<T>(Object? v, T Function(Json) f) =>
    [for (final e in (v as List?) ?? const []) f((e as Map).cast<String, Object?>())];
List<String> _strings(Object? v) => [for (final e in (v as List?) ?? const []) e as String];

DateTime? fromUnix(int? seconds) =>
    seconds == null || seconds == 0 ? null : DateTime.fromMillisecondsSinceEpoch(seconds * 1000);

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

enum LockState { uninitialized, locked, unlocked }

class SecwetStatus {
  const SecwetStatus(this.state, this.secwetId);

  factory SecwetStatus.fromJson(Json j) => SecwetStatus(
        LockState.values.byName(_str(j['status'])),
        j['secwet_id'] as String?,
      );

  final LockState state;
  final String? secwetId;
}

// ---------------------------------------------------------------------------
// Spaces, groups, items, environments
// ---------------------------------------------------------------------------

class Space {
  const Space({required this.id, required this.name, required this.position, this.icon, required this.isDefault, required this.groupsCount});

  factory Space.fromJson(Json j) => Space(
        id: _str(j['id']),
        name: _str(j['name']),
        position: _int(j['position']),
        icon: j['icon'] as String?,
        isDefault: j['is_default'] as bool? ?? false,
        groupsCount: _int(j['groups_count']),
      );

  final String id;
  final String name;
  final int position;
  final String? icon;
  final bool isDefault;
  final int groupsCount;
}

/// A group (stored as a label) inside a space.
class Group {
  const Group({required this.id, this.spaceId, required this.name, required this.position, this.icon, required this.itemsCount});

  factory Group.fromJson(Json j) => Group(
        id: _str(j['id']),
        spaceId: j['space_id'] as String?,
        name: _str(j['name']),
        position: _int(j['position']),
        icon: j['icon'] as String?,
        itemsCount: _int(j['items_count']),
      );

  final String id;
  final String? spaceId;
  final String name;
  final int position;
  final String? icon;
  final int itemsCount;
}

class Item {
  const Item({
    required this.id,
    required this.groupId,
    required this.name,
    this.description,
    required this.position,
    required this.environmentsCount,
    required this.secretsCount,
    required this.assetsCount,
    required this.notesCount,
  });

  factory Item.fromJson(Json j) => Item(
        id: _str(j['id']),
        groupId: _str(j['label_id']),
        name: _str(j['name']),
        description: j['description'] as String?,
        position: _int(j['position']),
        environmentsCount: _int(j['environments_count']),
        secretsCount: _int(j['secrets_count']),
        assetsCount: _int(j['assets_count']),
        notesCount: _int(j['notes_count']),
      );

  final String id;
  final String groupId;
  final String name;
  final String? description;
  final int position;
  final int environmentsCount;
  final int secretsCount;
  final int assetsCount;
  final int notesCount;
}

class Environment {
  const Environment({required this.id, required this.itemId, required this.name, required this.position, required this.secretCount});

  factory Environment.fromJson(Json j) => Environment(
        id: _str(j['id']),
        itemId: _str(j['project_id'] ?? j['item_id']),
        name: _str(j['name']),
        position: _int(j['position']),
        secretCount: _int(j['secret_count']),
      );

  final String id;
  final String itemId;
  final String name;
  final int position;
  final int secretCount;
}

// ---------------------------------------------------------------------------
// Secrets, assets, notes
// ---------------------------------------------------------------------------

enum SecretKind {
  password('password', 'Password'),
  apiKey('api_key', 'API key'),
  accessToken('access_token', 'Access token'),
  envVar('env_var', 'Environment variable'),
  sshKey('ssh_key', 'SSH key'),
  certificate('certificate', 'Certificate'),
  codes('codes', 'Codes');

  const SecretKind(this.wire, this.label);

  final String wire;
  final String label;

  static SecretKind fromWire(String v) => values.firstWhere((k) => k.wire == v, orElse: () => password);
}

/// Secret metadata. The value never comes with it; `valueTail` is the last
/// four characters for display.
class SecretMeta {
  const SecretMeta({
    required this.id,
    required this.itemId,
    this.environmentId,
    required this.name,
    required this.kind,
    this.note,
    required this.updatedAt,
    required this.valueTail,
  });

  factory SecretMeta.fromJson(Json j) => SecretMeta(
        id: _str(j['id']),
        itemId: _str(j['project_id'] ?? j['item_id']),
        environmentId: j['environment_id'] as String?,
        name: _str(j['name']),
        kind: SecretKind.fromWire(_str(j['kind'])),
        note: j['note'] as String?,
        updatedAt: _int(j['updated_at']),
        valueTail: _str(j['value_tail']),
      );

  final String id;
  final String itemId;
  final String? environmentId;
  final String name;
  final SecretKind kind;
  final String? note;
  final int updatedAt;
  final String valueTail;
}

/// Input for creating or updating a secret.
class SecretDraft {
  const SecretDraft({required this.itemId, this.environmentId, required this.name, required this.kind, required this.value, this.note});

  final String itemId;
  final String? environmentId;
  final String name;
  final SecretKind kind;
  final String value;
  final String? note;

  Json toJson() => {
        'item_id': itemId,
        'environment_id': environmentId,
        'name': name,
        'kind': kind.wire,
        'value': value,
        'note': note,
      };
}

class AssetMeta {
  const AssetMeta({
    required this.id,
    required this.itemId,
    this.environmentId,
    required this.name,
    required this.sizeBytes,
    required this.mimeType,
    required this.sha256,
    required this.updatedAt,
  });

  factory AssetMeta.fromJson(Json j) => AssetMeta(
        id: _str(j['id']),
        itemId: _str(j['item_id']),
        environmentId: j['environment_id'] as String?,
        name: _str(j['name']),
        sizeBytes: _int(j['size_bytes']),
        mimeType: _str(j['mime_type']),
        sha256: _str(j['sha256']),
        updatedAt: _int(j['updated_at']),
      );

  final String id;
  final String itemId;
  final String? environmentId;
  final String name;
  final int sizeBytes;
  final String mimeType;
  final String sha256;
  final int updatedAt;
}

class AssetDownload {
  const AssetDownload(this.meta, this.bytes);

  /// Copies the decoded number list into [bytes] and zeroes the list, so the
  /// only plaintext copy left in Dart is [bytes], which callers wipe.
  factory AssetDownload.fromJson(Json j) {
    final source = (j['bytes'] as List?) ?? const [];
    final bytes = Uint8List(source.length);
    for (var i = 0; i < source.length; i++) {
      bytes[i] = (source[i] as num).toInt();
    }
    if (source.isNotEmpty) source.fillRange(0, source.length, 0);
    return AssetDownload(AssetMeta.fromJson((j['meta'] as Map).cast()), bytes);
  }

  final AssetMeta meta;
  final Uint8List bytes;
}

class NoteMeta {
  const NoteMeta({required this.id, required this.itemId, this.environmentId, required this.title, required this.snippet, required this.updatedAt, required this.position});

  factory NoteMeta.fromJson(Json j) => NoteMeta(
        id: _str(j['id']),
        itemId: _str(j['item_id']),
        environmentId: j['environment_id'] as String?,
        title: _str(j['title']),
        snippet: _str(j['snippet']),
        updatedAt: _int(j['updated_at']),
        position: _int(j['position']),
      );

  final String id;
  final String itemId;
  final String? environmentId;
  final String title;
  final String snippet;
  final int updatedAt;
  final int position;
}

/// A note with its (HTML) content.
class Note {
  const Note({required this.id, required this.itemId, this.environmentId, required this.title, required this.content, required this.updatedAt, required this.position});

  factory Note.fromJson(Json j) => Note(
        id: _str(j['id']),
        itemId: _str(j['item_id']),
        environmentId: j['environment_id'] as String?,
        title: _str(j['title']),
        content: _str(j['content']),
        updatedAt: _int(j['updated_at']),
        position: _int(j['position']),
      );

  final String id;
  final String itemId;
  final String? environmentId;
  final String title;
  final String content;
  final int updatedAt;
  final int position;
}

// ---------------------------------------------------------------------------
// Overview and dashboard
// ---------------------------------------------------------------------------

class RecentSecret {
  const RecentSecret({required this.id, required this.name, required this.itemId, required this.itemName, required this.environmentId, required this.environmentName, required this.updatedAt});

  factory RecentSecret.fromJson(Json j) => RecentSecret(
        id: _str(j['id']),
        name: _str(j['name']),
        itemId: _str(j['project_id']),
        itemName: _str(j['project_name']),
        environmentId: _str(j['environment_id']),
        environmentName: _str(j['environment_name']),
        updatedAt: _int(j['updated_at']),
      );

  final String id;
  final String name;
  final String itemId;
  final String itemName;
  final String environmentId;
  final String environmentName;
  final int updatedAt;
}

class Checklist {
  const Checklist({required this.secwetCreated, required this.recoveryKeyCreated, required this.cliConnected, required this.addDeviceDone, this.pendingRotation});

  factory Checklist.fromJson(Json j) => Checklist(
        secwetCreated: j['secwet_created'] as bool? ?? false,
        recoveryKeyCreated: j['recovery_key_created'] as bool? ?? false,
        cliConnected: j['cli_connected'] as bool? ?? false,
        addDeviceDone: j['add_device_done'] as bool? ?? false,
        pendingRotation: j['pending_rotation'] as String?,
      );

  final bool secwetCreated;
  final bool recoveryKeyCreated;
  final bool cliConnected;
  final bool addDeviceDone;
  final String? pendingRotation;
}

/// An item with its environments (the older "project" shape).
class ProjectSummary {
  const ProjectSummary({required this.id, required this.name, required this.environments});

  factory ProjectSummary.fromJson(Json j) =>
      ProjectSummary(id: _str(j['id']), name: _str(j['name']), environments: _list(j['environments'], Environment.fromJson));

  final String id;
  final String name;
  final List<Environment> environments;
}

class Overview {
  const Overview({
    required this.groupsCount,
    required this.itemsCount,
    required this.environmentsCount,
    required this.secretsCount,
    required this.assetsCount,
    required this.notesCount,
    required this.activeDevicesCount,
    required this.items,
    required this.recent,
    required this.checklist,
  });

  factory Overview.fromJson(Json j) => Overview(
        groupsCount: _int(j['labels_count']),
        itemsCount: _int(j['items_count']),
        environmentsCount: _int(j['environments_count']),
        secretsCount: _int(j['secrets_count']),
        assetsCount: _int(j['assets_count']),
        notesCount: _int(j['notes_count']),
        activeDevicesCount: _int(j['active_devices_count']),
        items: _list(j['projects'], ProjectSummary.fromJson),
        recent: _list(j['recent'], RecentSecret.fromJson),
        checklist: Checklist.fromJson((j['checklist'] as Map? ?? const {}).cast()),
      );

  final int groupsCount;
  final int itemsCount;
  final int environmentsCount;
  final int secretsCount;
  final int assetsCount;
  final int notesCount;
  final int activeDevicesCount;
  final List<ProjectSummary> items;
  final List<RecentSecret> recent;
  final Checklist checklist;
}

class DashboardConfig {
  const DashboardConfig({required this.homeLabel, required this.visibleKpis, required this.widgets});

  factory DashboardConfig.fromJson(Json j) => DashboardConfig(
        homeLabel: _str(j['home_label']),
        visibleKpis: _strings(j['visible_kpis']),
        widgets: _strings(j['widgets']),
      );

  final String homeLabel;
  final List<String> visibleKpis;
  final List<String> widgets;

  Json toJson() => {'home_label': homeLabel, 'visible_kpis': visibleKpis, 'widgets': widgets};
}

// ---------------------------------------------------------------------------
// Settings and biometrics
// ---------------------------------------------------------------------------

class Settings {
  const Settings({required this.theme, required this.lockTimeoutMinutes, required this.deviceName});

  factory Settings.fromJson(Json j) => Settings(
        theme: _str(j['theme']),
        lockTimeoutMinutes: _int(j['lock_timeout_minutes']),
        deviceName: _str(j['device_name']),
      );

  final String theme;
  final int lockTimeoutMinutes;
  final String deviceName;
}

/// Biometric unlock state. When [available] is false the UI hides every
/// biometric control and the default unlock is used.
/// How this phone unlocks (`biometric_status`). With a screen lock the
/// system prompt is always required; biometric wording only appears when a
/// biometric is enrolled ([available]).
class BiometricStatus {
  const BiometricStatus({
    required this.available,
    required this.kind,
    required this.enabled,
    required this.platformKind,
    this.deviceLock = true,
  });

  factory BiometricStatus.fromJson(Json j) => BiometricStatus(
        available: j['available'] as bool? ?? false,
        kind: _str(j['kind']),
        enabled: j['enabled'] as bool? ?? false,
        platformKind: _str(j['platform_kind']),
        deviceLock: j['device_lock'] as bool? ?? true,
      );

  static const unavailable = BiometricStatus(available: false, kind: 'none', enabled: false, platformKind: 'none');

  /// A biometric is enrolled and offered by the system prompt.
  final bool available;
  final String kind;

  /// The system prompt guards every unlock (true whenever [deviceLock]).
  final bool enabled;

  /// The phone has a passcode, PIN, pattern or password.
  final bool deviceLock;

  /// What the phone uses: `face_id`, `touch_id`, `optic_id`, `fingerprint`,
  /// `face`, `iris`, `multiple` or `none`.
  final String platformKind;

  /// Name used mid-sentence, as desktop biometricName (lib/biometric.ts):
  /// proper nouns keep their capitals ("Face ID"), the rest is lowercase
  /// ("fingerprint", "face unlock", "biometrics").
  String get label => switch (platformKind) {
        'face_id' => 'Face ID',
        'touch_id' => 'Touch ID',
        'optic_id' => 'Optic ID',
        'fingerprint' => 'fingerprint',
        'face' => 'face unlock',
        'iris' => 'iris unlock',
        _ => 'biometrics',
      };
}

class ActiveSession {
  const ActiveSession({required this.sessionId, required this.pid, required this.itemId, this.environmentId, required this.command, required this.secretIds, required this.startedAt});

  factory ActiveSession.fromJson(Json j) => ActiveSession(
        sessionId: _str(j['session_id']),
        pid: _int(j['pid']),
        itemId: _str(j['item_id']),
        environmentId: j['environment_id'] as String?,
        command: _str(j['command']),
        secretIds: _strings(j['secret_ids']),
        startedAt: _int(j['started_at']),
      );

  final String sessionId;
  final int pid;
  final String itemId;
  final String? environmentId;
  final String command;
  final List<String> secretIds;
  final int startedAt;
}

// ---------------------------------------------------------------------------
// Recovery and backup
// ---------------------------------------------------------------------------

class RecoveryStatus {
  const RecoveryStatus({required this.created, this.createdAt});

  factory RecoveryStatus.fromJson(Json j) =>
      RecoveryStatus(created: j['created'] as bool? ?? false, createdAt: _intOrNull(j['created_at']));

  final bool created;
  final int? createdAt;
}

class ExportSummary {
  const ExportSummary({
    required this.filePath,
    required this.spacesCount,
    required this.groupsCount,
    required this.itemsCount,
    required this.environmentsCount,
    required this.secretsCount,
    required this.notesCount,
    required this.assetsCount,
    required this.bytesWritten,
  });

  factory ExportSummary.fromJson(Json j) => ExportSummary(
        filePath: _str(j['file_path']),
        spacesCount: _int(j['spaces_count']),
        groupsCount: _int(j['labels_count']),
        itemsCount: _int(j['items_count']),
        environmentsCount: _int(j['environments_count']),
        secretsCount: _int(j['secrets_count']),
        notesCount: _int(j['notes_count']),
        assetsCount: _int(j['assets_count'] ?? j['files_count']),
        bytesWritten: _int(j['bytes_written']),
      );

  final String filePath;
  final int spacesCount;
  final int groupsCount;
  final int itemsCount;
  final int environmentsCount;
  final int secretsCount;
  final int notesCount;
  final int assetsCount;
  final int bytesWritten;
}

// ---------------------------------------------------------------------------
// Relay, devices, pairing, sync
// ---------------------------------------------------------------------------

class RelayStatus {
  const RelayStatus({
    required this.connected,
    required this.relayUrl,
    required this.plan,
    required this.deviceLimit,
    required this.activeDevices,
    this.expiresAt,
    required this.pendingOutboxCount,
  });

  factory RelayStatus.fromJson(Json j) => RelayStatus(
        connected: j['connected'] as bool? ?? false,
        relayUrl: _str(j['relay_url']),
        plan: _str(j['plan']),
        deviceLimit: _int(j['device_limit']),
        activeDevices: _int(j['active_devices']),
        expiresAt: j['expires_at'] as String?,
        pendingOutboxCount: _int(j['pending_outbox_count']),
      );

  final bool connected;
  final String relayUrl;
  final String plan;
  final int deviceLimit;
  final int activeDevices;

  /// RFC 3339 time, when the plan ends.
  final String? expiresAt;
  final int pendingOutboxCount;
}

class RelayRegistration {
  const RelayRegistration({required this.secwetId, required this.deviceId, required this.createdAt, required this.currentEpoch});

  factory RelayRegistration.fromJson(Json j) => RelayRegistration(
        secwetId: _str(j['secwet_id']),
        deviceId: _str(j['device_id']),
        createdAt: _str(j['created_at']),
        currentEpoch: _int(j['current_epoch']),
      );

  final String secwetId;
  final String deviceId;
  final String createdAt;
  final int currentEpoch;
}

class Device {
  const Device({
    required this.id,
    required this.name,
    required this.platform,
    required this.fingerprint,
    required this.addedAt,
    required this.lastSeenAt,
    this.revokedAt,
    required this.isCurrent,
  });

  factory Device.fromJson(Json j) => Device(
        id: _str(j['id']),
        name: _str(j['name']),
        platform: _str(j['platform']),
        fingerprint: _str(j['fingerprint']),
        addedAt: _int(j['added_at']),
        lastSeenAt: _int(j['last_seen_at']),
        revokedAt: _intOrNull(j['revoked_at']),
        isCurrent: j['is_current'] as bool? ?? false,
      );

  final String id;
  final String name;
  final String platform;
  final String fingerprint;
  final int addedAt;
  final int lastSeenAt;
  final int? revokedAt;
  final bool isCurrent;

  bool get revoked => revokedAt != null;
}

class PairingSession {
  const PairingSession({required this.sessionId, required this.expiresAt, required this.qrPayload});

  factory PairingSession.fromJson(Json j) =>
      PairingSession(sessionId: _str(j['session_id']), expiresAt: _str(j['expires_at']), qrPayload: _str(j['qr_payload']));

  final String sessionId;
  final String expiresAt;

  /// `secwet://pair?v=1&s=<session>&k=<ephemeral key>`; never a reusable credential.
  final String qrPayload;
}

/// Result of polling a pairing session from the approving device.
sealed class PairingPoll {
  const PairingPoll();

  factory PairingPoll.fromJson(Json j) => switch (j['status']) {
        'found' => PairingFound(
            name: _str(j['name']),
            platform: _str(j['platform']),
            fingerprint: _str(j['fingerprint']),
            code: _str(j['code']),
            deviceId: _str(j['device_id']),
          ),
        'expired' => const PairingExpired(),
        'approved' => const PairingApproved(),
        _ => const PairingWaiting(),
      };
}

class PairingWaiting extends PairingPoll {
  const PairingWaiting();
}

class PairingExpired extends PairingPoll {
  const PairingExpired();
}

class PairingApproved extends PairingPoll {
  const PairingApproved();
}

/// A device asked to join; compare [code] on both screens before approving.
class PairingFound extends PairingPoll {
  const PairingFound({required this.name, required this.platform, required this.fingerprint, required this.code, required this.deviceId});

  final String name;
  final String platform;
  final String fingerprint;
  final String code;
  final String deviceId;
}

class SyncResult {
  const SyncResult(this.pushed, this.pulled);

  factory SyncResult.fromJson(Json j) => SyncResult(_int(j['pushed']), _int(j['pulled']));

  final int pushed;
  final int pulled;
}

class SyncStatus {
  const SyncStatus({required this.pendingOutboxCount, required this.syncCursor});

  factory SyncStatus.fromJson(Json j) =>
      SyncStatus(pendingOutboxCount: _int(j['pending_outbox_count']), syncCursor: _int(j['sync_cursor']));

  final int pendingOutboxCount;
  final int syncCursor;
}

// ---------------------------------------------------------------------------
// M7: revocation and key rotation
// ---------------------------------------------------------------------------

class RevokeResult {
  const RevokeResult({required this.deviceId, required this.wipeRequested, required this.rotationRecommended});

  factory RevokeResult.fromJson(Json j) => RevokeResult(
        deviceId: _str(j['device_id']),
        wipeRequested: j['wipe_requested'] as bool? ?? false,
        rotationRecommended: j['rotation_recommended'] as bool? ?? false,
      );

  final String deviceId;
  final bool wipeRequested;
  final bool rotationRecommended;
}

class KeyStatus {
  const KeyStatus({required this.epoch, this.rotatedAt, required this.rotationRecommended, this.pendingReason});

  factory KeyStatus.fromJson(Json j) => KeyStatus(
        epoch: _int(j['epoch']),
        rotatedAt: _intOrNull(j['rotated_at']),
        rotationRecommended: j['rotation_recommended'] as bool? ?? false,
        pendingReason: j['pending_reason'] as String?,
      );

  final int epoch;
  final int? rotatedAt;
  final bool rotationRecommended;
  final String? pendingReason;
}

class KeyRotationReport {
  const KeyRotationReport({required this.previousEpoch, required this.epoch, required this.resealed, required this.recipients, required this.adoptedFromConflict});

  factory KeyRotationReport.fromJson(Json j) => KeyRotationReport(
        previousEpoch: _int(j['previous_epoch']),
        epoch: _int(j['epoch']),
        resealed: _int(j['resealed']),
        recipients: _int(j['recipients']),
        adoptedFromConflict: j['adopted_from_conflict'] as bool? ?? false,
      );

  final int previousEpoch;
  final int epoch;
  final int resealed;
  final int recipients;
  final bool adoptedFromConflict;
}

/// Whether this device is still linked (`linked`, `revoked`, `archived`, ...).
class LinkStatus {
  const LinkStatus({required this.state, this.revokedAt});

  factory LinkStatus.fromJson(Json j) => LinkStatus(state: _str(j['state']), revokedAt: _intOrNull(j['revoked_at']));

  final String state;
  final int? revokedAt;
}

// ---------------------------------------------------------------------------
// M8: collaboration
// ---------------------------------------------------------------------------

/// A grant to give: [kind] is `space`, `group` or `item` (or `all`), [role]
/// `viewer`, `editor` or `admin` (docs/m7-m8-architecture.md).
class GrantInput {
  const GrantInput({required this.kind, this.id, required this.role});

  final String kind;
  final String? id;
  final String role;

  Json toJson() => {'kind': kind, 'id': id, 'role': role};
}

class Grant {
  const Grant({required this.kind, this.id, required this.role, required this.label, this.spaceId});

  factory Grant.fromJson(Json j) => Grant(
        kind: _str(j['kind']),
        id: j['id'] as String?,
        role: _str(j['role']),
        label: _str(j['label']),
        spaceId: j['space_id'] as String?,
      );

  final String kind;
  final String? id;
  final String role;
  final String label;
  final String? spaceId;

  GrantInput toInput() => GrantInput(kind: kind, id: id, role: role);
}

class MemberDevice {
  const MemberDevice({required this.id, required this.fingerprint, required this.revoked});

  factory MemberDevice.fromJson(Json j) =>
      MemberDevice(id: _str(j['id']), fingerprint: _str(j['fingerprint']), revoked: j['revoked'] as bool? ?? false);

  final String id;
  final String fingerprint;
  final bool revoked;
}

class Member {
  const Member({
    required this.memberId,
    this.email,
    required this.status,
    required this.grants,
    required this.devices,
    required this.invitedAt,
    this.invitationId,
  });

  factory Member.fromJson(Json j) => Member(
        memberId: _str(j['member_id']),
        email: j['email'] as String?,
        status: _str(j['status']),
        grants: _list(j['grants'], Grant.fromJson),
        devices: _list(j['devices'], MemberDevice.fromJson),
        invitedAt: _int(j['invited_at']),
        invitationId: j['invitation_id'] as String?,
      );

  final String memberId;
  final String? email;

  /// `invited`, `active`, `removed`, ...
  final String status;
  final List<Grant> grants;
  final List<MemberDevice> devices;
  final int invitedAt;
  final String? invitationId;
}

class InviteResult {
  const InviteResult({required this.invitationId, required this.memberId, required this.link, required this.expiresAt});

  factory InviteResult.fromJson(Json j) => InviteResult(
        invitationId: _str(j['invitation_id']),
        memberId: _str(j['member_id']),
        link: _str(j['link']),
        expiresAt: _int(j['expires_at']),
      );

  final String invitationId;
  final String memberId;

  /// One-time invite link; share it out of band.
  final String link;
  final int expiresAt;
}

/// A node of a space's tree (space, group, item) for the access picker.
class ScopeNode {
  const ScopeNode({required this.kind, required this.id, required this.label, required this.depth, this.parentId});

  factory ScopeNode.fromJson(Json j) => ScopeNode(
        kind: _str(j['kind']),
        id: _str(j['id']),
        label: _str(j['label']),
        depth: _int(j['depth']),
        parentId: j['parent_id'] as String?,
      );

  final String kind;
  final String id;
  final String label;
  final int depth;
  final String? parentId;
}

class Access {
  const Access({required this.isOwner, required this.grants});

  factory Access.fromJson(Json j) => Access(isOwner: j['is_owner'] as bool? ?? false, grants: _list(j['grants'], Grant.fromJson));

  final bool isOwner;
  final List<Grant> grants;
}

// ---------------------------------------------------------------------------
// Plan (F13)
// ---------------------------------------------------------------------------

/// The plan as the app layer caches it (`plan_status`); `plan` is `free`,
/// `pro` or `paused` (Pro ended: sync paused, data untouched).
class PlanStatus {
  const PlanStatus({
    required this.plan,
    required this.deviceLimit,
    required this.activeDevices,
    this.expiresAt,
    this.checkedAt,
    required this.relayConfigured,
    required this.syncEnabled,
    required this.relaySecurity,
    required this.secwetId,
  });

  factory PlanStatus.fromJson(Json j) => PlanStatus(
        plan: _str(j['plan']),
        deviceLimit: _int(j['device_limit']),
        activeDevices: _int(j['active_devices']),
        expiresAt: j['expires_at'] as String?,
        checkedAt: _intOrNull(j['checked_at']),
        relayConfigured: j['relay_configured'] as bool? ?? false,
        syncEnabled: j['sync_enabled'] as bool? ?? false,
        relaySecurity: j['relay_security'] as bool? ?? false,
        secwetId: _str(j['secwet_id']),
      );

  final String plan;
  final int deviceLimit;
  final int activeDevices;

  /// RFC 3339 end of the Pro entitlement, if it has one.
  final String? expiresAt;

  /// Unix ms of the last entitlement check on the relay.
  final int? checkedAt;
  final bool relayConfigured;

  /// Sync, pairing and sharing run only on an active Pro plan.
  final bool syncEnabled;

  /// Revocation and key rotation over the relay (Pro, and Pro that ended).
  final bool relaySecurity;
  final String secwetId;

  bool get isFree => plan == 'free';
  bool get isPro => plan == 'pro';
  bool get isPaused => plan == 'paused';
}

// ---------------------------------------------------------------------------
// Pairing as the new device (scanned secwet://pair link)
// ---------------------------------------------------------------------------

/// Shown on this phone while the other device compares and approves.
class PairingJoinInfo {
  const PairingJoinInfo({required this.code, required this.fingerprint});

  factory PairingJoinInfo.fromJson(Json j) => PairingJoinInfo(code: _str(j['code']), fingerprint: _str(j['fingerprint']));

  /// The code both screens must show ("123 456").
  final String code;
  final String fingerprint;
}

/// `waiting`, `expired` or `approved` (the store now exists and is open).
class PairingJoinPoll {
  const PairingJoinPoll({required this.status, this.synced = false});

  factory PairingJoinPoll.fromJson(Json j) =>
      PairingJoinPoll(status: _str(j['status']), synced: j['synced'] as bool? ?? false);

  final String status;

  /// After approval: whether the first sync brought the data already.
  final bool synced;

  bool get approved => status == 'approved';
  bool get expired => status == 'expired';
}
