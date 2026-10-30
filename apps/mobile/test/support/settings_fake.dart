import 'package:secwet_mobile/core/bridge.dart';

import 'fake_store.dart';

/// [FakeStore] plus the Settings and Members commands: devices, plan, relay,
/// recovery, revoke and members, held in memory so a test can change them
/// and see the screen follow. Test-only; the app always talks to Rust.
class SettingsFake extends FakeStore {
  SettingsFake({super.owner, super.linkState, this.pro = true});

  bool pro;
  bool paused = false;
  bool recoveryCreated = false;
  int epoch = 1;
  bool rotationRecommended = false;
  final revokes = <Map<String, Object?>>[];
  final removed = <Map<String, Object?>>[];
  final revokedInvites = <String>[];
  final invites = <Map<String, Object?>>[];

  final devices = <Map<String, Object?>>[
    {
      'id': 'd1',
      'name': 'Test Phone',
      'platform': 'iOS',
      'fingerprint': 'AB12 CD34',
      'added_at': 1760000000,
      'last_seen_at': 1760000000,
      'revoked_at': null,
      'is_current': true,
    },
    {
      'id': 'd2',
      'name': 'Studio Mac',
      'platform': 'macOS',
      'fingerprint': 'EF56 7890',
      'added_at': 1760000000,
      'last_seen_at': 1760000000,
      'revoked_at': null,
      'is_current': false,
    },
  ];

  final members = <Map<String, Object?>>[
    {
      'member_id': 'm1',
      'email': 'ana@example.com',
      'status': 'active',
      'grants': [
        {'kind': 'space', 'id': 's2', 'role': 'editor', 'label': 'Work', 'space_id': 's2'},
      ],
      'devices': [
        {'id': 'md1', 'fingerprint': '1111 2222', 'revoked': false},
      ],
      'invited_at': 1760000000,
      'invitation_id': null,
    },
    {
      'member_id': 'm2',
      'email': 'ben@example.com',
      'status': 'invited',
      'grants': [
        {'kind': 'space', 'id': 's2', 'role': 'viewer', 'label': 'Work', 'space_id': 's2'},
      ],
      'devices': <Object?>[],
      'invited_at': 1760000000,
      'invitation_id': 'inv2',
    },
  ];

  Map<String, Object?> get _plan => {
        'plan': paused ? 'paused' : (pro ? 'pro' : 'free'),
        'device_limit': pro ? 10 : 1,
        'active_devices': devices.where((d) => d['revoked_at'] == null).length,
        'expires_at': null,
        'checked_at': 1760000000,
        'relay_configured': pro,
        'sync_enabled': pro && !paused,
        'relay_security': false,
        'secwet_id': '00000000-0000-0000-0000-000000000001',
      };

  @override
  Map<String, Object? Function(Map<String, Object?>)> handlers() => {
        ...super.handlers(),
        'plan_status': (_) => _plan,
        'plan_refresh': (_) => _plan,
        'devices_list': (_) => devices,
        'recovery_status': (_) => {'created': recoveryCreated, 'created_at': recoveryCreated ? 1760000000 : null},
        'recovery_key_create': (_) {
          recoveryCreated = true;
          return 'ABCD-EFGH-IJKL-MNOP';
        },
        'key_status': (_) =>
            {'epoch': epoch, 'rotated_at': null, 'rotation_recommended': rotationRecommended, 'pending_reason': null},
        'key_rotate': (_) {
          epoch += 1;
          rotationRecommended = false;
          return {'previous_epoch': epoch - 1, 'epoch': epoch, 'resealed': 3, 'recipients': 1, 'adopted_from_conflict': false};
        },
        'relay_status': (_) {
          if (!pro) throw SecwetException('relay_not_configured', 'No relay address is set.');
          return {
            'connected': true,
            'relay_url': 'http://localhost:8080',
            'plan': 'pro',
            'device_limit': 10,
            'active_devices': 2,
            'expires_at': null,
            'pending_outbox_count': 2,
          };
        },
        'sync_now': (_) => {'pushed': 2, 'pulled': 1},
        'sync_status': (_) => {'pending_outbox_count': 0, 'sync_cursor': 4},
        'device_revoke': (a) {
          revokes.add(a);
          devices.firstWhere((d) => d['id'] == a['device_id'])['revoked_at'] = 1760000500;
          rotationRecommended = true;
          return {'device_id': a['device_id'], 'wipe_requested': a['wipe'], 'rotation_recommended': true};
        },
        'members_list': (_) {
          if (!pro) throw SecwetException('relay_not_configured', 'No relay address is set.');
          return [for (final m in members) if (m['status'] != 'removed') m];
        },
        'scope_nodes': (a) => [
              {'kind': 'space', 'id': a['space_id'], 'label': 'Work', 'depth': 0, 'parent_id': null},
            ],
        'member_invite': (a) {
          invites.add(a);
          members.add({
            'member_id': 'm${members.length + 1}',
            'email': a['email'],
            'status': 'invited',
            'grants': [
              for (final g in (a['grants'] as List).cast<Map<String, Object?>>())
                {...g, 'label': 'Work', 'space_id': 's2'},
            ],
            'devices': <Object?>[],
            'invited_at': 1760000000,
            'invitation_id': 'inv${members.length + 1}',
          });
          return {
            'invitation_id': 'inv${members.length}',
            'member_id': 'm${members.length}',
            'link': 'secwet://invite?i=inv${members.length}&k=secret',
            'expires_at': 1760600000,
          };
        },
        'member_remove': (a) {
          removed.add(a);
          members.firstWhere((m) => m['member_id'] == a['member_id'])['status'] = 'removed';
          return null;
        },
        'invitation_revoke': (a) {
          revokedInvites.add(a['invitation_id'] as String);
          members.removeWhere((m) => m['invitation_id'] == a['invitation_id']);
          return null;
        },
        'invite_link_copy': (a) {
          copied.add('invite:${a['invitation_id']}');
          return null;
        },
      };
}
