import 'dart:async';

import 'package:secwet_mobile/core/bridge.dart';

/// Test double for the Rust bridge: answers commands from [handlers] and
/// records every call. Lives in test/ only; the app always uses the real FFI.
class FakeBridge implements SecwetBridge {
  FakeBridge(this.handlers);

  final Map<String, Object? Function(Map<String, Object?> args)> handlers;
  final calls = <String>[];
  final _events = StreamController<SecwetEvent>.broadcast();

  void emit(SecwetEvent e) => _events.add(e);

  @override
  Stream<SecwetEvent> get events => _events.stream;

  @override
  Future<Object?> call(String cmd, [Map<String, Object?> args = const {}]) async {
    calls.add(cmd);
    final h = handlers[cmd];
    if (h == null) throw SecwetException('unknown_command', 'No fake for $cmd');
    return h(args);
  }
}

/// [screenLock]: the phone has a passcode (the system prompt guards every
/// unlock); [biometric]: Face ID is enrolled; [recovery]: no screen lock and
/// the store has a recovery key.
Map<String, Object? Function(Map<String, Object?>)> unlockedHandlers({
  bool biometric = false,
  bool screenLock = true,
  bool recovery = false,
}) =>
    {
      'secwet_status': (_) => {'status': 'unlocked', 'secwet_id': '00000000-0000-0000-0000-000000000001'},
      'biometric_status': (_) => {
            'available': biometric && screenLock,
            'kind': biometric && screenLock ? 'face_id' : 'none',
            'enabled': screenLock,
            'platform_kind': biometric && screenLock ? 'face_id' : 'none',
            'device_lock': screenLock,
          },
      'settings_get': (_) => {'theme': 'system', 'lock_timeout_minutes': 15, 'device_name': 'Test Phone'},
      'system_device_name': (_) => 'Test Phone',
      'overview': (_) => {
            'labels_count': 1,
            'items_count': 2,
            'projects_count': 2,
            'environments_count': 3,
            'secrets_count': 5,
            'assets_count': 2,
            'files_count': 2,
            'notes_count': 2,
            'active_devices_count': 2,
            'projects': <Object?>[],
            'recent': <Object?>[],
            'checklist': {
              'secwet_created': true,
              'recovery_key_created': false,
              'cli_connected': false,
              'add_device_done': false,
              'pending_rotation': null,
            },
          },
      'spaces_list': (_) => [
            {'id': 's1', 'name': 'Personal', 'position': 0, 'icon': null, 'is_default': true, 'groups_count': 1},
          ],
      'items_list': (_) => [
            {
              'id': 'i1',
              'label_id': 'g1',
              'name': 'Checkout',
              'description': null,
              'position': 0,
              'environments_count': 3,
              'secrets_count': 5,
              'assets_count': 2,
              'notes_count': 2,
            },
          ],
      'groups_list': (_) => [
            {'id': 'g1', 'space_id': 's1', 'name': 'Payments API', 'position': 0, 'icon': null, 'items_count': 2},
          ],
      'secwet_lock': (_) => null,
      'secwet_unlock': (_) => null,
    };
