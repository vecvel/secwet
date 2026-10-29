import 'package:flutter/cupertino.dart' show CupertinoPageRoute;
import 'package:flutter/material.dart' show MaterialApp;
import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:secwet_mobile/app/secwet_scope.dart';
import 'package:secwet_mobile/core/secwet_api.dart';
import 'package:secwet_mobile/core/session.dart';
import 'package:secwet_mobile/theme/app_theme.dart';
import 'package:secwet_mobile/theme/secwet_theme.dart';
import 'package:secwet_mobile/theme/secwet_tokens.dart';
import 'package:secwet_mobile/widgets/controls.dart';

import 'fake_bridge.dart';

/// An in-memory workspace behind [FakeBridge] for screen tests: spaces,
/// groups, items, environments, secrets, assets and notes that the fake
/// commands read and change, so a test can create something and see it
/// listed. Test-only; the app always talks to the Rust core.
class FakeStore {
  FakeStore({this.owner = true, this.grants = const [], this.linkState = 'linked'}) {
    spaces.addAll([
      {'id': 's1', 'name': 'Personal', 'position': 0, 'icon': null, 'is_default': true},
      {'id': 's2', 'name': 'Work', 'position': 1, 'icon': 'briefcase', 'is_default': false},
    ]);
  }

  bool owner;
  List<Map<String, Object?>> grants;
  String linkState;

  final spaces = <Map<String, Object?>>[];
  final groups = <Map<String, Object?>>[];
  final items = <Map<String, Object?>>[];
  final environments = <Map<String, Object?>>[];
  final secrets = <Map<String, Object?>>[];
  final values = <String, String>{};
  final assets = <Map<String, Object?>>[];
  final notes = <Map<String, Object?>>[];
  Map<String, Object?> dashboard = {
    'home_label': 'Overview',
    'visible_kpis': ['secrets', 'assets', 'notes', 'devices'],
    'widgets': ['recent_secrets', 'recent_notes', 'quick_actions', 'checklist'],
  };
  final copied = <String>[];
  var _next = 100;

  String _id(String p) => '$p${_next++}';
  int get _now => DateTime.now().millisecondsSinceEpoch ~/ 1000;

  Map<String, Object?> addGroup(String name, {String space = 's1'}) {
    final g = {'id': _id('g'), 'space_id': space, 'name': name, 'position': groups.length, 'icon': 'folder'};
    groups.add(g);
    return g;
  }

  Map<String, Object?> addItem(String groupId, String name, {String? description}) {
    final i = {'id': _id('i'), 'label_id': groupId, 'name': name, 'description': description, 'position': items.length};
    items.add(i);
    return i;
  }

  Map<String, Object?> addEnvironment(String itemId, String name) {
    final e = {'id': _id('e'), 'project_id': itemId, 'name': name, 'position': environments.length};
    environments.add(e);
    return e;
  }

  Map<String, Object?> addSecret(String itemId, String name, String value, {String? env, String kind = 'api_key', String? note}) {
    final s = {
      'id': _id('x'),
      'project_id': itemId,
      'environment_id': env,
      'name': name,
      'kind': kind,
      'note': note,
      'updated_at': _now,
      'value_tail': value.length > 4 ? value.substring(value.length - 4) : value,
    };
    secrets.add(s);
    values[s['id'] as String] = value;
    return s;
  }

  Map<String, Object?> addNote(String itemId, String title, String content) {
    final n = {
      'id': _id('n'),
      'item_id': itemId,
      'environment_id': null,
      'title': title,
      'content': content,
      'snippet': content.replaceAll(RegExp('<[^>]+>'), ' ').trim(),
      'updated_at': _now,
      'position': notes.length,
    };
    notes.add(n);
    return n;
  }

  Map<String, Object?> _item(Map<String, Object?> i) => {
        ...i,
        'environments_count': environments.where((e) => e['project_id'] == i['id']).length,
        'secrets_count': secrets.where((s) => s['project_id'] == i['id']).length,
        'assets_count': assets.where((a) => a['item_id'] == i['id']).length,
        'notes_count': notes.where((n) => n['item_id'] == i['id']).length,
      };

  Map<String, Object? Function(Map<String, Object?>)> handlers() => {
        ...unlockedHandlers(),
        'spaces_list': (_) => [
              for (final s in spaces) {...s, 'groups_count': groups.where((g) => g['space_id'] == s['id']).length},
            ],
        'space_create': (a) {
          final s = {'id': _id('s'), 'name': a['name'], 'position': spaces.length, 'icon': a['icon'], 'is_default': false};
          spaces.add(s);
          return {...s, 'groups_count': 0};
        },
        'space_rename': (a) {
          final s = spaces.firstWhere((x) => x['id'] == a['id']);
          s['name'] = a['name'];
          s['icon'] = a['icon'];
          return {...s, 'groups_count': 0};
        },
        'space_delete': (a) {
          spaces.removeWhere((x) => x['id'] == a['id']);
          for (final g in groups) {
            if (g['space_id'] == a['id']) g['space_id'] = 's1';
          }
          return null;
        },
        'groups_list': (_) => [
              for (final g in groups) {...g, 'items_count': items.where((i) => i['label_id'] == g['id']).length},
            ],
        'group_create': (a) => {...addGroup(a['name'] as String, space: a['space_id'] as String? ?? 's1'), 'items_count': 0},
        'group_rename': (a) {
          groups.firstWhere((g) => g['id'] == a['id'])['name'] = a['name'];
          return null;
        },
        'group_delete': (a) {
          final ids = {for (final i in items) if (i['label_id'] == a['id']) i['id']};
          items.removeWhere((i) => ids.contains(i['id']));
          secrets.removeWhere((s) => ids.contains(s['project_id']));
          groups.removeWhere((g) => g['id'] == a['id']);
          return null;
        },
        'group_reorder': (a) {
          final ids = (a['ids'] as List).cast<String>();
          groups.sort((x, y) => ids.indexOf(x['id'] as String).compareTo(ids.indexOf(y['id'] as String)));
          for (final (i, g) in groups.indexed) {
            g['position'] = i;
          }
          return null;
        },
        'group_move_to_space': (a) {
          groups.firstWhere((g) => g['id'] == a['id'])['space_id'] = a['space_id'];
          return null;
        },
        'items_list': (a) => [
              for (final i in items)
                if (a['label_id'] == null || i['label_id'] == a['label_id']) _item(i),
            ],
        'item_create': (a) => _item(addItem(a['label_id'] as String, a['name'] as String, description: a['description'] as String?)),
        'item_rename': (a) {
          final i = items.firstWhere((x) => x['id'] == a['id']);
          i['name'] = a['name'];
          i['description'] = a['description'];
          return null;
        },
        'item_delete': (a) {
          items.removeWhere((x) => x['id'] == a['id']);
          return null;
        },
        'environments_list': (a) => [
              for (final e in environments)
                if (e['project_id'] == a['item_id'])
                  {...e, 'secret_count': secrets.where((s) => s['environment_id'] == e['id']).length},
            ],
        'environment_add': (a) => {...addEnvironment(a['item_id'] as String, a['name'] as String), 'secret_count': 0},
        'environment_rename': (a) {
          environments.firstWhere((e) => e['id'] == a['id'])['name'] = a['name'];
          return null;
        },
        'environment_delete': (a) {
          environments.removeWhere((e) => e['id'] == a['id']);
          if (a['preserve_content'] == true) {
            for (final s in secrets) {
              if (s['environment_id'] == a['id']) s['environment_id'] = null;
            }
          } else {
            secrets.removeWhere((s) => s['environment_id'] == a['id']);
          }
          return null;
        },
        'secrets_list': (a) => [for (final s in secrets) if (s['project_id'] == a['item_id']) s],
        'secret_reveal': (a) => values[a['id']],
        'secret_copy': (a) {
          copied.add(values[a['id']]!);
          return null;
        },
        'clipboard_copy_text': (a) {
          copied.add(a['text'] as String);
          return null;
        },
        'secret_create': (a) {
          final d = (a['draft'] as Map).cast<String, Object?>();
          return addSecret(d['item_id'] as String, d['name'] as String, d['value'] as String,
              env: d['environment_id'] as String?, kind: d['kind'] as String, note: d['note'] as String?);
        },
        'secret_update': (a) {
          final d = (a['draft'] as Map).cast<String, Object?>();
          final s = secrets.firstWhere((x) => x['id'] == a['id']);
          s
            ..['name'] = d['name']
            ..['kind'] = d['kind']
            ..['note'] = d['note']
            ..['environment_id'] = d['environment_id'];
          values[s['id'] as String] = d['value'] as String;
          return s;
        },
        'secret_delete': (a) {
          secrets.removeWhere((x) => x['id'] == a['id']);
          return null;
        },
        'secret_copy_to_environment': (a) {
          final s = secrets.firstWhere((x) => x['id'] == a['id']);
          return addSecret(s['project_id'] as String, s['name'] as String, values[s['id']]!,
              env: a['target_environment_id'] as String?, kind: s['kind'] as String);
        },
        'assets_list': (a) => [for (final x in assets) if (x['item_id'] == a['item_id']) x],
        'asset_rename': (a) {
          final x = assets.firstWhere((x) => x['id'] == a['id']);
          x['name'] = a['name'];
          return x;
        },
        'asset_delete': (a) {
          assets.removeWhere((x) => x['id'] == a['id']);
          return null;
        },
        'notes_list': (a) => [for (final n in notes) if (n['item_id'] == a['item_id']) n],
        'note_get': (a) => notes.firstWhere((n) => n['id'] == a['id']),
        'note_create': (a) {
          final d = (a['draft'] as Map).cast<String, Object?>();
          return addNote(d['item_id'] as String, d['title'] as String, d['content'] as String);
        },
        'note_update': (a) {
          final d = (a['draft'] as Map).cast<String, Object?>();
          final n = notes.firstWhere((x) => x['id'] == a['id']);
          if (d['title'] != null) n['title'] = d['title'];
          if (d['content'] != null) n['content'] = d['content'];
          return n;
        },
        'note_delete': (a) {
          notes.removeWhere((x) => x['id'] == a['id']);
          return null;
        },
        'note_copy_plain': (a) {
          copied.add('note:${a['id']}');
          return null;
        },
        'active_sessions_list': (_) => <Object?>[],
        'my_access': (_) => {'is_owner': owner, 'grants': grants},
        'link_status': (_) => {'state': linkState, 'revoked_at': null},
        'dashboard_get': (_) => dashboard,
        'dashboard_set': (a) {
          dashboard = (a['config'] as Map).cast<String, Object?>();
          return null;
        },
        'key_status': (_) => {'epoch': 1, 'rotated_at': null, 'rotation_recommended': false, 'pending_reason': null},
        'plan_status': (_) => {
              'plan': 'free',
              'device_limit': 1,
              'active_devices': 1,
              'relay_configured': false,
              'sync_enabled': false,
              'relay_security': false,
              'secwet_id': '00000000-0000-0000-0000-000000000001',
            },
        'overview': (_) => {
              'labels_count': groups.length,
              'items_count': items.length,
              'environments_count': environments.length,
              'secrets_count': secrets.length,
              'assets_count': assets.length,
              'notes_count': notes.length,
              'active_devices_count': 1,
              'projects': <Object?>[],
              'recent': [
                for (final s in secrets.reversed)
                  {
                    'id': s['id'],
                    'name': s['name'],
                    'project_id': s['project_id'],
                    'project_name': items.firstWhere((i) => i['id'] == s['project_id'], orElse: () => {'name': ''})['name'],
                    'environment_id': s['environment_id'] ?? '',
                    'environment_name': s['environment_id'] == null ? 'General' : 'Env',
                    'updated_at': s['updated_at'],
                  },
              ],
              'checklist': {
                'secwet_created': true,
                'recovery_key_created': false,
                'cli_connected': false,
                'add_device_done': false,
                'pending_rotation': null,
              },
            },
      };
}

/// Pumps [screen] as the first route of an unlocked app over [store].
Future<FakeBridge> pumpScreen(WidgetTester tester, FakeStore store, Widget screen, {Brightness brightness = Brightness.light}) async {
  final bridge = FakeBridge(store.handlers());
  final session = SessionController(SecwetApi(bridge));
  await session.refresh();
  // An iPhone-sized view; MediaQuery follows it (menus place themselves by it).
  tester.view
    ..physicalSize = const Size(1170, 2532)
    ..devicePixelRatio = 3;
  addTearDown(tester.view.reset);
  await tester.pumpWidget(MaterialApp(
    theme: buildSecwetTheme(brightness),
    builder: (context, child) => SecwetScope(
      session: session,
      child: SecwetPaletteScope(
        palette: brightness == Brightness.dark ? SecwetPalette.dark : SecwetPalette.light,
        child: Builder(builder: (context) => DefaultTextStyle(style: SecwetText.body(context.palette), child: child!)),
      ),
    ),
    onGenerateRoute: (_) => CupertinoPageRoute<void>(builder: (_) => screen),
  ));
  await tester.pumpAndSettle();
  return bridge;
}

/// A tap target by its accessibility label ([Tappable.label]).
Finder byLabel(String label) => find.byWidgetPredicate((w) => w is Tappable && w.label == label);
