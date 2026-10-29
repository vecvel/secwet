import 'dart:async';

import 'package:flutter/cupertino.dart' show CupertinoSliverRefreshControl;
import 'package:flutter/widgets.dart';

import '../../app/secwet_scope.dart';
import '../../app/shell.dart';
import '../../core/secwet_api.dart';
import '../../theme/secwet_theme.dart';
import '../../theme/secwet_tokens.dart';
import '../../widgets/controls.dart';
import '../../widgets/layout.dart';
import '../../widgets/overlays.dart';
import 'devices_tab.dart';
import 'general_tab.dart';
import 'plan_tab.dart';
import 'recovery_tab.dart';
import 'security_tab.dart';
import 'sync_tab.dart';

/// Settings tabs, the same as desktop; Devices, Recovery, Sync and Plan live here on mobile.
enum SettingsTab { general, security, devices, recovery, sync, plan }

/// What the Settings tabs show, read from the app layer and refreshed on
/// `changed` events. The relay status is read only on the Sync and Plan tabs
/// (and on pull to refresh): it is the one read that may contact the relay.
class SettingsModel extends ChangeNotifier {
  SettingsModel(this.api);

  final SecwetApi api;

  Settings? settings;
  DashboardConfig? dashboard;
  PlanStatus? plan;
  RelayStatus? relay;
  String? relayError;
  bool relayLoading = false;
  KeyStatus? keys;
  Access? access;
  List<Device> devices = const [];
  RecoveryStatus? recovery;

  /// Owners (and stores from before member mode) manage devices and keys.
  bool get isOwner => access?.isOwner ?? true;

  Future<T?> _read<T>(Future<T> Function() f) => readWhenIdle(f);

  Future<void> load() async {
    final r = await Future.wait<Object?>([
      _read(api.settings),
      _read(api.dashboard),
      _read(api.planStatus),
      _read(api.keyStatus),
      _read(api.myAccess),
      _read(api.devices),
      _read(api.recoveryStatus),
    ]);
    settings = r[0] as Settings? ?? settings;
    dashboard = r[1] as DashboardConfig? ?? dashboard;
    plan = r[2] as PlanStatus? ?? plan;
    keys = r[3] as KeyStatus? ?? keys;
    access = r[4] as Access? ?? access;
    devices = r[5] as List<Device>? ?? devices;
    recovery = r[6] as RecoveryStatus? ?? recovery;
    notifyListeners();
  }

  Future<void> loadRelay() async {
    relayLoading = true;
    notifyListeners();
    try {
      relay = await api.relayStatus();
      relayError = null;
      plan = await _read(api.planStatus) ?? plan;
    } on SecwetException catch (e) {
      relayError = e.message;
    } finally {
      relayLoading = false;
      notifyListeners();
    }
  }

  /// Pull to refresh: sync when this Secwet syncs, then re-read everything.
  Future<String?> refresh({required bool readOnly}) async {
    String? error;
    if (!readOnly && (plan?.syncEnabled ?? false) && (plan?.relayConfigured ?? false)) {
      try {
        await api.syncNow();
      } on SecwetException catch (e) {
        error = e.message;
      }
    }
    await load();
    if (relay != null) await loadRelay();
    return error;
  }
}

/// Settings: General, Security, Devices, Recovery, Sync and Plan, as on
/// desktop (the CLI tab and the running-session list do not apply on a phone).
/// Pull down to sync and reload.
class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key, this.initialTab = SettingsTab.general});

  final SettingsTab initialTab;

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  late SettingsTab _tab = widget.initialTab;
  SettingsModel? _model;
  StreamSubscription<SecwetEvent>? _changes;

  static const _labels = {
    SettingsTab.general: 'General',
    SettingsTab.security: 'Security',
    SettingsTab.devices: 'Devices',
    SettingsTab.recovery: 'Recovery',
    SettingsTab.sync: 'Sync',
    SettingsTab.plan: 'Plan',
  };

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    if (_model != null) return;
    final api = SecwetScope.read(context).api;
    _model = SettingsModel(api)..addListener(_rebuild);
    _changes = api.events.where((e) => e.isChanged).listen((_) => _model!.load());
    _model!.load();
    _onTab(_tab);
  }

  void _rebuild() {
    if (mounted) setState(() {});
  }

  void _onTab(SettingsTab tab) {
    setState(() => _tab = tab);
    if (tab == SettingsTab.sync || tab == SettingsTab.plan) _model!.loadRelay();
  }

  @override
  void dispose() {
    _changes?.cancel();
    _model?.removeListener(_rebuild);
    _model?.dispose();
    super.dispose();
  }

  Future<void> _refresh() async {
    final scope = SecwetScope.read(context);
    final error = await _model!.refresh(readOnly: scope.session.readOnly);
    await scope.session.reloadSettings();
    if (error != null && mounted) showToast(context, error, tone: BadgeTone.warning);
  }

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    final model = _model!;
    final content = switch (_tab) {
      SettingsTab.general => GeneralTab(model: model),
      SettingsTab.security => SecurityTab(model: model),
      SettingsTab.devices => DevicesTab(model: model),
      SettingsTab.recovery => RecoveryTab(model: model),
      SettingsTab.sync => SyncTab(model: model, onShowPlan: () => _onTab(SettingsTab.plan)),
      SettingsTab.plan => PlanTab(model: model),
    };
    return ColoredBox(
      color: p.bg,
      child: SafeArea(
        bottom: false,
        child: CustomScrollView(
          physics: const AlwaysScrollableScrollPhysics(parent: BouncingScrollPhysics()),
          slivers: [
            CupertinoSliverRefreshControl(onRefresh: _refresh),
            SliverPadding(
              padding: EdgeInsets.fromLTRB(SecwetSpace.s4, 0, SecwetSpace.s4, bottomBarClearance(context)),
              sliver: SliverList.list(
                children: [
                  const TopBar(title: 'Settings'),
                  SegmentedTabs<SettingsTab>(
                    tabs: [for (final t in SettingsTab.values) TabSpec(t, _labels[t]!)],
                    selected: _tab,
                    onChanged: _onTab,
                  ),
                  const SizedBox(height: SecwetSpace.s3),
                  KeyedSubtree(key: ValueKey(_tab), child: content),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}
