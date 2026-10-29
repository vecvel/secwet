import 'package:flutter/widgets.dart';

import '../../app/secwet_scope.dart';
import '../../core/secwet_api.dart';
import '../../widgets/controls.dart';
import '../../widgets/layout.dart';
import 'settings_screen.dart';
import 'settings_widgets.dart';

/// Settings > Sync: relay address, registration, connection, what waits to
/// be sent, and Sync now. Secwet also syncs when it opens, when it comes
/// back to the foreground, and on pull to refresh.
class SyncTab extends StatefulWidget {
  const SyncTab({super.key, required this.model, required this.onShowPlan});

  final SettingsModel model;
  final VoidCallback onShowPlan;

  @override
  State<SyncTab> createState() => _SyncTabState();
}

class _SyncTabState extends State<SyncTab> {
  bool _syncing = false;
  bool _registering = false;
  String? _result;
  String? _error;

  SettingsModel get model => widget.model;

  static final _url = RegExp(r'^https?://[^\s/]+', caseSensitive: false);

  Future<void> _saveUrl(String value) async {
    final url = value.trim();
    if (url.isNotEmpty && !_url.hasMatch(url)) {
      setState(() => _error = 'Enter the relay address, for example https://relay.example.com.');
      return;
    }
    try {
      await SecwetScope.read(context).api.setRelayUrl(url);
      setState(() => _error = null);
      await model.loadRelay();
    } on SecwetException catch (e) {
      if (mounted) setState(() => _error = e.message.isEmpty ? "Couldn't save the relay address." : e.message);
    }
  }

  Future<void> _register() async {
    setState(() {
      _registering = true;
      _error = null;
    });
    try {
      await SecwetScope.read(context).api.relayRegister();
      await model.loadRelay();
      if (mounted) setState(() => _result = 'This device is registered with the relay.');
    } on SecwetException catch (e) {
      if (mounted) setState(() => _error = e.message);
    } finally {
      if (mounted) setState(() => _registering = false);
    }
  }

  Future<void> _sync() async {
    setState(() => _syncing = true);
    try {
      final r = await SecwetScope.read(context).api.syncNow();
      _result = 'Synced just now. Sent ${r.pushed}, received ${r.pulled}.';
    } on SecwetException catch (e) {
      _result = e.message.isEmpty ? 'Sync failed. Check the relay connection.' : e.message;
    } finally {
      // Every sync re-reads the entitlement, so the plan may have changed.
      await model.load();
      await model.loadRelay();
      if (mounted) setState(() => _syncing = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final readOnly = SecwetScope.of(context).session.readOnly;
    final plan = model.plan;
    final name = plan?.plan ?? 'free';
    final relay = model.relay;
    final savedUrl = relay?.relayUrl ?? '';
    final end = formatIsoDate(plan?.expiresAt);
    final active = plan?.activeDevices ?? 1;
    final limit = plan?.deviceLimit ?? 1;
    final error = _error ?? model.relayError;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        if (readOnly)
          const SettingsNotice(
            label: 'Read-only',
            text: 'This device was unlinked from Secwet. Sync is disabled; what is here stays readable.',
          ),
        if (name == 'free')
          SettingsNotice(
            label: 'Free',
            tone: BadgeTone.accent,
            text: 'Sync comes with Pro. On Free, everything stays on this phone and Secwet never contacts the relay.',
            action: SecwetButton(label: 'See plan', variant: ButtonVariant.tertiary, small: true, onPressed: widget.onShowPlan),
          ),
        if (name == 'paused')
          SettingsNotice(
            label: 'Sync paused',
            text: 'Pro ended${end != null ? ' on $end' : ''}, so sync is paused on every device. Everything here stays usable '
                'and exportable. Changes you make now are kept and sent once Pro is renewed.',
          ),
        if (error != null) SettingsNotice(label: 'Sync', text: error),
        const SectionLabel('Sync'),
        SecwetCard(
          children: [
            SettingRow(
              title: 'Relay address',
              meta: 'The sync relay this Secwet uses. It only stores encrypted data.',
              below: SaveOnDoneField(
                initial: savedUrl,
                hint: 'https://relay.example.com',
                keyboardType: TextInputType.url,
                enabled: !readOnly,
                onSave: _saveUrl,
              ),
            ),
            SettingRow(
              title: 'Relay connection',
              meta: name == 'free' ? 'Not used on Free.' : (savedUrl.isNotEmpty ? savedUrl : 'Add the relay address to sync.'),
              trailing: name == 'free'
                  ? const SecwetBadge('Off')
                  : relay?.connected ?? false
                      ? const SecwetBadge('Connected', tone: BadgeTone.success)
                      : SecwetBadge(model.relayLoading ? 'Checking…' : 'Offline'),
            ),
            if (name != 'free' && savedUrl.isNotEmpty && !(relay?.connected ?? false))
              SettingRow(
                title: 'Register this device',
                meta: 'Registers this Secwet and device key with the relay, if it has not been yet.',
                trailing: SecwetButton(
                  label: _registering ? 'Registering…' : 'Register',
                  variant: ButtonVariant.secondary,
                  small: true,
                  onPressed: _registering || readOnly ? null : _register,
                ),
              ),
            SettingRow(
              title: 'Devices',
              meta: '$active of $limit devices on this plan.',
              trailing: SecwetBadge('$active / $limit', tone: active >= limit ? BadgeTone.warning : BadgeTone.neutral),
            ),
            if (name != 'free')
              SettingRow(
                title: 'Waiting to sync',
                meta: name == 'paused'
                    ? 'Changes made while sync is paused. They are sent once Pro is renewed.'
                    : 'Local changes not sent yet. Everything is encrypted before it leaves this phone.',
                trailing: SecwetBadge(plural(relay?.pendingOutboxCount ?? 0, 'change')),
              ),
            SettingRow(
              title: 'Sync now',
              meta: readOnly
                  ? 'This device was unlinked from Secwet. Sync is disabled.'
                  : name == 'free'
                      ? 'Needs Pro.'
                      : name == 'paused'
                          ? _result ?? 'Checks whether Pro was renewed, then syncs.'
                          : _result ?? 'Send and receive changes now. Pull down anywhere in Settings to sync too.',
              trailing: SecwetButton(
                label: _syncing ? 'Syncing…' : 'Sync now',
                variant: ButtonVariant.secondary,
                small: true,
                onPressed: _syncing || readOnly || name == 'free' || savedUrl.isEmpty ? null : _sync,
              ),
            ),
          ],
        ),
        const BulletCard(
          title: 'What the relay sees',
          lines: [
            'The relay never sees your master key, secret values, names or notes.',
            "Every request is signed with this device's own key and protected against replay.",
            'The relay stores only encrypted data and random IDs.',
          ],
        ),
      ],
    );
  }
}
