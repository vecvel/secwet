import 'dart:async';

import 'package:flutter/widgets.dart';

import '../../app/secwet_scope.dart';
import '../../core/secwet_api.dart';
import '../../theme/secwet_theme.dart';
import '../../theme/secwet_tokens.dart';
import '../../widgets/controls.dart';
import '../../widgets/icon.dart';
import '../../widgets/layout.dart';
import '../../widgets/overlays.dart';
import 'plan_tab.dart';
import 'qr_code.dart';
import 'security_tab.dart';
import 'settings_screen.dart';
import 'settings_widgets.dart';

/// Settings > Devices: this Secwet's devices, pairing a new one (this phone
/// shows the code) and revoking with the M7 choice. Member devices cannot
/// pair: the relay only adds devices for the owner.
class DevicesTab extends StatefulWidget {
  const DevicesTab({super.key, required this.model});

  final SettingsModel model;

  @override
  State<DevicesTab> createState() => _DevicesTabState();
}

class _DevicesTabState extends State<DevicesTab> {
  String? _notice;

  SettingsModel get model => widget.model;

  String _meta(Device d, bool paused) {
    if (d.revoked) return '${d.platform}, revoked ${formatDate(d.revokedAt!)}.';
    if (d.isCurrent) return '${d.platform}, added ${formatDate(d.addedAt)}, key ${d.fingerprint}';
    final sync = d.lastSeenAt > 0 ? 'last synced ${formatAgo(d.lastSeenAt).toLowerCase()}' : 'active';
    // When Pro ends, the other devices stop syncing (F13).
    return '${d.platform}, ${paused ? 'sync paused, $sync' : sync}, key ${d.fingerprint}';
  }

  Future<void> _pair() async {
    final plan = model.plan;
    if (plan != null && !plan.isPro) {
      await showPlanDialog(
        context,
        plan: plan,
        reason: plan.isPaused
            ? 'Pro has ended, so pairing is paused. Everything on this phone keeps working.'
            : 'Pairing a second device requires Pro. Everything on this phone remains fully functional on Free.',
      );
      return;
    }
    final device = await showSecwetDialog<Device>(
      context,
      dismissible: false,
      builder: (_) => PairDeviceSheet(api: SecwetScope.read(context).api),
    );
    await model.load();
    if (device != null && mounted) setState(() => _notice = '${device.name} was added. It syncs from now on.');
  }

  Future<void> _revoke(Device d) async {
    final result = await showSecwetDialog<RevokeResult>(
      context,
      builder: (_) => RevokeDeviceSheet(api: SecwetScope.read(context).api, device: d),
    );
    if (result == null) return;
    await model.load();
    if (!mounted) return;
    setState(() {
      _notice = result.wipeRequested
          ? '${d.name} was revoked. It erases its keys and local data when it next connects.'
          : '${d.name} was revoked. It keeps a read-only copy of what it had.';
    });
  }

  @override
  Widget build(BuildContext context) {
    final session = SecwetScope.of(context).session;
    final readOnly = session.readOnly;
    final canPair = !readOnly && model.isOwner;
    final paused = model.plan?.isPaused ?? false;
    final active = [for (final d in model.devices) if (!d.revoked) d];
    final revoked = [for (final d in model.devices) if (d.revoked) d];
    final recommended = model.keys?.rotationRecommended ?? false;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        if (readOnly)
          const SettingsNotice(
            label: 'Read-only',
            text: 'This device was unlinked from Secwet. What is here stays readable, but it no longer syncs or changes.',
          ),
        if (_notice != null)
          SettingsNotice(
            label: 'Done',
            tone: BadgeTone.success,
            text: _notice!,
            action: SecwetButton(
              label: 'Dismiss',
              variant: ButtonVariant.tertiary,
              small: true,
              onPressed: () => setState(() => _notice = null),
            ),
          ),
        if (recommended && canPair) RotationNotice(model: model),
        SectionLabel(
          'Active Devices',
          trailing: canPair ? SecwetButton(label: 'Pair a device', icon: SecwetIcons.plus, small: true, onPressed: _pair) : null,
        ),
        SecwetCard(
          children: [
            for (final d in active)
              SettingRow(
                title: d.name,
                badges: [
                  if (d.isCurrent) const SecwetBadge('This device'),
                  if (!d.isCurrent && paused) const SecwetBadge('Paused', tone: BadgeTone.warning),
                ],
                meta: _meta(d, paused),
                trailing: d.isCurrent
                    ? const SecwetBadge('Active', tone: BadgeTone.success)
                    : readOnly || !model.isOwner
                        ? null
                        : SecwetButton(label: 'Revoke', variant: ButtonVariant.tertiary, small: true, onPressed: () => _revoke(d)),
              ),
            if (active.isEmpty) const SettingRow(title: 'Loading devices…'),
          ],
        ),
        if (!model.isOwner)
          const SettingsNotice(
            label: 'Member',
            tone: BadgeTone.accent,
            text: 'This phone uses a shared Secwet. Only its owner can pair or revoke devices.',
          ),
        if (revoked.isNotEmpty) ...[
          const SectionLabel('Revoked Devices'),
          SecwetCard(
            children: [
              for (final d in revoked)
                SettingRow(
                  title: d.name,
                  muted: true,
                  meta: _meta(d, false),
                  trailing: const SecwetBadge('Revoked', tone: BadgeTone.danger),
                ),
            ],
          ),
        ],
      ],
    );
  }
}

enum _PairPhase { starting, waiting, found, expired }

/// Pairing as the approving device: shows the QR code (session id, an
/// ephemeral public key and the relay address, never a key), waits for the
/// new device, then the user compares the 6-digit codes and approves.
/// Resolves with the added device.
class PairDeviceSheet extends StatefulWidget {
  const PairDeviceSheet({super.key, required this.api});

  final SecwetApi api;

  @override
  State<PairDeviceSheet> createState() => _PairDeviceSheetState();
}

class _PairDeviceSheetState extends State<PairDeviceSheet> {
  _PairPhase _phase = _PairPhase.starting;
  PairingSession? _session;
  PairingFound? _peer;
  DateTime _expiresAt = DateTime.now().add(const Duration(minutes: 5));
  Timer? _tick;
  Timer? _poll;
  bool _approving = false;
  bool _closed = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    _start();
    _tick = Timer.periodic(const Duration(seconds: 1), (_) {
      if (!mounted) return;
      if (_phase == _PairPhase.waiting && DateTime.now().isAfter(_expiresAt)) _phase = _PairPhase.expired;
      setState(() {});
    });
  }

  @override
  void dispose() {
    _tick?.cancel();
    _poll?.cancel();
    if (!_closed) widget.api.cancelPairing().ignore();
    super.dispose();
  }

  Future<void> _start() async {
    setState(() {
      _phase = _PairPhase.starting;
      _peer = null;
      _error = null;
    });
    try {
      final s = await widget.api.startPairing();
      if (!mounted) return;
      setState(() {
        _session = s;
        _expiresAt = DateTime.tryParse(s.expiresAt)?.toLocal() ?? DateTime.now().add(const Duration(minutes: 5));
        _phase = _PairPhase.waiting;
      });
      _schedulePoll();
    } on SecwetException catch (e) {
      if (mounted) setState(() => _error = e.message.isEmpty ? "Couldn't start pairing." : e.message);
    }
  }

  void _schedulePoll() {
    _poll?.cancel();
    _poll = Timer(const Duration(milliseconds: 1500), () async {
      if (!mounted || _phase != _PairPhase.waiting) return;
      try {
        final r = await widget.api.pollPairing();
        if (!mounted) return;
        switch (r) {
          case PairingFound():
            setState(() {
              _peer = r;
              _phase = _PairPhase.found;
            });
            return;
          case PairingExpired():
            setState(() => _phase = _PairPhase.expired);
            return;
          case PairingWaiting() || PairingApproved():
            break;
        }
      } on SecwetException {
        // Keep polling; the relay may be briefly unreachable.
      }
      _schedulePoll();
    });
  }

  Future<void> _approve() async {
    setState(() {
      _approving = true;
      _error = null;
    });
    try {
      final device = await widget.api.approvePairing();
      _closed = true;
      if (mounted) Navigator.of(context).pop(device);
    } on SecwetException catch (e) {
      if (mounted) setState(() => _error = e.message.isEmpty ? "Couldn't approve this device." : e.message);
    } finally {
      if (mounted) setState(() => _approving = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    final remaining = _expiresAt.difference(DateTime.now());
    final peer = _peer;
    final (badge, tone) = switch (_phase) {
      _PairPhase.starting => ('Starting…', BadgeTone.neutral),
      _PairPhase.waiting => ('Waiting for the new device', BadgeTone.accent),
      _PairPhase.found => ('New device found', BadgeTone.success),
      _PairPhase.expired => ('Code expired', BadgeTone.warning),
    };
    return SecwetDialog(
      title: 'Pair a device',
      description: 'Open Secwet on the new device, choose Pair with another device, and scan this code.',
      actions: [
        SecwetButton(
          label: 'Cancel',
          variant: ButtonVariant.secondary,
          onPressed: _approving ? null : () => Navigator.of(context).pop(),
        ),
        if (_phase == _PairPhase.expired)
          SecwetButton(label: 'Show a new code', onPressed: _start)
        else
          SecwetButton(
            label: _approving ? 'Approving…' : 'Codes match, approve',
            onPressed: _phase == _PairPhase.found && !_approving ? _approve : null,
          ),
      ],
      children: [
        if (_error != null) Text(_error!, style: SecwetText.sm(p, color: p.danger)),
        Center(
          child: Opacity(
            opacity: _phase == _PairPhase.expired ? 0.25 : 1,
            child: Container(
              decoration: BoxDecoration(
                border: Border.all(color: p.border),
                borderRadius: BorderRadius.circular(SecwetRadius.card),
              ),
              clipBehavior: Clip.antiAlias,
              child: _session == null
                  ? SizedBox.square(dimension: 200, child: ColoredBox(color: p.surfaceSunken))
                  : QrCode(data: _session!.qrPayload, size: 200, semanticLabel: 'Pairing QR code for a new device'),
            ),
          ),
        ),
        Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            SecwetBadge(badge, tone: tone),
            const SizedBox(height: SecwetSpace.s2),
            Text(
              _phase == _PairPhase.expired
                  ? 'This code can no longer be used. Show a new one to keep pairing.'
                  : 'This code works once and expires in ${formatCountdown(remaining)}. It holds no encryption key.',
              style: SecwetText.sm(p),
            ),
          ],
        ),
        Container(
          padding: const EdgeInsets.all(SecwetSpace.s3),
          decoration: BoxDecoration(
            color: p.surfaceSunken,
            borderRadius: BorderRadius.circular(SecwetRadius.card),
          ),
          child: peer == null
              ? Text('A matching code appears on both devices once the new device scans.', style: SecwetText.sm(p))
              : Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text('${peer.name} (${peer.platform}) wants to join. Check it shows this code:', style: SecwetText.sm(p)),
                    const SizedBox(height: SecwetSpace.s2),
                    Text(peer.code, style: SecwetText.stat(p)),
                    const SizedBox(height: SecwetSpace.s1),
                    Text('Device key ${peer.fingerprint}', style: SecwetText.xs(p, color: p.textTertiary)),
                  ],
                ),
        ),
      ],
    );
  }
}

/// M7 revoke: erase the device's copy on its next contact (remote wipe), or
/// stop its sync and leave it a read-only copy.
class RevokeDeviceSheet extends StatefulWidget {
  const RevokeDeviceSheet({super.key, required this.api, required this.device});

  final SecwetApi api;
  final Device device;

  @override
  State<RevokeDeviceSheet> createState() => _RevokeDeviceSheetState();
}

class _RevokeDeviceSheetState extends State<RevokeDeviceSheet> {
  bool _wipe = true;
  bool _busy = false;
  String? _error;

  Future<void> _confirm() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final r = await widget.api.revokeDevice(widget.device.id, wipe: _wipe);
      if (mounted) Navigator.of(context).pop(r);
    } on SecwetException catch (e) {
      if (mounted) {
        setState(() {
          _error = e.message.isEmpty ? "Couldn't revoke this device. Try again." : e.message;
          _busy = false;
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    final name = widget.device.name;
    return SecwetDialog(
      title: 'Revoke $name?',
      description: "It stops syncing right away. Rotate the encryption key afterwards so it can't read changes made from now on.",
      actions: [
        SecwetButton(label: 'Cancel', variant: ButtonVariant.secondary, onPressed: _busy ? null : () => Navigator.of(context).pop()),
        SecwetButton(
          label: _busy ? 'Revoking…' : (_wipe ? 'Revoke and erase' : 'Revoke and keep copy'),
          variant: ButtonVariant.danger,
          onPressed: _busy ? null : _confirm,
        ),
      ],
      children: [
        ChoiceCards<bool>(
          label: 'How to revoke',
          value: _wipe,
          onChanged: _busy ? null : (v) => setState(() => _wipe = v),
          choices: [
            Choice(
              value: true,
              title: 'Revoke and erase',
              hint: 'Recommended if lost or stolen',
              description:
                  '$name deletes its keys and local data when it next connects. If it never connects again, it keeps what it has, so change the secrets it held at their source.',
            ),
            Choice(
              value: false,
              title: 'Revoke and keep a read-only copy',
              hint: "Recommended for a device you're retiring",
              description: "$name stops syncing. What's already on it stays there, read-only, for anyone using it.",
            ),
          ],
        ),
        if (_error != null) Text(_error!, style: SecwetText.sm(p, color: p.danger)),
      ],
    );
  }
}
