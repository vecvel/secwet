import 'package:flutter/widgets.dart';

import '../../app/secwet_scope.dart';
import '../../core/secwet_api.dart';
import '../../theme/secwet_theme.dart';
import '../../widgets/controls.dart';
import '../../widgets/layout.dart';
import '../../widgets/overlays.dart';
import 'settings_screen.dart';
import 'settings_widgets.dart';

/// Settings > Security: master key rotation (owner devices), how the phone
/// unlocks (always the system prompt with a screen lock; biometric wording
/// only when one is enrolled), lock now, and how keys are protected.
class SecurityTab extends StatelessWidget {
  const SecurityTab({super.key, required this.model});

  final SettingsModel model;

  @override
  Widget build(BuildContext context) {
    final session = SecwetScope.of(context).session;
    final keys = model.keys;
    final canRotate = !session.readOnly && model.isOwner;
    final recommended = keys?.rotationRecommended ?? false;
    final String meta;
    if (!model.isOwner) {
      meta = 'Managed by the workspace owner. Shared spaces use their own keys.';
    } else if (keys?.rotatedAt != null) {
      meta = 'Last rotated ${formatAgo(keys!.rotatedAt!).toLowerCase()}. Rotate after revoking a device.';
    } else {
      meta = 'Never rotated. Rotate after revoking a device.';
    }
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        if (recommended && canRotate) RotationNotice(model: model),
        const SectionLabel('Key Rotation'),
        SecwetCard(
          children: [
            SettingRow(
              title: 'Master encryption key',
              badges: [
                if (keys != null) SecwetBadge('Version ${keys.epoch}'),
                if (recommended) const SecwetBadge('Rotation recommended', tone: BadgeTone.warning),
              ],
              meta: meta,
              trailing: model.isOwner
                  ? SecwetButton(
                      label: 'Rotate key',
                      variant: recommended ? ButtonVariant.primary : ButtonVariant.secondary,
                      onPressed: canRotate ? () => showRotateKeyDialog(context, model) : null,
                    )
                  : null,
            ),
          ],
        ),
        const SectionLabel('Locking'),
        SecwetCard(
          children: [
            UnlockMethodRow(status: session.biometric),
            SettingRow(
              title: 'Lock now',
              meta: session.lockTimeoutMinutes > 0
                  ? 'Secwet also locks after ${_minutes(session.lockTimeoutMinutes)} idle or away from the app.'
                  : 'Auto-lock is off. Secwet still locks every time it starts.',
              trailing: SecwetButton(label: 'Lock', variant: ButtonVariant.secondary, onPressed: session.lock),
            ),
          ],
        ),
        const SectionLabel('Zeroization & Memory Protection'),
        const SecwetCard(
          children: [
            SettingRow(
              title: 'Strict zeroization policy',
              meta: 'Decrypted keys, secrets, notes and file buffers are wiped from memory whenever Secwet locks or closes.',
              trailing: SecwetBadge('Enforced', tone: BadgeTone.success),
            ),
            SettingRow(
              title: 'Storage at rest',
              meta: "Records and files are encrypted with XChaCha20-Poly1305. Keys stay in this phone's secure storage, "
                  "behind its screen lock. Removing the screen lock erases them, so keep a recovery key.",
              trailing: SecwetBadge('XChaCha20', tone: BadgeTone.success),
            ),
          ],
        ),
      ],
    );
  }
}

String _minutes(int m) => m == 60 ? '1 hour' : '$m minutes';

/// How Secwet opens on this phone. Read-only: with a screen lock the system
/// prompt is always required, so there is nothing to turn on or off.
class UnlockMethodRow extends StatelessWidget {
  const UnlockMethodRow({super.key, required this.status});

  final BiometricStatus status;

  @override
  Widget build(BuildContext context) {
    // Without a screen lock Secwet stops at "Set a screen lock" before it
    // opens, so an open Secwet always has one; this is the passcode-only case.
    if (!status.available) {
      return const SettingRow(
        title: "Unlock with the phone's passcode",
        badges: [SecwetBadge('Always on', tone: BadgeTone.success)],
        meta: 'Every time Secwet opens, and when you come back after the auto-lock time.',
      );
    }
    return SettingRow(
      title: 'Unlock with ${status.label}',
      badges: const [SecwetBadge('Always on', tone: BadgeTone.success)],
      meta: "Every time Secwet opens, and when you come back after the auto-lock time. The phone's passcode works when ${status.label} can't read you.",
    );
  }
}

/// "A device was revoked. Rotate the encryption key…" with the action.
class RotationNotice extends StatelessWidget {
  const RotationNotice({super.key, required this.model});

  final SettingsModel model;

  @override
  Widget build(BuildContext context) {
    final reason = model.keys?.pendingReason?.trim();
    return SettingsNotice(
      label: 'Rotate key',
      text: "${reason == null || reason.isEmpty ? 'A device was revoked.' : reason} "
          "Rotate the encryption key so it can't read changes made from now on.",
      action: SecwetButton(
        label: 'Rotate encryption key',
        variant: ButtonVariant.tertiary,
        onPressed: () => showRotateKeyDialog(context, model),
      ),
    );
  }
}

Future<void> showRotateKeyDialog(BuildContext context, SettingsModel model) async {
  await showSecwetDialog<void>(context, builder: (_) => _RotateKeyDialog(api: SecwetScope.read(context).api));
  await model.load();
}

class _RotateKeyDialog extends StatefulWidget {
  const _RotateKeyDialog({required this.api});

  final SecwetApi api;

  @override
  State<_RotateKeyDialog> createState() => _RotateKeyDialogState();
}

class _RotateKeyDialogState extends State<_RotateKeyDialog> {
  bool _running = false;
  String? _error;
  KeyRotationReport? _report;

  Future<void> _run() async {
    setState(() {
      _running = true;
      _error = null;
    });
    try {
      final report = await widget.api.rotateKey();
      if (mounted) setState(() => _report = report);
    } on SecwetException catch (e) {
      if (mounted) setState(() => _error = e.message.isEmpty ? "Couldn't rotate the key. Try again." : e.message);
    } finally {
      if (mounted) setState(() => _running = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    final report = _report;
    if (report != null) {
      return SecwetDialog(
        title: 'Key rotated',
        description: 'Your active devices pick up the new key on their next sync.',
        actions: [SecwetButton(label: 'Done', onPressed: () => Navigator.of(context).pop())],
        children: [
          SecwetNotice(
            text: 'Now on key version ${report.epoch}. Re-encrypted ${plural(report.resealed, 'item')} on this phone.',
            badge: const SecwetBadge('Done', tone: BadgeTone.success),
          ),
          if (report.adoptedFromConflict)
            Text('Another device rotated first; this phone switched to its key.', style: SecwetText.sm(p)),
        ],
      );
    }
    return SecwetDialog(
      title: 'Rotate encryption key?',
      description: 'A new encryption key is created on this phone and shared only with your active devices.',
      actions: [
        SecwetButton(
          label: 'Cancel',
          variant: ButtonVariant.secondary,
          onPressed: _running ? null : () => Navigator.of(context).pop(),
        ),
        SecwetButton(label: _running ? 'Rotating…' : 'Rotate key', onPressed: _running ? null : _run),
      ],
      children: [
        const BulletList(lines: [
          "Revoked devices can't read anything changed after this.",
          'Your recovery key keeps working.',
        ]),
        if (_error != null) Text(_error!, style: SecwetText.sm(p, color: p.danger)),
      ],
    );
  }
}
