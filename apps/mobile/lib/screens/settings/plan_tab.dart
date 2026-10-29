import 'package:flutter/widgets.dart';

import '../../app/secwet_scope.dart';
import '../../core/secwet_api.dart';
import '../../theme/secwet_theme.dart';
import '../../theme/secwet_tokens.dart';
import '../../widgets/controls.dart';
import '../../widgets/layout.dart';
import '../../widgets/overlays.dart';
import 'settings_screen.dart';
import 'settings_widgets.dart';

/// Settings > Plan (F13): the real plan from the relay entitlement, cached
/// in the app layer. Free never contacts the relay except "Check for Pro".
class PlanTab extends StatefulWidget {
  const PlanTab({super.key, required this.model});

  final SettingsModel model;

  @override
  State<PlanTab> createState() => _PlanTabState();
}

class _PlanTabState extends State<PlanTab> {
  bool _busy = false;
  (BadgeTone, String)? _message;

  SettingsModel get model => widget.model;

  Future<void> _check() async {
    final api = SecwetScope.read(context).api;
    final free = model.plan?.isFree ?? true;
    setState(() {
      _busy = true;
      _message = null;
    });
    try {
      final next = free ? await api.activatePlan() : await api.refreshPlan();
      model.plan = next;
      _message = next.isPro
          ? (BadgeTone.success, 'Pro is active. Sync, pairing and sharing are on.')
          : next.isPaused
              ? (BadgeTone.warning, 'Pro has ended for this Secwet. Sync stays paused; everything here keeps working.')
              : (BadgeTone.warning, "This Secwet doesn't have Pro yet. Everything keeps working on this phone.");
      await model.load();
    } on SecwetException catch (e) {
      _message = (BadgeTone.warning, e.message.isEmpty ? "Couldn't reach the relay. Try again." : e.message);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _copyId() async {
    final id = model.plan?.secwetId;
    if (id == null) return;
    try {
      await SecwetScope.read(context).api.copyText(id);
      if (mounted) setState(() => _message = (BadgeTone.success, 'Secwet ID copied.'));
    } on SecwetException catch (e) {
      if (mounted) setState(() => _message = (BadgeTone.warning, e.message));
    }
  }

  @override
  Widget build(BuildContext context) {
    final readOnly = SecwetScope.of(context).session.readOnly;
    final plan = model.plan;
    final name = plan?.plan ?? 'free';
    final end = formatIsoDate(plan?.expiresAt);
    final relaySaved = (model.relay?.relayUrl ?? '').isNotEmpty || (plan?.relayConfigured ?? false);
    final message = _message;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        if (message != null)
          SettingsNotice(
            label: 'Plan',
            tone: message.$1,
            text: message.$2,
            action: SecwetButton(
              label: 'Dismiss',
              variant: ButtonVariant.tertiary,
              onPressed: () => setState(() => _message = null),
            ),
          ),
        const SectionLabel('Plan'),
        SecwetCard(
          children: [
            SettingRow(
              title: name == 'free' ? 'Free' : 'Pro',
              badges: [
                if (name == 'paused')
                  const SecwetBadge('Paused', tone: BadgeTone.warning)
                else
                  const SecwetBadge('Current plan', tone: BadgeTone.accent),
              ],
              meta: switch (name) {
                'pro' => '${plan?.deviceLimit ?? 5} devices${end != null ? ', until $end' : ''}. Sync, pairing and sharing are on.',
                'paused' => 'Pro ended${end != null ? ' on $end' : ''}. Sync is paused. Nothing is deleted or locked, and you can still export.',
                _ => 'One device, everything local. Secwet never contacts the relay on Free.',
              },
              trailing: SecwetButton(
                label: 'Compare',
                variant: ButtonVariant.tertiary,
                onPressed: plan == null ? null : () => showPlanDialog(context, plan: plan),
              ),
            ),
            SettingRow(
              title: 'Secwet ID',
              meta: plan?.secwetId ?? 'Unlock Secwet to see its ID.',
              trailing: SecwetButton(
                label: 'Copy',
                variant: ButtonVariant.tertiary,
                onPressed: plan == null ? null : _copyId,
              ),
            ),
            SettingRow(
              title: name == 'free' ? 'Check for Pro' : 'Check plan',
              meta: !relaySaved
                  ? 'Add the relay address in Settings > Sync first.'
                  : name == 'free'
                      ? 'Check once so the relay knows this Secwet ID, then again after Pro is granted to it. This is the only time a Free device contacts the relay.'
                      : plan?.checkedAt != null
                          ? 'Checked ${formatAgo(plan!.checkedAt!).toLowerCase()}. The plan is also checked on every sync.'
                          : 'The plan is checked on every sync.',
              trailing: SecwetButton(
                label: _busy ? 'Checking…' : (name == 'free' ? 'Check' : 'Check now'),
                variant: ButtonVariant.secondary,
                onPressed: _busy || readOnly || !relaySaved ? null : _check,
              ),
            ),
          ],
        ),
        const BulletCard(
          title: 'If Pro ends',
          lines: [
            'Nothing is deleted or locked. Everything on this phone stays usable.',
            'Recovery keys, backups and export work on every plan.',
            'Sync pauses on every device and resumes when Pro is renewed.',
          ],
        ),
      ],
    );
  }
}

const _plans = [
  (
    id: 'free',
    name: 'Free',
    summary: 'One device, everything local.',
    features: [
      'Unlimited local projects and secrets',
      'Passwords, tokens, API keys, SSH keys, certificates and environment variables',
      'Encrypted export and recovery',
      'No account, password or cloud dependency. Never contacts the relay',
    ],
  ),
  (
    id: 'pro',
    name: 'Pro',
    summary: 'Secwet on every device you approve.',
    features: [
      'Pair and revoke multiple devices',
      'Near real-time encrypted sync through the relay',
      'Share spaces with people, each with their own key',
      'Encryption key rotation after removing a device',
    ],
  ),
];

/// Free and Pro side by side (desktop PlanDialog). [reason] explains why it
/// opened, for example when pairing needs Pro.
Future<void> showPlanDialog(BuildContext context, {required PlanStatus plan, String? reason}) {
  return showSecwetDialog<void>(context, builder: (context) {
    final p = context.palette;
    final end = formatIsoDate(plan.expiresAt);
    String? badge(String id) {
      if (id == 'pro' && plan.isPaused) return end != null ? 'Ended $end' : 'Ended';
      if (id == plan.plan) return id == 'pro' && end != null ? 'Current plan, until $end' : 'Current plan';
      return null;
    }

    return SecwetDialog(
      title: 'Free and Pro',
      description: reason ?? 'Pro adds sync between devices. Your local data works the same on both plans.',
      actions: [SecwetButton(label: 'Done', onPressed: () => Navigator.of(context).pop())],
      children: [
        for (final plan in _plans)
          Container(
            padding: const EdgeInsets.all(SecwetSpace.s3),
            decoration: BoxDecoration(
              color: p.surface,
              border: Border.all(color: p.border),
              borderRadius: BorderRadius.circular(SecwetRadius.card),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Wrap(
                  spacing: SecwetSpace.s2,
                  crossAxisAlignment: WrapCrossAlignment.center,
                  children: [
                    Text(plan.name, style: SecwetText.md(p, weight: FontWeight.w600)),
                    if (badge(plan.id) != null) SecwetBadge(badge(plan.id)!, tone: BadgeTone.accent),
                  ],
                ),
                const SizedBox(height: 2),
                Text(plan.summary, style: SecwetText.sm(p)),
                const SizedBox(height: SecwetSpace.s2),
                BulletList(lines: plan.features),
              ],
            ),
          ),
        Text(
          'If Pro ends, sync pauses and nothing is deleted or locked. Your local data stays usable and exportable. '
          'To get Pro, use Check for Pro in Settings > Plan once so the relay knows your Secwet ID, '
          'have Pro granted to that ID, then check again.',
          style: SecwetText.sm(p),
        ),
      ],
    );
  });
}
