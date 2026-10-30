import 'dart:async';

import 'package:flutter/services.dart' show PlatformException;
import 'package:flutter/widgets.dart';

import '../../app/secwet_scope.dart';
import '../../core/links.dart';
import '../../core/secwet_api.dart';
import '../../theme/secwet_theme.dart';
import '../../theme/secwet_tokens.dart';
import '../../widgets/controls.dart';
import '../../widgets/icon.dart';
import '../../widgets/layout.dart';
import 'settings_widgets.dart';

enum _JoinPhase { intro, joining, waiting, expired, approved }

/// Pairing as the new device: scan the code another device of this Secwet
/// shows (Settings > Devices > Pair a device), or open its `secwet://pair`
/// link. Both screens then show the same 6-digit code; once the other
/// device approves, the Secwet is created here with the keys it sent and
/// syncs. Reached from onboarding and from pair links on a fresh phone.
///
/// Any app or web page can open a `secwet://pair` link, so a link the app
/// was opened with never joins by itself: the screen names the relay it
/// would pair through and waits for "Pair with this device". Codes scanned
/// or typed here join right away.
class PairJoinScreen extends StatefulWidget {
  const PairJoinScreen({super.key, this.link, this.scanner});

  /// A pairing link the app was opened with; joining waits for the user.
  final String? link;

  /// Override for tests.
  final QrScanner? scanner;

  @override
  State<PairJoinScreen> createState() => _PairJoinScreenState();
}

class _PairJoinScreenState extends State<PairJoinScreen> {
  _JoinPhase _phase = _JoinPhase.intro;
  final _deviceName = TextEditingController();
  final _manual = TextEditingController();
  bool _showManual = false;
  PairingJoinInfo? _info;
  String? _error;
  Timer? _poll;
  SecwetApi? _api;

  /// The opened link, until the user confirms or dismisses it.
  String? _pending;

  @override
  void initState() {
    super.initState();
    _pending = widget.link;
    WidgetsBinding.instance.addPostFrameCallback((_) async {
      final api = SecwetScope.read(context).api;
      try {
        final name = await api.systemDeviceName();
        if (mounted && _deviceName.text.isEmpty) _deviceName.text = name;
      } on SecwetException {
        // Rust falls back to the phone's name.
      }
    });
  }

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    _api ??= SecwetScope.read(context).api;
  }

  @override
  void dispose() {
    _poll?.cancel();
    if (_phase == _JoinPhase.waiting) _api?.cancelPairingJoin().ignore();
    _deviceName.dispose();
    _manual.dispose();
    super.dispose();
  }

  Future<void> _scan() async {
    final scope = SecwetScope.read(context);
    setState(() => _error = null);
    try {
      final text = await scope.session.external(() => (widget.scanner ?? QrScanner()).scan());
      if (text == null || !mounted) return;
      if (!text.toLowerCase().startsWith('secwet://pair')) {
        setState(() => _error = "That isn't a Secwet pairing code. Scan the code from Settings > Devices on your other device.");
        return;
      }
      await _join(text);
    } on PlatformException catch (e) {
      if (mounted) setState(() => _error = e.message ?? "Couldn't open the camera.");
    }
  }

  Future<void> _join(String link) async {
    final api = SecwetScope.read(context).api;
    setState(() {
      _phase = _JoinPhase.joining;
      _error = null;
      _pending = null;
    });
    try {
      final name = _deviceName.text.trim();
      final info = await api.joinPairing(link.trim(), deviceName: name.isEmpty ? null : name);
      if (!mounted) return;
      setState(() {
        _info = info;
        _phase = _JoinPhase.waiting;
      });
      _schedulePoll();
    } on SecwetException catch (e) {
      if (!mounted) return;
      setState(() {
        _phase = _JoinPhase.intro;
        _error = switch (e.code) {
          'already_joined' => 'This code was already used. Show a new code on your other device.',
          'expired' => 'This code expired. Show a new code on your other device.',
          _ => e.message.isEmpty ? "Couldn't join. Check the connection and try again." : e.message,
        };
      });
    }
  }

  void _schedulePoll() {
    _poll?.cancel();
    _poll = Timer(const Duration(seconds: 2), () async {
      if (!mounted || _phase != _JoinPhase.waiting) return;
      final scope = SecwetScope.read(context);
      try {
        final r = await scope.api.pollPairingJoin();
        if (!mounted) return;
        if (r.approved) {
          setState(() => _phase = _JoinPhase.approved);
          Navigator.of(context).popUntil((route) => route.isFirst);
          await scope.session.opened();
          return;
        }
        if (r.expired) {
          setState(() => _phase = _JoinPhase.expired);
          return;
        }
      } on SecwetException catch (e) {
        if (mounted) setState(() => _error = e.message);
      }
      _schedulePoll();
    });
  }

  Future<void> _cancel() async {
    _poll?.cancel();
    if (_phase == _JoinPhase.waiting) await SecwetScope.read(context).api.cancelPairingJoin().catchError((_) {});
    if (!mounted) return;
    if (Navigator.of(context).canPop()) {
      Navigator.of(context).pop();
    } else {
      setState(() {
        _phase = _JoinPhase.intro;
        _info = null;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    final info = _info;
    final (title, subtitle) = switch (_phase) {
      _JoinPhase.intro || _JoinPhase.joining => (
          'Pair with another device',
          'On a device that already has your Secwet, open Settings > Devices > Pair a device, then scan the code it shows.',
        ),
      _JoinPhase.waiting || _JoinPhase.approved => (
          'Compare the codes',
          'Check that your other device shows the same code, then approve there. Keep Secwet open.',
        ),
      _JoinPhase.expired => (
          'The code expired',
          'Nothing was added. Show a new code on your other device and scan it again.',
        ),
    };
    return ColoredBox(
      color: p.bg,
      child: SafeArea(
        child: ListView(
          padding: const EdgeInsets.fromLTRB(SecwetSpace.s6, 0, SecwetSpace.s6, SecwetSpace.s6),
          children: [
            const SizedBox(height: SecwetSpace.s6),
            const IconTile(icon: SecwetIcons.devices),
            const SizedBox(height: SecwetSpace.s4),
            Text(title, style: TextStyle(fontSize: SecwetFontSize.xxl, fontWeight: FontWeight.w600, height: 1.2, color: p.textPrimary)),
            const SizedBox(height: SecwetSpace.s2),
            Text(subtitle, style: SecwetText.body(p).copyWith(color: p.textSecondary)),
            const SizedBox(height: SecwetSpace.s6),
            if (_error != null) ...[
              SecwetNotice(text: _error!, badge: const SecwetBadge('Pairing', tone: BadgeTone.warning)),
              const SizedBox(height: SecwetSpace.s4),
            ],
            ...switch (_phase) {
              _JoinPhase.intro || _JoinPhase.joining => _intro(),
              _JoinPhase.waiting || _JoinPhase.approved => [
                  Container(
                    padding: const EdgeInsets.all(SecwetSpace.s4),
                    decoration: BoxDecoration(
                      color: p.surface,
                      border: Border.all(color: p.border),
                      borderRadius: BorderRadius.circular(SecwetRadius.card),
                    ),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        SecwetBadge(
                          _phase == _JoinPhase.approved ? 'Approved' : 'Waiting for approval',
                          tone: _phase == _JoinPhase.approved ? BadgeTone.success : BadgeTone.accent,
                        ),
                        const SizedBox(height: SecwetSpace.s3),
                        Text(info?.code ?? '', style: SecwetText.stat(p)),
                        const SizedBox(height: SecwetSpace.s1),
                        Text('This device key ${info?.fingerprint ?? ''}', style: SecwetText.xs(p, color: p.textTertiary)),
                      ],
                    ),
                  ),
                  const SizedBox(height: SecwetSpace.s4),
                  Text(
                    "If the codes differ, cancel: someone may be in between. Nothing is stored here until it's approved.",
                    style: SecwetText.sm(p),
                  ),
                  const SizedBox(height: SecwetSpace.s6),
                  SecwetButton(label: 'Cancel', variant: ButtonVariant.secondary, expand: true, onPressed: _cancel),
                ],
              _JoinPhase.expired => [
                  SecwetButton(label: 'Scan a new code', expand: true, onPressed: () => setState(() => _phase = _JoinPhase.intro)),
                  const SizedBox(height: SecwetSpace.s2),
                  SecwetButton(label: 'Back', variant: ButtonVariant.secondary, expand: true, onPressed: _cancel),
                ],
            },
          ],
        ),
      ),
    );
  }

  List<Widget> _intro() {
    final busy = _phase == _JoinPhase.joining;
    final pending = _pending;
    if (pending != null) return _confirmLink(pending);
    return [
      SecwetField(
        label: 'Device name',
        help: 'How this phone appears on your other devices',
        hint: 'e.g. iPhone',
        controller: _deviceName,
      ),
      const SizedBox(height: SecwetSpace.s6),
      SecwetButton(label: busy ? 'Joining…' : 'Scan code', icon: busy ? null : SecwetIcons.search, expand: true, onPressed: busy ? null : _scan),
      const SizedBox(height: SecwetSpace.s2),
      if (_showManual) ...[
        const SizedBox(height: SecwetSpace.s2),
        SecwetField(
          label: 'Pairing link',
          hint: 'secwet://pair?…',
          controller: _manual,
          autocorrect: false,
          keyboardType: TextInputType.url,
        ),
        const SizedBox(height: SecwetSpace.s4),
        SecwetButton(
          label: 'Continue',
          variant: ButtonVariant.secondary,
          expand: true,
          onPressed: busy ? null : () => _join(_manual.text),
        ),
      ] else
        SecwetButton(
          label: 'Enter the link instead',
          variant: ButtonVariant.secondary,
          expand: true,
          onPressed: busy ? null : () => setState(() => _showManual = true),
        ),
      const SizedBox(height: SecwetSpace.s2),
      SecwetButton(label: 'Back', variant: ButtonVariant.tertiary, expand: true, onPressed: busy ? null : _cancel),
      const SizedBox(height: SecwetSpace.s6),
      BulletList(lines: [
        'The code holds no key. Keys are sent only after you approve on your other device.',
        'Pairing needs Pro and sync on your other device.',
      ]),
    ];
  }

  /// An opened link: who it pairs with, and an explicit go-ahead.
  List<Widget> _confirmLink(String link) {
    final p = context.palette;
    final relay = pairingRelayHost(link);
    return [
      SecwetNotice(
        text: relay == null
            ? "A link opened Secwet to pair this phone. Continue only if you opened it from your own device's pairing code."
            : "A link opened Secwet to pair this phone through $relay. Continue only if you opened it from your own device's pairing code.",
        badge: const SecwetBadge('Pairing link', tone: BadgeTone.warning),
      ),
      const SizedBox(height: SecwetSpace.s4),
      SecwetField(
        label: 'Device name',
        help: 'How this phone appears on your other devices',
        hint: 'e.g. iPhone',
        controller: _deviceName,
      ),
      const SizedBox(height: SecwetSpace.s6),
      SecwetButton(label: 'Pair with this device', expand: true, onPressed: () => _join(link)),
      const SizedBox(height: SecwetSpace.s2),
      SecwetButton(
        label: 'Scan a code instead',
        variant: ButtonVariant.secondary,
        expand: true,
        onPressed: () => setState(() => _pending = null),
      ),
      const SizedBox(height: SecwetSpace.s2),
      SecwetButton(label: 'Back', variant: ButtonVariant.tertiary, expand: true, onPressed: _cancel),
      const SizedBox(height: SecwetSpace.s6),
      Text('Secwet sends this phone\'s new keys to that relay to join.', style: SecwetText.sm(p)),
    ];
  }
}

/// The relay host a `secwet://pair` link names (its `r` field), for showing
/// before joining; null when the link has none.
String? pairingRelayHost(String link) {
  final uri = Uri.tryParse(link.trim());
  final r = uri?.queryParameters['r']?.trim();
  if (r == null || r.isEmpty) return null;
  final full = Uri.tryParse(r.contains('://') ? r : 'https://$r');
  final host = full?.host ?? '';
  if (host.isEmpty) return r;
  return full!.hasPort ? '$host:${full.port}' : host;
}
