import 'package:flutter/widgets.dart';

import '../../app/secwet_scope.dart';
import '../../core/secwet_api.dart';
import '../../theme/secwet_theme.dart';
import '../../theme/secwet_tokens.dart';

/// The lock screen (docs/design-decisions.md, "Mobile unlock and header").
///
/// With a screen lock it is blank: the system prompt (Face ID, Touch ID or
/// fingerprint, with the passcode or PIN as fallback) opens by itself once
/// the app is in front, and again after a cancel when the user taps the
/// screen or brings the app back. Rust runs the prompt inside unlock, so this
/// screen cannot open the store on its own.
///
/// A phone with no screen lock never shows this screen: RootGate stops at
/// "Set a screen lock to use Secwet" instead. The recovery key is never asked
/// for to unlock.
class LockScreen extends StatefulWidget {
  const LockScreen({super.key});

  @override
  State<LockScreen> createState() => _LockScreenState();
}

class _LockScreenState extends State<LockScreen> {
  bool _busy = false;
  String? _error;
  bool _wasAway = false;
  late final AppLifecycleListener _lifecycle;

  @override
  void initState() {
    super.initState();
    // Only a real return to the app prompts again. The system prompt itself
    // only makes the app inactive, so closing it never reopens it.
    _lifecycle = AppLifecycleListener(
      onHide: () => _wasAway = true,
      onResume: () {
        if (!_wasAway) return;
        _wasAway = false;
        _prompt();
      },
    );
    WidgetsBinding.instance.addPostFrameCallback((_) => _start());
  }

  @override
  void dispose() {
    _lifecycle.dispose();
    super.dispose();
  }

  Future<void> _start() async {
    if (!mounted) return;
    final session = SecwetScope.read(context).session;
    await session.reloadBiometric();
    final notice = session.takeNotice();
    if (notice != null && mounted) setState(() => _error = notice);
    await _prompt();
  }

  /// Opens the system prompt when the phone has a screen lock and the app
  /// is in front (iOS only shows it to a foreground app).
  Future<void> _prompt() async {
    if (!mounted || _busy) return;
    if (WidgetsBinding.instance.lifecycleState != AppLifecycleState.resumed) return;
    if (!SecwetScope.read(context).session.biometric.deviceLock) return;
    await _unlock();
  }

  Future<void> _unlock() async {
    if (_busy) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    final session = SecwetScope.read(context).session;
    try {
      // The system prompt makes the app inactive; that must not cover or lock.
      await session.external(session.unlock);
    } on SecwetException catch (e) {
      // A dismissed prompt leaves the screen blank; a tap shows it again.
      if (mounted) setState(() => _error = e.code == 'biometric_cancelled' ? null : e.message);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    return GestureDetector(
      behavior: HitTestBehavior.opaque,
      onTap: _unlock,
      child: ColoredBox(
        color: p.bg,
        child: SafeArea(
          child: _error == null
              ? const SizedBox.expand()
              : Center(
                  child: Padding(
                    padding: const EdgeInsets.symmetric(horizontal: SecwetSpace.s6),
                    child: Text(
                      '$_error Tap to try again.',
                      textAlign: TextAlign.center,
                      style: SecwetText.md(p, color: p.textSecondary),
                    ),
                  ),
                ),
        ),
      ),
    );
  }
}
