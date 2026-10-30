import 'package:flutter/widgets.dart';

import '../core/session.dart';
import '../screens/onboarding/onboarding_screen.dart';
import '../screens/settings/auto_sync.dart';
import '../screens/settings/erased_screen.dart';
import '../screens/unlock/screen_lock_screen.dart';
import '../screens/unlock/unlock_screen.dart';
import '../theme/secwet_theme.dart';
import '../widgets/controls.dart';
import '../widgets/icon.dart';
import 'secwet_scope.dart';
import 'shell.dart';

/// Picks the top-level screen from the session: onboarding on first launch,
/// the blank lock screen while locked, the tab shell when open. A phone with
/// no screen lock stops at "Set a screen lock to use Secwet" before
/// onboarding and unlock.
class RootGate extends StatefulWidget {
  const RootGate({super.key});

  @override
  State<RootGate> createState() => _RootGateState();
}

class _RootGateState extends State<RootGate> {
  late final AppLifecycleListener _lifecycle;

  @override
  void initState() {
    super.initState();
    // Coming back from the phone's settings: a screen lock may be set now.
    _lifecycle = AppLifecycleListener(onResume: () {
      final session = SecwetScope.read(context).session;
      if (!session.biometric.deviceLock) session.reloadBiometric();
    });
    WidgetsBinding.instance.addPostFrameCallback((_) => SecwetScope.read(context).session.refresh());
  }

  @override
  void dispose() {
    _lifecycle.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final session = SecwetScope.of(context).session;
    final p = context.palette;
    final noScreenLock = !session.biometric.deviceLock;
    final Widget page = switch (session.state) {
      // Blank, like the lock screen that usually follows.
      SessionState.starting => ColoredBox(key: const ValueKey('starting'), color: p.bg),
      SessionState.uninitialized when session.erased => const ErasedScreen(key: ValueKey('erased')),
      SessionState.uninitialized || SessionState.locked when noScreenLock =>
        const ScreenLockRequiredScreen(key: ValueKey('screen-lock')),
      SessionState.uninitialized => const OnboardingScreen(key: ValueKey('onboarding')),
      SessionState.locked => const LockScreen(key: ValueKey('unlock')),
      SessionState.unlocked => const AutoSync(key: ValueKey('shell'), child: SecwetShell()),
      SessionState.failed => ColoredBox(
          key: const ValueKey('failed'),
          color: p.bg,
          child: SafeArea(
            child: Padding(
              padding: const EdgeInsets.all(24),
              child: Center(
                child: EmptyState(
                  icon: SecwetIcons.info,
                  title: 'Secwet could not start',
                  body: session.error?.message ?? 'Something went wrong while opening Secwet.',
                  action: SecwetButton(label: 'Try again', onPressed: session.refresh),
                ),
              ),
            ),
          ),
        ),
    };
    return AnimatedSwitcher(duration: const Duration(milliseconds: 180), child: page);
  }
}
