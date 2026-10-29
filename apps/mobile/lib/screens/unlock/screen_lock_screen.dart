import 'package:flutter/widgets.dart';

import '../../app/secwet_scope.dart';
import '../../theme/secwet_theme.dart';
import '../../theme/secwet_tokens.dart';
import '../../widgets/controls.dart';
import '../../widgets/icon.dart';

/// Shown instead of onboarding and the lock screen on a phone with no screen
/// lock. Secwet's keys
/// live behind the screen lock, so there is no way around this screen: the
/// button opens the phone's security settings, and RootGate re-reads the
/// status whenever the app comes back, continuing once a lock is set.
class ScreenLockRequiredScreen extends StatelessWidget {
  const ScreenLockRequiredScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    final scope = SecwetScope.of(context);
    return ColoredBox(
      color: p.bg,
      child: SafeArea(
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: SecwetSpace.s6),
          child: Center(
            child: SingleChildScrollView(
              child: EmptyState(
                icon: SecwetIcons.lock,
                title: 'Set a screen lock to use Secwet',
                body: "Secwet keeps its keys behind this phone's screen lock. Set a passcode, PIN, pattern or "
                    'password, then come back here to continue.',
                action: SecwetButton(
                  label: 'Open security settings',
                  onPressed: () => scope.session.external(scope.api.platform.openSecuritySettings).catchError((Object _) {}),
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}
