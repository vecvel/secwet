import 'dart:async';

import 'package:flutter/widgets.dart';

import '../core/session.dart';
import '../theme/secwet_theme.dart';
import 'secwet_scope.dart';

/// Locks Secwet after the idle time set in Settings (`lock_timeout_minutes`,
/// 0 = never), both while the app is in use and when it comes back from the
/// background after at least that long. While the app is inactive or away
/// (app switcher, notification shade) a blank cover, the same as the lock
/// screen, hides the content so the OS snapshot never shows secrets.
class AutoLock extends StatefulWidget {
  const AutoLock({super.key, required this.child});

  final Widget child;

  @override
  State<AutoLock> createState() => _AutoLockState();
}

class _AutoLockState extends State<AutoLock> {
  late final AppLifecycleListener _lifecycle;
  Timer? _idle;
  bool _covered = false;
  SessionController? _session;

  @override
  void initState() {
    super.initState();
    _lifecycle = AppLifecycleListener(
      onInactive: () => _cover(true),
      onResume: _resumed,
      onHide: _backgrounded,
      onPause: _backgrounded,
    );
  }

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    final session = SecwetScope.of(context).session;
    if (!identical(session, _session)) {
      _session?.removeListener(_restartIdle);
      _session = session..addListener(_restartIdle);
      _restartIdle();
    }
  }

  void _cover(bool on) {
    // Native screens we opened ourselves (biometric prompt, pickers) make the
    // app inactive too; there is nothing secret behind them to hide.
    if (on && _session!.inExternalFlow) return;
    if (_covered != on) setState(() => _covered = on);
  }

  void _backgrounded() {
    final session = _session!;
    if (session.inExternalFlow) return;
    _cover(true);
    session.wentAway();
  }

  void _resumed() {
    // Decide about locking before the cover comes off.
    _session!.cameBack();
    _cover(false);
  }

  void _restartIdle() {
    _idle?.cancel();
    final session = _session!;
    final minutes = session.lockTimeoutMinutes;
    if (session.state != SessionState.unlocked || minutes <= 0) return;
    _idle = Timer(Duration(minutes: minutes), session.lock);
  }

  @override
  void dispose() {
    _idle?.cancel();
    _session?.removeListener(_restartIdle);
    _lifecycle.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    return Listener(
      behavior: HitTestBehavior.translucent,
      onPointerDown: (_) => _restartIdle(),
      child: Stack(
        fit: StackFit.expand,
        children: [
          widget.child,
          if (_covered && _session!.state == SessionState.unlocked)
            ColoredBox(color: p.bg),
        ],
      ),
    );
  }
}
