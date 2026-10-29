import 'dart:async';

import 'package:flutter/widgets.dart';

import '../../app/secwet_scope.dart';
import '../../core/secwet_api.dart';
import '../../core/session.dart';
import '../../widgets/controls.dart';
import '../../widgets/overlays.dart';

/// Keeps an open Secwet in sync: syncs when the shell opens (after unlock)
/// and whenever the app returns to the foreground, quietly and only when
/// this Secwet syncs (Pro, relay set, device not unlinked). Errors are left
/// to the session: a revocation arrives as a `wiped` or `unlinked` event.
///
/// Also answers invite and pairing links opened while a Secwet is already
/// here: they only set up a new phone.
class AutoSync extends StatefulWidget {
  const AutoSync({super.key, required this.child});

  final Widget child;

  @override
  State<AutoSync> createState() => _AutoSyncState();
}

class _AutoSyncState extends State<AutoSync> {
  late final AppLifecycleListener _lifecycle;
  SessionController? _session;
  bool _running = false;
  DateTime? _last;

  static const _minGap = Duration(seconds: 15);

  @override
  void initState() {
    super.initState();
    _lifecycle = AppLifecycleListener(onResume: () => _sync());
    WidgetsBinding.instance.addPostFrameCallback((_) => _sync(force: true));
  }

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    final session = SecwetScope.of(context).session;
    if (!identical(session, _session)) {
      _session?.removeListener(_onSession);
      _session = session..addListener(_onSession);
      _onSession();
    }
  }

  void _onSession() {
    final session = _session!;
    if (session.state != SessionState.unlocked || session.pendingLink == null) return;
    final link = session.takeLink('secwet://');
    if (link == null) return;
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!mounted) return;
      showToast(
        context,
        link.toLowerCase().startsWith('secwet://invite')
            ? 'This phone already has a Secwet. Open invite links on a phone without one.'
            : 'This phone already has a Secwet. Scan pairing codes on the new device.',
        tone: BadgeTone.warning,
      );
    });
  }

  Future<void> _sync({bool force = false}) async {
    final session = _session;
    if (session == null || _running || session.state != SessionState.unlocked || session.readOnly) return;
    final last = _last;
    if (!force && last != null && DateTime.now().difference(last) < _minGap) return;
    _running = true;
    try {
      final plan = await session.api.planStatus();
      if (plan.syncEnabled && plan.relayConfigured) {
        _last = DateTime.now();
        await session.api.syncNow();
      }
    } on SecwetException {
      // Offline or locked meanwhile; the next open or pull to refresh retries.
    } finally {
      _running = false;
    }
  }

  @override
  void dispose() {
    _lifecycle.dispose();
    _session?.removeListener(_onSession);
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => widget.child;
}
