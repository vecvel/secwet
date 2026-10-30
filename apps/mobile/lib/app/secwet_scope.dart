import 'package:flutter/widgets.dart';

import '../core/secwet_api.dart';
import '../core/session.dart';

/// Gives every screen the app-layer API and the session:
/// `SecwetScope.of(context).api.items(groupId: id)`.
class SecwetScope extends InheritedNotifier<SessionController> {
  const SecwetScope({super.key, required SessionController session, required super.child}) : super(notifier: session);

  static SecwetScope of(BuildContext context) {
    final scope = context.dependOnInheritedWidgetOfExactType<SecwetScope>();
    assert(scope != null, 'SecwetScope missing above this widget');
    return scope!;
  }

  /// Like [of] without rebuilding when the session changes.
  static SecwetScope read(BuildContext context) =>
      context.getElementForInheritedWidgetOfExactType<SecwetScope>()!.widget as SecwetScope;

  SessionController get session => notifier!;
  SecwetApi get api => notifier!.api;
}
