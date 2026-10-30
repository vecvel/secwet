import 'package:flutter/widgets.dart';

import 'app/app.dart';
import 'core/bridge.dart';
import 'core/links.dart';
import 'core/secwet_api.dart';
import 'core/session.dart';

/// The native side (AppDelegate on iOS, MainActivity on Android) registers
/// secure storage, clipboard and biometrics with Rust before this runs.
void main() {
  WidgetsFlutterBinding.ensureInitialized();
  final api = SecwetApi(NativeSecwetBridge());
  final session = SessionController(api);
  DeepLinks().listen(session.openLink);
  runApp(SecwetApp(session: session));
}
