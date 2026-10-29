import 'package:flutter/services.dart';

/// `secwet://invite` and `secwet://pair` links the app is opened with, over
/// our own channel `app.secwet/links` (iOS SceneDelegate.swift, Android
/// SecwetLinksAndScanner.kt). Flutter's router deep linking is off.
class DeepLinks {
  DeepLinks({MethodChannel? channel}) : _channel = channel ?? const MethodChannel('app.secwet/links');

  final MethodChannel _channel;

  /// Calls [onLink] with the launch link (if any) and every later one.
  Future<void> listen(void Function(String link) onLink) async {
    _channel.setMethodCallHandler((call) async {
      if (call.method != 'link' || call.arguments is! String) return false;
      onLink(call.arguments as String);
      return true;
    });
    try {
      final initial = await _channel.invokeMethod<String>('initialLink');
      if (initial != null) onLink(initial);
    } on MissingPluginException {
      // Tests and hosts without the channel.
    }
  }
}

/// QR scanning over `app.secwet/scanner`: AVFoundation on iOS, Google Play
/// services' code scanner on Android. Wrap calls in `session.external(...)`.
class QrScanner {
  QrScanner({MethodChannel? channel}) : _channel = channel ?? const MethodChannel('app.secwet/scanner');

  final MethodChannel _channel;

  /// The scanned text, or null when the user cancelled. Throws
  /// [PlatformException] (`camera_denied`, `camera_unavailable`).
  Future<String?> scan() => _channel.invokeMethod<String>('scan');
}
