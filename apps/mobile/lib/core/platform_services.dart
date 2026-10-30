import 'package:flutter/services.dart';

/// A file the user picked; [path] is a private copy the app can read.
class PickedFile {
  const PickedFile(this.path, this.name);

  final String path;
  final String name;
}

/// Native services over our own platform channel (`app.secwet/platform`):
/// the system document picker and save dialog, and the app's private temp
/// directory. iOS: ios/Runner/SecwetPlatform.swift. Android:
/// android/.../SecwetPlatformChannel.kt.
class PlatformServices {
  PlatformServices({MethodChannel? channel}) : _channel = channel ?? const MethodChannel('app.secwet/platform');

  final MethodChannel _channel;

  /// Lets the user pick a document; null when cancelled.
  Future<PickedFile?> pickFile() async {
    final r = await _channel.invokeMapMethod<String, Object?>('pickFile');
    if (r == null) return null;
    return PickedFile(r['path'] as String, r['name'] as String);
  }

  /// Hands the file at [path] to the system save dialog (iOS Files, Android
  /// Storage Access Framework) and deletes the private copy afterwards.
  /// Returns false when the user cancelled.
  Future<bool> saveFile(String path, String suggestedName) async =>
      await _channel.invokeMethod<bool>('saveFile', {'path': path, 'name': suggestedName}) ?? false;

  /// Hands [bytes] to the system save dialog as [suggestedName] without
  /// staging them as a plain file: Android writes them straight into the
  /// document the user creates, iOS through a file readable only while the
  /// phone is unlocked that lives as long as the dialog. Returns false when
  /// the user cancelled.
  Future<bool> saveBytes(Uint8List bytes, String suggestedName) async =>
      await _channel.invokeMethod<bool>('saveBytes', {'bytes': bytes, 'name': suggestedName}) ?? false;

  /// A private directory for files on their way in or out (exports).
  Future<String> tempDirectory() async => (await _channel.invokeMethod<String>('tempDirectory'))!;

  /// Deletes everything in [tempDirectory] unless a file dialog is open. The
  /// native side also does this on every launch, before Dart starts.
  Future<void> clearTempDirectory() => _channel.invokeMethod<void>('clearTempDirectory');

  /// Opens the phone's security settings, where the user sets a screen lock
  /// (iOS: Secwet's page in Settings, since iOS links nowhere deeper).
  Future<void> openSecuritySettings() => _channel.invokeMethod<void>('openSecuritySettings');

  /// Draws the first [maxPages] pages of a PDF as PNG images [width] pixels
  /// wide (PDFKit on iOS, PdfRenderer on Android), for asset previews. Empty
  /// when the document cannot be read.
  Future<List<Uint8List>> renderPdf(Uint8List bytes, {int maxPages = 20, int width = 1080}) async =>
      await _channel.invokeListMethod<Uint8List>('renderPdf', {'bytes': bytes, 'maxPages': maxPages, 'width': width}) ??
      const [];
}
