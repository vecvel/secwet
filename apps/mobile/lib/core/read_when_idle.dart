import 'bridge.dart';

/// Runs a local read, waiting out a sync in flight: while a relay call holds
/// the store (auto-sync on open and foreground), reads answer `busy`.
/// Null when the read fails for any other reason (locked meanwhile).
Future<T?> readWhenIdle<T>(Future<T> Function() read) async {
  for (var attempt = 0;; attempt++) {
    try {
      return await read();
    } on SecwetException catch (e) {
      if (e.code != 'busy' || attempt >= 40) return null;
      await Future<void>.delayed(const Duration(milliseconds: 250));
    }
  }
}
