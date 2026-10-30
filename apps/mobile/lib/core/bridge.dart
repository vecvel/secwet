import 'dart:async';
import 'dart:convert';
import 'dart:ffi';
import 'dart:isolate';
import 'dart:typed_data';

import 'ffi_bindings.dart';

/// Structured error from the app layer (`UiError`): `code` is stable,
/// `message` is fit for the UI.
class SecwetException implements Exception {
  const SecwetException(this.code, this.message, {this.field});

  factory SecwetException.fromJson(Map<String, Object?> j) => SecwetException(
        j['code'] as String? ?? 'internal',
        j['message'] as String? ?? 'Something went wrong.',
        field: j['field'] as String?,
      );

  final String code;
  final String? field;
  final String message;

  @override
  String toString() => field == null ? '$code: $message' : '$code[$field]: $message';
}

/// A notification from the app layer: `secwet://changed` (with a scope),
/// `secwet://locked`, `secwet://wiped`, `secwet://unlinked`.
class SecwetEvent {
  const SecwetEvent(this.name, this.payload);

  final String name;
  final Object? payload;

  bool get isChanged => name == 'secwet://changed';
  bool get isLocked => name == 'secwet://locked';
  bool get isWiped => name == 'secwet://wiped';
  bool get isUnlinked => name == 'secwet://unlinked';

  /// `spaces`, `labels`, `items`, `secrets`, `settings`, `all`, ... for changes.
  String? get scope => payload is Map ? (payload as Map)['scope'] as String? : null;
}

/// Transport to the Rust app layer: one JSON command in, one result out.
abstract interface class SecwetBridge {
  /// Runs [cmd] with snake_case [args]; throws [SecwetException] on failure.
  Future<Object?> call(String cmd, [Map<String, Object?> args = const {}]);

  /// App-layer notifications, delivered on the UI isolate.
  Stream<SecwetEvent> get events;
}

/// The real bridge over dart:ffi. Each call runs on a short-lived background
/// isolate, so slow commands (sync, pairing, unlock with a biometric prompt)
/// never block the UI.
class NativeSecwetBridge implements SecwetBridge {
  NativeSecwetBridge() {
    final lib = SecwetNativeLib.open();
    _listener = NativeCallable<SecwetEventC>.listener(_onEvent);
    lib.setEventCallback(_listener.nativeFunction);
  }

  late final NativeCallable<SecwetEventC> _listener;
  final _events = StreamController<SecwetEvent>.broadcast();

  void _onEvent(Pointer<Uint8> ptr, int len) {
    final lib = SecwetNativeLib.open();
    try {
      final body = jsonDecode(utf8.decode(ptr.asTypedList(len))) as Map<String, Object?>;
      _events.add(SecwetEvent(body['name'] as String? ?? '', body['payload']));
    } on FormatException {
      // Ignore a malformed event; the next change refreshes the UI anyway.
    } finally {
      lib.free(ptr, len);
    }
  }

  @override
  Stream<SecwetEvent> get events => _events.stream;

  @override
  Future<Object?> call(String cmd, [Map<String, Object?> args = const {}]) async {
    // Encoded straight to bytes (no intermediate JSON String), so every
    // copy of the request can be zeroed. Values the caller passed in as
    // Strings stay in the Dart heap until collected: Dart strings are
    // immutable and cannot be wiped.
    final request = Uint8List.fromList(JsonUtf8Encoder().convert({'cmd': cmd, 'args': args}));
    final response = await Isolate.run(() {
      final bytes = SecwetNativeLib.open().call(request);
      request.fillRange(0, request.length, 0);
      return bytes;
    }, debugName: 'secwet:$cmd');
    request.fillRange(0, request.length, 0);
    try {
      return decodeResponseBytes(response);
    } finally {
      response.fillRange(0, response.length, 0);
    }
  }

  /// Stops event delivery (tests and hot restart).
  void dispose() {
    SecwetNativeLib.open().setEventCallback(nullptr);
    _listener.close();
    _events.close();
  }
}

/// Unwraps `{"ok": value}` or throws for `{"err": {...}}`.
Object? decodeResponse(String response) => _unwrap(jsonDecode(response) as Map<String, Object?>);

/// [decodeResponse] for UTF-8 bytes, parsed without building the whole
/// response as one String first. Secret values in the result are still Dart
/// Strings, which cannot be wiped.
Object? decodeResponseBytes(Uint8List response) =>
    _unwrap(utf8.decoder.fuse(json.decoder).convert(response) as Map<String, Object?>);

Object? _unwrap(Map<String, Object?> body) {
  if (body.containsKey('err')) {
    throw SecwetException.fromJson((body['err'] as Map).cast<String, Object?>());
  }
  return body['ok'];
}
