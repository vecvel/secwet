import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

/// Raw dart:ffi bindings to crates/secwet-ffi (include/secwet_ffi.h).
///
/// The Rust library is linked into the iOS Runner (looked up in the process)
/// and shipped as libsecwet_ffi.so on Android. The native side registers its
/// platform services before Dart runs, so Dart only calls, frees and listens.
final class SecwetNativeLib {
  SecwetNativeLib._(DynamicLibrary lib)
      : _call = lib.lookupFunction<_CallC, _CallDart>('secwet_ffi_call'),
        free = lib.lookupFunction<_FreeC, SecwetFreeDart>('secwet_ffi_free'),
        setEventCallback = lib.lookupFunction<_SetCbC, SecwetSetCallbackDart>('secwet_ffi_set_event_callback');

  static SecwetNativeLib? _instance;

  /// Opens the library in the current isolate (each isolate looks it up once).
  static SecwetNativeLib open() => _instance ??= SecwetNativeLib._(
        Platform.isAndroid ? DynamicLibrary.open('libsecwet_ffi.so') : DynamicLibrary.process(),
      );

  final _CallDart _call;
  final SecwetFreeDart free;
  final SecwetSetCallbackDart setEventCallback;

  /// Runs one request synchronously on the calling thread and returns the
  /// response JSON as UTF-8 bytes. Call it from a background isolate: network
  /// commands block.
  ///
  /// The request copy in native memory is zeroed before it is freed, and the
  /// response buffer is zeroized by Rust when freed. The returned copy is a
  /// byte list so the caller can zero it after parsing (decodeResponse).
  Uint8List call(Uint8List request) {
    final req = _malloc(request.length);
    final outLen = _malloc(sizeOf<Size>()).cast<Size>();
    try {
      req.asTypedList(request.length).setAll(0, request);
      final ptr = _call(req, request.length, outLen);
      final len = outLen.value;
      try {
        return Uint8List.fromList(ptr.asTypedList(len));
      } finally {
        free(ptr, len);
      }
    } finally {
      req.asTypedList(request.length).fillRange(0, request.length, 0);
      _free(req);
      _free(outLen.cast());
    }
  }
}

typedef _CallC = Pointer<Uint8> Function(Pointer<Uint8>, Size, Pointer<Size>);
typedef _CallDart = Pointer<Uint8> Function(Pointer<Uint8>, int, Pointer<Size>);
typedef _FreeC = Void Function(Pointer<Uint8>, Size);
typedef SecwetFreeDart = void Function(Pointer<Uint8>, int);
typedef SecwetEventC = Void Function(Pointer<Uint8>, Size);
typedef _SetCbC = Void Function(Pointer<NativeFunction<SecwetEventC>>);
typedef SecwetSetCallbackDart = void Function(Pointer<NativeFunction<SecwetEventC>>);

// C allocator from the process (libc on both platforms); no package needed.
final DynamicLibrary _libc = Platform.isAndroid ? DynamicLibrary.open('libc.so') : DynamicLibrary.process();
final Pointer<Uint8> Function(int) _mallocRaw =
    _libc.lookupFunction<Pointer<Uint8> Function(Size), Pointer<Uint8> Function(int)>('malloc');
final void Function(Pointer<Uint8>) _free =
    _libc.lookupFunction<Void Function(Pointer<Uint8>), void Function(Pointer<Uint8>)>('free');

Pointer<Uint8> _malloc(int size) {
  final p = _mallocRaw(size == 0 ? 1 : size);
  if (p == nullptr) throw StateError('Out of memory');
  return p;
}
