import 'dart:async';

import 'package:flutter/foundation.dart';

import 'secwet_api.dart';

/// Where the app is: deciding, first launch, locked or open.
enum SessionState { starting, uninitialized, locked, unlocked, failed }

/// App-wide lock state, biometric availability and the auto-lock timeout.
/// The Rust app layer is the authority; this mirrors it for the UI and
/// follows its `locked` / `wiped` / `unlinked` events.
class SessionController extends ChangeNotifier {
  SessionController(this.api, {DateTime Function()? clock}) : _clock = clock ?? DateTime.now {
    _events = api.events.listen(_onEvent);
  }

  final SecwetApi api;
  final DateTime Function() _clock;
  late final StreamSubscription<SecwetEvent> _events;

  SessionState _state = SessionState.starting;
  SessionState get state => _state;

  SecwetException? _error;

  /// Why the last status check failed (state [SessionState.failed]).
  SecwetException? get error => _error;

  BiometricStatus _biometric = BiometricStatus.unavailable;

  /// How this phone unlocks. Without an enrolled biometric no biometric
  /// wording appears anywhere.
  BiometricStatus get biometric => _biometric;

  int _lockTimeoutMinutes = 15;

  String _theme = 'system';

  /// Appearance from Settings: `system`, `light` or `dark`.
  String get theme => _theme;

  bool _readOnly = false;

  /// True after this device was unlinked (revoked with "keep a read-only
  /// copy"): everything stays readable, nothing can change or sync.
  bool get readOnly => _readOnly;

  bool _erased = false;

  /// True after a remote wipe erased this device's copy; the gate shows the
  /// erased screen until [acknowledgeErased].
  bool get erased => _erased;

  void acknowledgeErased() {
    _erased = false;
    notifyListeners();
  }

  String? _pendingLink;

  /// A `secwet://invite` or `secwet://pair` link the app was opened with,
  /// waiting for the screen that handles it.
  String? get pendingLink => _pendingLink;

  /// Records a deep link; the onboarding or join screen takes it.
  void openLink(String link) {
    _pendingLink = link;
    notifyListeners();
  }

  /// Takes the pending link if it starts with [prefix].
  String? takeLink(String prefix) {
    final link = _pendingLink;
    if (link == null || !link.toLowerCase().startsWith(prefix)) return null;
    _pendingLink = null;
    return link;
  }

  /// Idle minutes before auto-lock (from Settings); 0 turns the idle lock off.
  int get lockTimeoutMinutes => _lockTimeoutMinutes;

  String? _notice;

  /// One-shot message for the next screen ("This device was unlinked").
  String? takeNotice() {
    final n = _notice;
    _notice = null;
    return n;
  }

  int _external = 0;

  /// True while a native screen (document picker, share sheet) is in front;
  /// auto-lock then ignores the app going to the background.
  bool get inExternalFlow => _external > 0;

  /// Runs [action] (which presents native UI) without auto-locking for it.
  Future<T> external<T>(Future<T> Function() action) async {
    _external++;
    try {
      return await action();
    } finally {
      _external--;
    }
  }

  void _set(SessionState s) {
    if (_state == s) return;
    _state = s;
    notifyListeners();
  }

  /// Reads the store status and biometric availability from Rust.
  Future<void> refresh() async {
    try {
      final status = await api.status();
      _error = null;
      await _loadBiometric();
      switch (status.state) {
        case LockState.uninitialized:
          _set(SessionState.uninitialized);
        case LockState.locked:
          _set(SessionState.locked);
        case LockState.unlocked:
          await _loadSettings();
          _set(SessionState.unlocked);
      }
    } on SecwetException catch (e) {
      _error = e;
      _set(SessionState.failed);
    }
  }

  Future<void> _loadBiometric() async {
    try {
      _biometric = await api.biometricStatus();
    } on SecwetException {
      _biometric = BiometricStatus.unavailable;
    }
  }

  Future<void> _loadSettings() async {
    try {
      final settings = await api.settings();
      _lockTimeoutMinutes = settings.lockTimeoutMinutes;
      _theme = settings.theme.isEmpty ? 'system' : settings.theme;
    } on SecwetException {
      // Keep the previous values.
    }
    await _loadLink();
  }

  Future<void> _loadLink() async {
    try {
      _readOnly = (await api.linkStatus()).state == 'unlinked';
    } on SecwetException {
      // Locked meanwhile; read again on the next unlock.
    }
  }

  /// Re-reads appearance, auto-lock and link state (after Settings saves).
  Future<void> reloadSettings() async {
    await _loadSettings();
    notifyListeners();
  }

  /// Unlocks. Rust runs the system prompt inside unlock; a phone with no
  /// screen lock never gets here (RootGate stops at "Set a screen lock").
  Future<void> unlock() async {
    await api.unlock();
    await _loadSettings();
    await _loadBiometric();
    _set(SessionState.unlocked);
  }

  /// Called by onboarding once a Secwet exists and is open.
  Future<void> opened() async {
    await _loadSettings();
    await _loadBiometric();
    _set(SessionState.unlocked);
  }

  /// Locks now. Safe to call when already locked.
  Future<void> lock() async {
    if (_state != SessionState.unlocked) return;
    _set(SessionState.locked);
    _clearTemp();
    try {
      await api.lock();
    } on SecwetException {
      // The UI is locked either way; Rust drops its keys on the next lock.
    }
  }

  /// Removes picked or exported files left in the app's temp folder.
  void _clearTemp() {
    api.platform.clearTempDirectory().catchError((Object _) {
      // Best effort; the native side clears the folder on every launch too.
    });
  }

  /// Re-reads how the phone unlocks (a screen lock was set or removed).
  Future<void> reloadBiometric() async {
    await _loadBiometric();
    notifyListeners();
  }

  DateTime? _awaySince;

  /// The app went to the background (not for a native screen we opened).
  void wentAway() {
    if (_state == SessionState.unlocked) _awaySince ??= _clock();
  }

  /// The app is in front again: locks when it was away for the auto-lock
  /// time or longer. "Never" (0) keeps it open.
  void cameBack() {
    final since = _awaySince;
    _awaySince = null;
    if (since == null || _lockTimeoutMinutes <= 0) return;
    if (_clock().difference(since) >= Duration(minutes: _lockTimeoutMinutes)) lock();
  }

  void _onEvent(SecwetEvent e) {
    if (e.isLocked) {
      _set(SessionState.locked);
      _clearTemp();
    } else if (e.isWiped) {
      _notice = 'This device was removed from the Secwet and its data was erased.';
      _erased = true;
      _readOnly = false;
      refresh();
    } else if (e.isUnlinked) {
      _notice = 'This device was unlinked. Your data stays here, but it no longer syncs.';
      _readOnly = true;
      notifyListeners();
    } else if (e.isChanged && (e.scope == 'settings' || e.scope == 'all')) {
      _loadSettings().then((_) => _loadBiometric()).then((_) => notifyListeners());
    }
  }

  @override
  void dispose() {
    _events.cancel();
    super.dispose();
  }
}
