import 'dart:async';

import 'package:flutter/widgets.dart';

import '../../app/secwet_scope.dart';
import '../../core/secwet_api.dart';
import '../../theme/secwet_theme.dart';
import '../../theme/secwet_tokens.dart';
import '../../widgets/controls.dart';
import '../../widgets/icon.dart';
import '../../widgets/layout.dart';
import '../settings/pair_join_screen.dart';

enum _Mode { create, restore, join }

/// First launch, as on desktop: create a workspace on this phone, restore an
/// encrypted export, or join someone's workspace with an invite link.
class OnboardingScreen extends StatefulWidget {
  const OnboardingScreen({super.key});

  @override
  State<OnboardingScreen> createState() => _OnboardingScreenState();
}

class _OnboardingScreenState extends State<OnboardingScreen> {
  _Mode _mode = _Mode.create;
  bool _busy = false;
  bool _waitingForAccess = false;
  String? _error;
  String? _notice;
  final _deviceName = TextEditingController();
  final _recoveryKey = TextEditingController();
  final _link = TextEditingController();
  final _email = TextEditingController();
  PickedFile? _backup;
  Map<String, String> _fieldErrors = const {};
  Timer? _waitTimer;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) async {
      final scope = SecwetScope.read(context);
      setState(() => _notice = scope.session.takeNotice());
      try {
        final name = await scope.api.systemDeviceName();
        if (mounted && _deviceName.text.isEmpty) _deviceName.text = name;
      } on SecwetException {
        // Leave it empty; Rust falls back to the phone's name.
      }
    });
  }

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    // Links the app was opened with: an invite fills in Join, a pairing
    // code opens the pairing screen.
    final session = SecwetScope.of(context).session;
    final invite = session.takeLink('secwet://invite');
    if (invite != null) {
      _link.text = invite;
      _mode = _Mode.join;
    }
    final pair = session.takeLink('secwet://pair');
    if (pair != null) WidgetsBinding.instance.addPostFrameCallback((_) => _pairWithDevice(pair));
  }

  void _pairWithDevice([String? link]) {
    if (!mounted) return;
    Navigator.of(context).push(PageRouteBuilder<void>(
      pageBuilder: (_, _, _) => PairJoinScreen(link: link),
      transitionsBuilder: (_, animation, _, child) => FadeTransition(opacity: animation, child: child),
    ));
  }

  @override
  void dispose() {
    _waitTimer?.cancel();
    _deviceName.dispose();
    _recoveryKey.dispose();
    _link.dispose();
    _email.dispose();
    super.dispose();
  }

  String? get _name => _deviceName.text.trim().isEmpty ? null : _deviceName.text.trim();

  Future<void> _run(Future<void> Function() action, String fallback) async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      // Keys are only ever stored behind a screen lock. If it was removed
      // while this screen was open, RootGate now shows "Set a screen lock".
      final session = SecwetScope.read(context).session;
      await session.reloadBiometric();
      if (!session.biometric.deviceLock) return;
      await action();
    } on SecwetException catch (e) {
      // A dismissed system prompt is not an error; the button runs it again.
      if (e.code == 'biometric_cancelled') return;
      if (mounted) {
        setState(() {
          _error = e.message.isEmpty ? fallback : e.message;
          if (e.field != null) _fieldErrors = {e.field!: e.message};
        });
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _create() => _run(() async {
        final scope = SecwetScope.read(context);
        await scope.api.create(deviceName: _name);
        await scope.session.opened();
      }, "Couldn't create the workspace. Try again.");

  Future<void> _pickBackup() async {
    final scope = SecwetScope.read(context);
    try {
      final file = await scope.session.external(scope.api.platform.pickFile);
      if (file != null && mounted) setState(() => _backup = file);
    } on Exception {
      if (mounted) setState(() => _error = "Couldn't open that file.");
    }
  }

  Future<void> _restore() async {
    final errs = <String, String>{};
    if (_backup == null) errs['path'] = 'Choose the .secwet backup file.';
    if (_recoveryKey.text.trim().isEmpty) errs['recovery_key'] = 'Enter the recovery key for this backup.';
    setState(() => _fieldErrors = errs);
    if (errs.isNotEmpty) return;
    final key = _recoveryKey.text.trim();
    await _run(() async {
      final scope = SecwetScope.read(context);
      await scope.api.restoreWorkspace(path: _backup!.path, recoveryKey: key, deviceName: _name);
      _recoveryKey.clear();
      await scope.session.opened();
    }, "Couldn't restore this backup.");
  }

  Future<void> _join() async {
    final link = _link.text.trim();
    final email = _email.text.trim();
    final errs = <String, String>{};
    if (link.isEmpty) {
      errs['link'] = 'Paste the invite link you were sent.';
    } else if (!link.toLowerCase().startsWith('secwet://invite')) {
      errs['link'] = 'Invite links start with secwet://invite.';
    }
    if (!RegExp(r'^[^@\s]+@[^@\s]+\.[^@\s]+$').hasMatch(email)) errs['email'] = 'Enter the email the invite was sent to.';
    setState(() => _fieldErrors = errs);
    if (errs.isNotEmpty) return;
    await _run(() async {
      final api = SecwetScope.read(context).api;
      await api.acceptInvitation(link: link, email: email, deviceName: _name);
      _link.clear();
      if (mounted) setState(() => _waitingForAccess = true);
      _waitForAccess();
    }, "Couldn't join with this invite.");
  }

  /// After joining, sync until the shared content arrives, then open.
  void _waitForAccess() {
    _waitTimer?.cancel();
    _waitTimer = Timer.periodic(const Duration(seconds: 5), (_) async {
      final scope = SecwetScope.read(context);
      try {
        await scope.api.syncNow();
        final o = await scope.api.overview();
        if (o.itemsCount > 0 || o.groupsCount > 0) _stopWaiting();
      } on SecwetException {
        // Not granted yet or offline; keep waiting.
      }
    });
  }

  void _stopWaiting() {
    _waitTimer?.cancel();
    if (mounted) SecwetScope.read(context).session.opened();
  }

  void _switch(_Mode mode) => setState(() {
        _mode = mode;
        _error = null;
        _fieldErrors = const {};
      });

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    final (title, subtitle) = _waitingForAccess
        ? (
            'Waiting for access from the admin…',
            'This device joined the workspace. What they shared with you appears once their device syncs. Keep Secwet open.',
          )
        : switch (_mode) {
            _Mode.create => (
                'Welcome to Secwet',
                'Your personal, end-to-end encrypted secret manager. Data stays encrypted on your devices with keys only you control.',
              ),
            _Mode.restore => (
                'Restore from backup',
                'Choose an encrypted .secwet export and enter its recovery key. Everything is decrypted on this phone.',
              ),
            _Mode.join => (
                'Join with an invite',
                'Paste the link you were sent. This device gets its own key, and you only see what was shared with you.',
              ),
          };

    return ColoredBox(
      color: p.bg,
      child: SafeArea(
        child: ListView(
          padding: const EdgeInsets.fromLTRB(SecwetSpace.s6, 0, SecwetSpace.s6, SecwetSpace.s6),
          children: [
            const SizedBox(height: SecwetSpace.s6),
            Text(title, style: TextStyle(fontSize: SecwetFontSize.xxl, fontWeight: FontWeight.w600, height: 1.2, color: p.textPrimary)),
            const SizedBox(height: SecwetSpace.s2),
            Text(subtitle, style: SecwetText.body(p).copyWith(color: p.textSecondary)),
            const SizedBox(height: SecwetSpace.s6),
            if (_notice != null) ...[
              SecwetNotice(text: _notice!, badge: const SecwetBadge('Erased', tone: BadgeTone.warning)),
              const SizedBox(height: SecwetSpace.s4),
            ],
            if (_error != null) ...[
              SecwetNotice(
                text: _error!,
                badge: SecwetBadge(_mode == _Mode.join ? 'Join error' : 'Setup error', tone: BadgeTone.warning),
              ),
              const SizedBox(height: SecwetSpace.s4),
            ],
            if (_waitingForAccess)
              Align(
                alignment: Alignment.centerLeft,
                child: SecwetButton(label: 'Stop waiting', variant: ButtonVariant.secondary, onPressed: _stopWaiting),
              )
            else
              ..._form(),
          ],
        ),
      ),
    );
  }

  List<Widget> _form() {
    const gap = SizedBox(height: SecwetSpace.s4);
    final deviceField = SecwetField(
      label: 'Device name',
      help: 'Identify this device in your encrypted workspace',
      hint: 'e.g. iPhone',
      controller: _deviceName,
    );
    switch (_mode) {
      case _Mode.create:
        return [
          deviceField,
          const SizedBox(height: SecwetSpace.s6),
          SecwetButton(label: _busy ? 'Creating workspace…' : 'Create workspace', expand: true, onPressed: _busy ? null : _create),
          const SizedBox(height: SecwetSpace.s2),
          SecwetButton(
            label: 'Restore from backup',
            variant: ButtonVariant.secondary,
            expand: true,
            onPressed: _busy ? null : () => _switch(_Mode.restore),
          ),
          const SizedBox(height: SecwetSpace.s2),
          SecwetButton(
            label: 'Join with an invite',
            variant: ButtonVariant.secondary,
            expand: true,
            onPressed: _busy ? null : () => _switch(_Mode.join),
          ),
          const SizedBox(height: SecwetSpace.s2),
          SecwetButton(
            label: 'Pair with another device',
            variant: ButtonVariant.secondary,
            expand: true,
            onPressed: _busy ? null : _pairWithDevice,
          ),
        ];
      case _Mode.restore:
        return [
          ListRow(
            title: _backup?.name ?? 'No file chosen',
            meta: _fieldErrors['path'] ?? 'An encrypted export made with Secwet',
            leading: const IconTile(icon: SecwetIcons.file),
            trailing: SecwetButton(
              label: _backup == null ? 'Choose' : 'Change',
              variant: ButtonVariant.secondary,
              small: true,
              onPressed: _busy ? null : _pickBackup,
            ),
          ),
          gap,
          SecwetField(
            label: 'Recovery key',
            hint: 'The key shown when the backup was made',
            controller: _recoveryKey,
            obscure: true,
            autocorrect: false,
            error: _fieldErrors['recovery_key'],
          ),
          gap,
          deviceField,
          const SizedBox(height: SecwetSpace.s6),
          SecwetButton(label: _busy ? 'Restoring…' : 'Restore', expand: true, onPressed: _busy ? null : _restore),
          const SizedBox(height: SecwetSpace.s2),
          SecwetButton(label: 'Back', variant: ButtonVariant.secondary, expand: true, onPressed: _busy ? null : () => _switch(_Mode.create)),
        ];
      case _Mode.join:
        return [
          SecwetField(
            label: 'Invite link',
            hint: 'secwet://invite?…',
            controller: _link,
            autocorrect: false,
            keyboardType: TextInputType.url,
            error: _fieldErrors['link'],
          ),
          gap,
          SecwetField(
            label: 'Your email',
            help: 'The email address the invite was sent to',
            hint: 'name@example.com',
            controller: _email,
            autocorrect: false,
            keyboardType: TextInputType.emailAddress,
            error: _fieldErrors['email'],
          ),
          gap,
          deviceField,
          const SizedBox(height: SecwetSpace.s6),
          SecwetButton(label: _busy ? 'Joining…' : 'Join', expand: true, onPressed: _busy ? null : _join),
          const SizedBox(height: SecwetSpace.s2),
          SecwetButton(label: 'Back', variant: ButtonVariant.secondary, expand: true, onPressed: _busy ? null : () => _switch(_Mode.create)),
        ];
    }
  }
}
