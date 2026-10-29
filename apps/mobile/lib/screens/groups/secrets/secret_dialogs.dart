import 'dart:async';

import 'package:flutter/widgets.dart';

import '../../../app/secwet_scope.dart';
import '../../../core/secwet_api.dart';
import '../../../theme/secwet_theme.dart';
import '../../../theme/secwet_tokens.dart';
import '../../../widgets/controls.dart';
import '../../../widgets/icon.dart';
import '../../../widgets/layout.dart';
import '../../../widgets/overlays.dart';
import '../common.dart';
import 'secret_parser.dart';

/// Secret kinds in the desktop's default order (alphabetical by label).
const secretKindOrder = [
  SecretKind.accessToken,
  SecretKind.apiKey,
  SecretKind.certificate,
  SecretKind.codes,
  SecretKind.envVar,
  SecretKind.password,
  SecretKind.sshKey,
];

/// The desktop `kindLabels` order used by the Type select.
const _typeSelectOrder = [
  SecretKind.codes,
  SecretKind.apiKey,
  SecretKind.accessToken,
  SecretKind.password,
  SecretKind.envVar,
  SecretKind.sshKey,
  SecretKind.certificate,
];

final _namePattern = RegExp(r'^[A-Za-z_][A-Za-z0-9_.@-]*$');

class _Entry {
  _Entry({String name = '', String value = '', String note = ''})
      : name = TextEditingController(text: name),
        value = TextEditingController(text: value),
        note = TextEditingController(text: note);

  final TextEditingController name;
  final TextEditingController value;
  final TextEditingController note;
  String? errorName;
  String? errorValue;

  void dispose() {
    // Scrub the value from the controller before letting it go.
    value.clear();
    name.dispose();
    value.dispose();
    note.dispose();
  }
}

/// Add or edit secrets (desktop SecretDialog): type and environment for the
/// batch, then name, value and note per entry; "Add another"; pasting an
/// .env, JSON or key=value block fills several entries. Resolves true when saved.
Future<bool> showSecretDialog(
  BuildContext context, {
  required Item item,
  required List<Environment> environments,
  required String? defaultEnvironmentId,
  required List<SecretMeta> existing,
  SecretMeta? initial,
}) async =>
    await showSecwetDialog<bool>(
      context,
      builder: (_) => _SecretDialog(
        item: item,
        environments: environments,
        defaultEnvironmentId: defaultEnvironmentId,
        existing: existing,
        initial: initial,
      ),
    ) ??
    false;

class _SecretDialog extends StatefulWidget {
  const _SecretDialog({
    required this.item,
    required this.environments,
    required this.defaultEnvironmentId,
    required this.existing,
    this.initial,
  });

  final Item item;
  final List<Environment> environments;
  final String? defaultEnvironmentId;
  final List<SecretMeta> existing;
  final SecretMeta? initial;

  @override
  State<_SecretDialog> createState() => _SecretDialogState();
}

class _SecretDialogState extends State<_SecretDialog> {
  late SecretKind _kind = widget.initial?.kind ?? SecretKind.envVar;
  late final String? _initialEnvId = widget.initial != null ? widget.initial!.environmentId : widget.defaultEnvironmentId;
  late String? _environmentId = _initialEnvId;
  late final List<_Entry> _entries = [_Entry(name: widget.initial?.name ?? '', note: widget.initial?.note ?? '')];
  String? _pastedNotice;
  Timer? _noticeTimer;
  bool _saving = false;
  String? _error;

  /// Last text per field, to tell a paste from typing.
  final _lastText = <TextEditingController, String>{};

  bool get _editing => widget.initial != null;
  bool get _envScoped => widget.environments.isNotEmpty && _initialEnvId != null;

  @override
  void initState() {
    super.initState();
    if (_editing) {
      SecwetScope.read(context).api.revealSecret(widget.initial!.id).then((v) {
        if (mounted) _entries.first.value.text = v;
      }, onError: (_) {});
    }
  }

  @override
  void dispose() {
    _noticeTimer?.cancel();
    for (final e in _entries) {
      e.dispose();
    }
    super.dispose();
  }

  String? get _envName => widget.environments.where((e) => e.id == _environmentId).firstOrNull?.name;

  /// A paste of several pairs (or one pair into the name of an empty form)
  /// fills the entries. Single-line fields drop newlines, so a multi-line
  /// .env block is caught in the Value field.
  void _maybePaste(_Entry entry, String text, {required bool isName}) {
    if (_editing) return;
    final field = isName ? entry.name : entry.value;
    final before = _lastText[field] ?? '';
    _lastText[field] = text;
    if (text.length - before.length < 3 || !RegExp('[=:\n]').hasMatch(text)) return;
    final parsed = parseSecretText(text);
    final single = parsed.length == 1 && isName && _entries.length == 1 && entry.value.text.isEmpty;
    if (parsed.length < 2 && !single) return;
    setState(() {
      for (final e in _entries) {
        e.dispose();
      }
      _lastText.clear();
      _entries
        ..clear()
        ..addAll([for (final p in parsed) _Entry(name: p.name, value: p.value)]);
      _pastedNotice = 'Detected ${parsed.length} ${parsed.length == 1 ? 'secret' : 'secrets'} from clipboard';
    });
    _noticeTimer?.cancel();
    _noticeTimer = Timer(const Duration(milliseconds: 3500), () {
      if (mounted) setState(() => _pastedNotice = null);
    });
  }

  bool _validate() {
    var ok = true;
    final seen = <String>{};
    for (final e in _entries) {
      final t = e.name.text.trim();
      e.errorName = null;
      e.errorValue = null;
      if (t.isEmpty) {
        e.errorName = 'Enter a name.';
      } else if (!_namePattern.hasMatch(t)) {
        e.errorName = 'Use letters, numbers, underscores, dots or dashes.';
      } else if (seen.contains(t.toLowerCase())) {
        e.errorName = 'Duplicate name in this batch.';
      } else if (widget.existing.any((s) =>
          s.id != widget.initial?.id && s.environmentId == _environmentId && s.name.toLowerCase() == t.toLowerCase())) {
        e.errorName = _envName != null ? 'Already exists in $_envName.' : 'Already exists in General.';
      }
      seen.add(t.toLowerCase());
      if (e.value.text.isEmpty) e.errorValue = 'Enter the secret value.';
      if (e.errorName != null || e.errorValue != null) ok = false;
    }
    setState(() {});
    return ok;
  }

  Future<void> _submit() async {
    if (_saving || !_validate()) return;
    setState(() {
      _saving = true;
      _error = null;
    });
    final api = SecwetScope.read(context).api;
    try {
      for (final e in _entries) {
        final note = e.note.text.trim();
        final draft = SecretDraft(
          itemId: widget.item.id,
          environmentId: _environmentId,
          name: e.name.text.trim(),
          kind: _kind,
          value: e.value.text,
          note: note.isEmpty ? null : note,
        );
        if (_editing) {
          await api.updateSecret(widget.initial!.id, draft);
        } else {
          await api.createSecret(draft);
        }
      }
      if (mounted) Navigator.of(context).pop(true);
    } catch (e) {
      if (mounted) {
        setState(() {
          _saving = false;
          _error = errorText(e, "Couldn't save. Try again.");
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    final multiple = _entries.length > 1;
    final title = _editing ? 'Edit ${widget.initial!.name}' : (multiple ? 'Add ${_entries.length} secrets' : 'Add secret');
    final submit = _saving
        ? 'Saving...'
        : _editing
            ? 'Save changes'
            : (multiple ? 'Save ${_entries.length} secrets' : 'Save secret');
    return SecwetDialog(
      title: title,
      description: _envScoped
          ? 'Saved to ${widget.item.name} (${_envName ?? 'Environment'}). The values are encrypted on this device before storage.'
          : 'Saved as general secrets to ${widget.item.name}. The values are encrypted on this device before storage.',
      actions: [
        SecwetButton(label: 'Cancel', variant: ButtonVariant.secondary, onPressed: _saving ? null : () => Navigator.of(context).pop(false)),
        SecwetButton(label: submit, onPressed: _saving ? null : _submit),
      ],
      children: [
        ChoiceField<SecretKind>(
          label: 'Type',
          value: _kind,
          choices: [for (final k in _typeSelectOrder) Choice(k, k.label)],
          onChanged: (k) => setState(() => _kind = k),
        ),
        if (_envScoped)
          ChoiceField<String?>(
            label: 'Environment',
            value: _environmentId,
            choices: [for (final e in widget.environments) Choice(e.id, e.name)],
            onChanged: (v) => setState(() => _environmentId = v),
          ),
        if (_pastedNotice != null)
          Row(
            children: [
              SecwetIcon(SecwetIcons.check, size: 14, color: p.success),
              const SizedBox(width: SecwetSpace.s2),
              Expanded(child: Text(_pastedNotice!, style: SecwetText.sm(p, color: p.success))),
            ],
          ),
        for (final (i, e) in _entries.indexed)
          Container(
            padding: EdgeInsets.only(top: multiple && i > 0 ? SecwetSpace.s4 : 0),
            decoration: multiple && i > 0
                ? BoxDecoration(border: Border(top: BorderSide(color: p.borderSeparator)))
                : null,
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                if (multiple)
                  Row(
                    children: [
                      SecwetBadge('#${i + 1}'),
                      const Spacer(),
                      SecwetIconButton(
                        icon: SecwetIcons.trash,
                        label: 'Remove secret from batch',
                        small: true,
                        onPressed: () => setState(() => _entries.removeAt(i).dispose()),
                      ),
                    ],
                  ),
                SecwetField(
                  label: 'Name',
                  controller: e.name,
                  hint: 'DATABASE_URL',
                  error: e.errorName,
                  onDialog: true,
                  autofocus: i == 0 && !_editing,
                  autocorrect: false,
                  onChanged: (v) {
                    if (e.errorName != null) setState(() => e.errorName = null);
                    _maybePaste(e, v, isName: true);
                  },
                ),
                const SizedBox(height: SecwetSpace.s3),
                SecwetField(
                  label: 'Value',
                  controller: e.value,
                  hint: 'postgres://user:password@host:5432/db',
                  error: e.errorValue,
                  onDialog: true,
                  multiline: true,
                  autocorrect: false,
                  onChanged: (v) {
                    if (e.errorValue != null) setState(() => e.errorValue = null);
                    _maybePaste(e, v, isName: false);
                  },
                ),
                const SizedBox(height: SecwetSpace.s3),
                SecwetField(
                  label: 'Note',
                  controller: e.note,
                  hint: 'Rotates every 90 days',
                  help: 'Optional. Encrypted with the secret.',
                  onDialog: true,
                ),
              ],
            ),
          ),
        if (!_editing)
          Wrap(
            spacing: SecwetSpace.s3,
            runSpacing: SecwetSpace.s2,
            crossAxisAlignment: WrapCrossAlignment.center,
            children: [
              SecwetButton(
                label: 'Add another',
                icon: SecwetIcons.plus,
                variant: ButtonVariant.secondary,
                onPressed: () => setState(() => _entries.add(_Entry())),
              ),
              Text('Tip: Paste .env, JSON, or key=value pairs to auto-fill', style: SecwetText.sm(p)),
            ],
          ),
        if (_error != null) Text(_error!, style: SecwetText.sm(p, color: p.danger)),
      ],
    );
  }
}

/// Copies a secret into another environment of the same item (desktop CopySecretDialog).
Future<String?> showCopySecretDialog(
  BuildContext context, {
  required SecretMeta secret,
  required List<Environment> environments,
  required List<SecretMeta> existing,
}) =>
    showSecwetDialog<String>(
      context,
      builder: (_) => _CopySecretDialog(secret: secret, environments: environments, existing: existing),
    );

class _CopySecretDialog extends StatefulWidget {
  const _CopySecretDialog({required this.secret, required this.environments, required this.existing});

  final SecretMeta secret;
  final List<Environment> environments;
  final List<SecretMeta> existing;

  @override
  State<_CopySecretDialog> createState() => _CopySecretDialogState();
}

class _CopySecretDialogState extends State<_CopySecretDialog> {
  late final _targets = [for (final e in widget.environments) if (e.id != widget.secret.environmentId) e];
  late String? _target = _targets.isEmpty ? null : _targets.first.id;
  String? _error;
  bool _busy = false;

  Future<void> _submit() async {
    final env = _targets.where((t) => t.id == _target).firstOrNull;
    if (env == null) return;
    if (widget.existing.any((s) => s.environmentId == env.id && s.name == widget.secret.name)) {
      return setState(() => _error = '${widget.secret.name} already exists in ${env.name}. Edit that one instead, or delete it first.');
    }
    setState(() => _busy = true);
    try {
      await SecwetScope.read(context).api.copySecretToEnvironment(widget.secret.id, env.id);
      if (mounted) Navigator.of(context).pop(env.id);
    } catch (e) {
      if (mounted) {
        setState(() {
          _busy = false;
          _error = errorText(e, "Couldn't copy this secret.");
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return SecwetDialog(
      title: 'Copy ${widget.secret.name}',
      description: "Creates a separate copy with the same name, type, value and note. Later edits to one don't change the other.",
      actions: [
        SecwetButton(label: 'Cancel', variant: ButtonVariant.secondary, onPressed: () => Navigator.of(context).pop()),
        SecwetButton(label: 'Copy secret', onPressed: _busy || _target == null ? null : _submit),
      ],
      children: [
        ChoiceField<String?>(
          label: 'Copy to',
          value: _target,
          error: _error,
          choices: [for (final e in _targets) Choice(e.id, e.name)],
          onChanged: (v) => setState(() {
            _target = v;
            _error = null;
          }),
        ),
      ],
    );
  }
}

/// CLI commands and code snippets for reading a secret (desktop SecretUsageDialog),
/// with the running process when the CLI injected it.
Future<void> showSecretUsage(
  BuildContext context, {
  required SecretMeta secret,
  ActiveSession? session,
  String? itemName,
  String? environmentName,
}) =>
    showSecwetDialog<void>(
      context,
      builder: (_) => _SecretUsage(secret: secret, session: session, itemName: itemName, environmentName: environmentName),
    );

class _SecretUsage extends StatefulWidget {
  const _SecretUsage({required this.secret, this.session, this.itemName, this.environmentName});

  final SecretMeta secret;
  final ActiveSession? session;
  final String? itemName;
  final String? environmentName;

  @override
  State<_SecretUsage> createState() => _SecretUsageState();
}

class _SecretUsageState extends State<_SecretUsage> {
  bool _stopping = false;
  bool _stopped = false;

  Future<void> _stop() async {
    setState(() => _stopping = true);
    try {
      await SecwetScope.read(context).api.stopActiveSession(widget.session!.sessionId);
      if (mounted) setState(() => _stopped = true);
    } catch (e) {
      if (mounted) showError(context, e, "Couldn't stop the process.");
    } finally {
      if (mounted) setState(() => _stopping = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    final name = widget.secret.name;
    final item = widget.itemName != null ? ' -i "${widget.itemName}"' : '';
    final env = widget.environmentName != null ? ' -e "${widget.environmentName}"' : '';
    final session = _stopped ? null : widget.session;
    Widget section(String title, List<Widget> rows) => Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(title, style: SecwetText.md(p, weight: FontWeight.w600)),
            for (final r in rows) ...[const SizedBox(height: SecwetSpace.s3), r],
          ],
        );
    return SecwetDialog(
      title: 'Usage: $name',
      description: 'Commands and language code snippets for reading and injecting this secret.',
      actions: [SecwetButton(label: 'Close', variant: ButtonVariant.secondary, onPressed: () => Navigator.of(context).pop())],
      children: [
        PillRow(
          children: [
            SecwetBadge(widget.secret.kind.label),
            SecwetBadge(widget.environmentName ?? 'General', tone: BadgeTone.accent),
            if (widget.itemName != null) SecwetBadge(widget.itemName!),
            if (session != null) const SecwetBadge('In use', tone: BadgeTone.success),
          ],
        ),
        if (session != null)
          SecwetCard(
            children: [
              ListRow(
                title: 'Running Process Session',
                meta: 'Command: ${session.command} • PID: ${session.pid}',
                below: Align(
                  alignment: Alignment.centerLeft,
                  child: SecwetButton(
                    label: _stopping ? 'Stopping...' : 'Stop process',
                    icon: SecwetIcons.stop,
                    variant: ButtonVariant.danger,
                    small: true,
                    onPressed: _stopping ? null : _stop,
                  ),
                ),
              ),
            ],
          ),
        section('Terminal & CLI', [
          _Snippet(label: 'Print secret value to stdout', code: 'secwet get $name$item$env', badge: 'CLI'),
          _Snippet(label: 'Run application with injected secrets', code: 'secwet run$item$env -- <your-command>', badge: 'CLI'),
        ]),
        section('Application Code', [
          _Snippet(label: 'Node.js / TypeScript', code: 'process.env.$name', badge: 'Node.js'),
          _Snippet(label: 'Python', code: 'import os\n${name.toLowerCase()} = os.environ.get("$name")', badge: 'Python'),
          _Snippet(label: 'Go', code: 'os.Getenv("$name")', badge: 'Go'),
          _Snippet(label: 'Rust', code: 'std::env::var("$name")', badge: 'Rust'),
          _Snippet(label: 'Shell / Bash', code: '"\$$name"', badge: 'Bash'),
        ]),
      ],
    );
  }
}

class _Snippet extends StatefulWidget {
  const _Snippet({required this.label, required this.code, required this.badge});

  final String label;
  final String code;
  final String badge;

  @override
  State<_Snippet> createState() => _SnippetState();
}

class _SnippetState extends State<_Snippet> {
  bool _copied = false;
  Timer? _reset;

  @override
  void dispose() {
    _reset?.cancel();
    super.dispose();
  }

  Future<void> _copy() async {
    try {
      await SecwetScope.read(context).api.copyText(widget.code);
      if (!mounted) return;
      setState(() => _copied = true);
      _reset?.cancel();
      _reset = Timer(const Duration(seconds: 2), () {
        if (mounted) setState(() => _copied = false);
      });
    } catch (e) {
      if (mounted) showError(context, e, "Couldn't copy.");
    }
  }

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Row(
          children: [
            Expanded(child: Text(widget.label, style: SecwetText.sm(p, color: p.textSecondary))),
            SecwetBadge(widget.badge),
          ],
        ),
        const SizedBox(height: SecwetSpace.s1),
        Container(
          padding: const EdgeInsets.only(left: SecwetSpace.s3),
          decoration: BoxDecoration(
            color: p.surfaceSunken,
            border: Border.all(color: p.border),
            borderRadius: BorderRadius.circular(SecwetRadius.control),
          ),
          child: Row(
            children: [
              Expanded(
                child: Padding(
                  padding: const EdgeInsets.symmetric(vertical: SecwetSpace.s2),
                  child: Text(widget.code, style: SecwetText.md(p)),
                ),
              ),
              SecwetIconButton(
                icon: _copied ? SecwetIcons.check : SecwetIcons.copy,
                label: _copied ? 'Copied' : 'Copy ${widget.label}',
                color: _copied ? p.success : null,
                onPressed: _copy,
              ),
            ],
          ),
        ),
      ],
    );
  }
}
