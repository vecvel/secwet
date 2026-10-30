import 'package:flutter/services.dart' show PlatformException;
import 'package:flutter/widgets.dart';

import '../../app/secwet_scope.dart';
import '../../core/secwet_api.dart';
import '../../theme/secwet_theme.dart';
import '../../theme/secwet_tokens.dart';
import '../../widgets/controls.dart';
import '../../widgets/icon.dart';
import '../../widgets/layout.dart';
import '../../widgets/overlays.dart';
import 'settings_screen.dart';
import 'settings_widgets.dart';

/// Settings > Recovery: the recovery key, the encrypted export (handed to
/// the system save sheet) and how restoring works.
class RecoveryTab extends StatelessWidget {
  const RecoveryTab({super.key, required this.model});

  final SettingsModel model;

  Future<void> _createKey(BuildContext context, bool replacing) async {
    if (replacing) {
      final ok = await showConfirmDialog(
        context,
        title: 'Replace recovery key?',
        message: 'The current recovery key stops working, including for exports made with it. '
            'A new key is shown once.',
        confirmLabel: 'Replace key',
      );
      if (!ok || !context.mounted) return;
    }
    await showSecwetDialog<void>(
      context,
      dismissible: false,
      builder: (_) => RecoveryKeySheet(api: SecwetScope.read(context).api, replacing: replacing),
    );
    await model.load();
  }

  @override
  Widget build(BuildContext context) {
    final recovery = model.recovery;
    final created = recovery?.created ?? false;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const SectionLabel('Recovery'),
        SecwetCard(
          children: [
            SettingRow(
              title: 'Recovery key',
              badges: [
                created
                    ? const SecwetBadge('Created', tone: BadgeTone.success)
                    : const SecwetBadge('Not created', tone: BadgeTone.warning),
              ],
              meta: created
                  ? '${recovery?.createdAt != null ? 'Created ${formatDate(recovery!.createdAt!)}. ' : ''}'
                      'Keep it safe and separate from this phone.'
                  : 'Without a recovery key, losing all approved devices means losing access to Secwet forever.',
              trailing: SecwetButton(
                label: created ? 'Replace' : 'Create',
                variant: created ? ButtonVariant.secondary : ButtonVariant.primary,
                onPressed: () => _createKey(context, created),
              ),
            ),
            SettingRow(
              title: 'Encrypted export',
              meta: created
                  ? 'Full encrypted backup of every item, secret, note and file, saved where you choose.'
                  : 'Create a recovery key first. The backup is encrypted with your recovery key.',
              trailing: SecwetButton(
                label: created ? 'Export data' : 'Create key first',
                variant: ButtonVariant.secondary,
                onPressed: created
                    ? () => showSecwetDialog<void>(context, builder: (_) => const ExportSheet())
                    : () => _createKey(context, false),
              ),
            ),
            const SettingRow(
              title: 'Restore from a backup',
              meta: 'Restoring opens a .secwet export with its recovery key. Choose Restore from backup when you set up '
                  'Secwet on a phone; it does not overwrite a Secwet that is already here.',
            ),
          ],
        ),
        const BulletCard(
          title: 'What recovery cannot do',
          lines: [
            'Secwet servers never hold your encryption key; there is no account reset or cloud password recovery.',
            'Revoking a device or rotating the key cannot erase secrets a device already copied locally.',
            'Ending a Pro subscription never deletes or locks your local data. Backups and exports remain accessible on every plan.',
          ],
        ),
      ],
    );
  }
}

/// Creates (or replaces) the recovery key and shows it once. The key is
/// copied only through the auto-clearing clipboard and never stored.
class RecoveryKeySheet extends StatefulWidget {
  const RecoveryKeySheet({super.key, required this.api, required this.replacing});

  final SecwetApi api;
  final bool replacing;

  @override
  State<RecoveryKeySheet> createState() => _RecoveryKeySheetState();
}

class _RecoveryKeySheetState extends State<RecoveryKeySheet> {
  String? _key;
  String? _error;
  bool _stored = false;
  bool _copied = false;

  @override
  void initState() {
    super.initState();
    _derive();
  }

  @override
  void dispose() {
    _key = null;
    super.dispose();
  }

  Future<void> _derive() async {
    try {
      final key = widget.replacing ? await widget.api.replaceRecoveryKey() : await widget.api.createRecoveryKey();
      if (mounted) setState(() => _key = key);
    } on SecwetException catch (e) {
      if (mounted) setState(() => _error = e.message.isEmpty ? "Couldn't create the recovery key." : e.message);
    }
  }

  Future<void> _copy() async {
    final key = _key;
    if (key == null) return;
    try {
      await widget.api.copyText(key);
      if (mounted) setState(() => _copied = true);
    } on SecwetException catch (e) {
      if (mounted) setState(() => _error = e.message);
    }
  }

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    final key = _key;
    return SecwetDialog(
      title: widget.replacing ? 'Replace recovery key' : 'Create recovery key',
      description: "Store this somewhere safe, away from this phone: a password manager or on paper. Secwet can't show it again.",
      actions: [
        SecwetButton(
          label: 'Done',
          onPressed: _stored && key != null || _error != null && key == null ? () => Navigator.of(context).pop() : null,
        ),
      ],
      children: [
        if (_error != null) SecwetNotice(text: _error!, badge: const SecwetBadge('Recovery key', tone: BadgeTone.warning)),
        if (key == null && _error == null) Text('Creating the recovery key…', style: SecwetText.sm(p)),
        if (key != null) ...[
          Container(
            padding: const EdgeInsets.all(SecwetSpace.s4),
            decoration: BoxDecoration(
              color: p.surfaceSunken,
              border: Border.all(color: p.border),
              borderRadius: BorderRadius.circular(SecwetRadius.card),
            ),
            child: Row(
              children: [
                Expanded(
                  // Whole 5-character groups only: a narrow line breaks
                  // after a hyphen, never inside a group.
                  child: Semantics(
                    label: key,
                    excludeSemantics: true,
                    child: Wrap(
                      children: [
                        for (final (i, group) in key.split('-').indexed)
                          Text(
                            i < key.split('-').length - 1 ? '$group-' : group,
                            softWrap: false,
                            style: TextStyle(fontSize: SecwetFontSize.lg, fontWeight: FontWeight.w500, height: 1.4, color: p.textPrimary),
                          ),
                      ],
                    ),
                  ),
                ),
                SecwetIconButton(
                  icon: _copied ? SecwetIcons.check : SecwetIcons.copy,
                  label: _copied ? 'Copied' : 'Copy recovery key',
                  onPressed: _copy,
                ),
              ],
            ),
          ),
          if (_copied) Text('Copied. Clears in 30 seconds.', style: SecwetText.sm(p)),
          Tappable(
            label: 'I have stored my recovery key',
            selected: _stored,
            onTap: () => setState(() => _stored = !_stored),
            child: SizedBox(
              height: SecwetControl.touchTarget,
              child: Row(
                children: [
                  CheckBox(checked: _stored),
                  const SizedBox(width: SecwetSpace.s3),
                  Expanded(child: Text('I have stored my recovery key', style: SecwetText.md(p))),
                ],
              ),
            ),
          ),
        ],
      ],
    );
  }
}

/// A square check box drawn with the app's tokens (no Material).
class CheckBox extends StatelessWidget {
  const CheckBox({super.key, required this.checked});

  final bool checked;

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    return Container(
      width: 18,
      height: 18,
      alignment: Alignment.center,
      decoration: BoxDecoration(
        color: checked ? p.accentFill : InputSurface.background(context),
        border: Border.all(color: checked ? p.accentFill : p.borderStrong),
        borderRadius: BorderRadius.circular(5),
      ),
      child: checked ? SecwetIcon(SecwetIcons.check, size: 14, color: p.onAccentFill) : null,
    );
  }
}

/// Encrypted export: written to the app's private folder with the recovery
/// key, then handed to the system save sheet (Files on iOS, the storage
/// picker on Android); the private copy is deleted afterwards.
class ExportSheet extends StatefulWidget {
  const ExportSheet({super.key});

  @override
  State<ExportSheet> createState() => _ExportSheetState();
}

class _ExportSheetState extends State<ExportSheet> {
  final _key = TextEditingController();
  bool _busy = false;
  String? _error;
  ExportSummary? _done;

  @override
  void dispose() {
    _key.clear();
    _key.dispose();
    super.dispose();
  }

  String _fileName() {
    final n = DateTime.now();
    String two(int v) => v.toString().padLeft(2, '0');
    return 'secwet-export-${n.year}${two(n.month)}${two(n.day)}.secwet';
  }

  Future<void> _export() async {
    final key = _key.text.trim();
    if (key.replaceAll('-', '').length < 25) {
      setState(() => _error = 'Enter your full 25-character recovery key.');
      return;
    }
    final scope = SecwetScope.read(context);
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final name = _fileName();
      final dir = await scope.api.platform.tempDirectory();
      final summary = await scope.api.exportWorkspace(path: '$dir/$name', recoveryKey: key);
      _key.clear();
      final saved = await scope.session.external(() => scope.api.platform.saveFile(summary.filePath, name));
      if (!mounted) return;
      if (saved) {
        setState(() => _done = summary);
      } else {
        setState(() => _error = 'The export was not saved.');
      }
    } on SecwetException catch (e) {
      if (mounted) setState(() => _error = e.message.isEmpty ? "Couldn't export. Check your recovery key and try again." : e.message);
    } on PlatformException catch (e) {
      if (mounted) setState(() => _error = e.message ?? "Couldn't save the export.");
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final done = _done;
    if (done != null) {
      return SecwetDialog(
        title: 'Encrypted export',
        actions: [SecwetButton(label: 'Done', onPressed: () => Navigator.of(context).pop())],
        children: [
          SecwetNotice(
            text: 'Saved ${plural(done.itemsCount, 'item')}, ${plural(done.secretsCount, 'secret')}, '
                '${plural(done.notesCount, 'note')} and ${plural(done.assetsCount, 'file')}.',
            badge: const SecwetBadge('Export complete', tone: BadgeTone.success),
          ),
        ],
      );
    }
    return SecwetDialog(
      title: 'Encrypted export',
      description: 'Create an encrypted backup (.secwet) sealed with your recovery key, then choose where to save it.',
      actions: [
        SecwetButton(label: 'Cancel', variant: ButtonVariant.secondary, onPressed: _busy ? null : () => Navigator.of(context).pop()),
        SecwetButton(label: _busy ? 'Exporting…' : 'Save export', onPressed: _busy ? null : _export),
      ],
      children: [
        SecwetCard(
          children: const [
            SettingRow(title: 'Includes', meta: 'Every space, group, item, secret, note and file.'),
            SettingRow(title: 'Encrypted with', meta: 'Your 25-character recovery key'),
            SettingRow(title: 'Readable by', meta: 'Anyone holding both the .secwet file and the recovery key'),
          ],
        ),
        SecwetField(
          label: 'Recovery key',
          help: 'Enter your recovery key to seal this archive.',
          hint: 'XXXXX-XXXXX-XXXXX-XXXXX-XXXXX',
          controller: _key,
          obscure: true,
          autocorrect: false,
          error: _error,
        ),
      ],
    );
  }
}
