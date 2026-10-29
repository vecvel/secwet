// Small pieces the Groups and Overview screens share: formatting helpers as
// in the desktop lib/format.ts, the one-field name dialog, a select field
// that opens a bottom sheet, and check and radio rows.
import 'package:flutter/widgets.dart';

import '../../core/secwet_api.dart';
import '../../theme/secwet_theme.dart';
import '../../theme/secwet_tokens.dart';
import '../../widgets/controls.dart';
import '../../widgets/icon.dart';
import '../../widgets/layout.dart';
import '../../widgets/overlays.dart';

String plural(int count, String noun) => '$count $noun${count == 1 ? '' : 's'}';

/// First letter or digit of [name], upper case, for initial tiles ("#" when none).
String initialOf(String name) {
  final m = RegExp(r'[A-Za-z0-9]').firstMatch(name);
  return m == null ? '#' : m.group(0)!.toUpperCase();
}

const _months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

/// "Oct 26", as the desktop formatDate.
String formatDate(DateTime d) => '${_months[d.month - 1]} ${d.day}';

/// Short relative time ("15 min. ago", "Just now"), as the desktop formatAgo
/// (Intl.RelativeTimeFormat, short style, numeric auto). [seconds] is Unix seconds.
String formatAgo(int seconds, {DateTime? now}) {
  final t = seconds > 100000000000 ? seconds : seconds * 1000;
  final diff = t - (now ?? DateTime.now()).millisecondsSinceEpoch;
  final abs = diff.abs();
  String fmt(int n, String unit, String yesterday, String tomorrow) {
    if (n == 1) return diff < 0 ? yesterday : tomorrow;
    return diff < 0 ? '$n $unit ago' : 'in $n $unit';
  }

  if (abs >= 86400000) return fmt((abs / 86400000).round(), 'days', 'yesterday', 'tomorrow');
  if (abs >= 3600000) {
    final n = (abs / 3600000).round();
    return diff < 0 ? '$n hr. ago' : 'in $n hr.';
  }
  if (abs >= 60000) {
    final n = (abs / 60000).round();
    return diff < 0 ? '$n min. ago' : 'in $n min.';
  }
  return 'Just now';
}

String formatBytes(int bytes) {
  if (bytes <= 0) return '0 Bytes';
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  var i = 0;
  var v = bytes.toDouble();
  while (v >= 1024 && i < sizes.length - 1) {
    v /= 1024;
    i++;
  }
  final s = v.toStringAsFixed(1);
  return '${s.endsWith('.0') ? s.substring(0, s.length - 2) : s} ${sizes[i]}';
}

/// The UI message of an app-layer error, or [fallback].
String errorText(Object e, String fallback) => e is SecwetException ? e.message : fallback;

/// Shows an error toast for a failed action.
void showError(BuildContext context, Object e, String fallback) {
  if (context.mounted) showToast(context, errorText(e, fallback), tone: BadgeTone.danger);
}

// ---------------------------------------------------------------------------
// Name dialog (desktop components/NameDialog.tsx)
// ---------------------------------------------------------------------------

/// One-field dialog for creating or renaming something. [validate] returns an
/// error message or null; [onSubmit] may throw, and its message shows on the field.
/// Resolves with the trimmed value, or null when cancelled.
Future<String?> showNameDialog(
  BuildContext context, {
  required String title,
  String? description,
  required String label,
  String initial = '',
  String? placeholder,
  required String confirmLabel,
  required String? Function(String value) validate,
  Future<void> Function(String value)? onSubmit,
}) =>
    showSecwetDialog<String>(
      context,
      builder: (_) => _NameDialog(
        title: title,
        description: description,
        label: label,
        initial: initial,
        placeholder: placeholder,
        confirmLabel: confirmLabel,
        validate: validate,
        onSubmit: onSubmit,
      ),
    );

class _NameDialog extends StatefulWidget {
  const _NameDialog({
    required this.title,
    this.description,
    required this.label,
    required this.initial,
    this.placeholder,
    required this.confirmLabel,
    required this.validate,
    this.onSubmit,
  });

  final String title;
  final String? description;
  final String label;
  final String initial;
  final String? placeholder;
  final String confirmLabel;
  final String? Function(String value) validate;
  final Future<void> Function(String value)? onSubmit;

  @override
  State<_NameDialog> createState() => _NameDialogState();
}

class _NameDialogState extends State<_NameDialog> {
  late final _value = TextEditingController(text: widget.initial);
  String? _error;
  bool _busy = false;

  @override
  void dispose() {
    _value.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    if (_busy) return;
    final err = widget.validate(_value.text);
    setState(() => _error = err);
    if (err != null) return;
    final v = _value.text.trim();
    if (widget.onSubmit != null) {
      setState(() => _busy = true);
      try {
        await widget.onSubmit!(v);
      } catch (e) {
        if (mounted) setState(() => _error = errorText(e, 'Something went wrong. Try again.'));
        return;
      } finally {
        if (mounted) setState(() => _busy = false);
      }
    }
    if (mounted) Navigator.of(context).pop(v);
  }

  @override
  Widget build(BuildContext context) {
    return SecwetDialog(
      title: widget.title,
      description: widget.description,
      actions: [
        SecwetButton(label: 'Cancel', variant: ButtonVariant.secondary, onPressed: () => Navigator.of(context).pop()),
        SecwetButton(label: widget.confirmLabel, onPressed: _busy ? null : _submit),
      ],
      children: [
        SecwetField(
          label: widget.label,
          controller: _value,
          hint: widget.placeholder,
          error: _error,
          onDialog: true,
          autofocus: true,
          autocorrect: false,
          onChanged: (_) {
            if (_error != null) setState(() => _error = null);
          },
          onSubmitted: (_) => _submit(),
        ),
      ],
    );
  }
}

// ---------------------------------------------------------------------------
// Select field
// ---------------------------------------------------------------------------

/// One option of a [ChoiceField].
class Choice<T> {
  const Choice(this.value, this.label, {this.icon});

  final T value;
  final String label;
  final SecwetIcons? icon;
}

/// Desktop SelectField: label and a 44 px control showing the current choice;
/// tapping it opens the options as a bottom sheet.
class ChoiceField<T> extends StatelessWidget {
  const ChoiceField({
    super.key,
    this.label,
    required this.value,
    required this.choices,
    required this.onChanged,
    this.error,
    this.onDialog = true,
  });

  final String? label;
  final T value;
  final List<Choice<T>> choices;
  final ValueChanged<T> onChanged;
  final String? error;
  final bool onDialog;

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    Choice<T>? current;
    for (final c in choices) {
      if (c.value == value) current = c;
    }
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      mainAxisSize: MainAxisSize.min,
      children: [
        if (label != null) ...[
          Text(label!, style: SecwetText.sm(p, color: p.textSecondary).copyWith(fontWeight: FontWeight.w500)),
          const SizedBox(height: SecwetSpace.s1),
        ],
        Tappable(
          label: label ?? current?.label,
          onTap: () async {
            final picked = await showSecwetDialog<Choice<T>>(
              context,
              builder: (ctx) => SecwetDialog(
                title: label ?? 'Choose',
                children: [
                  SecwetCard(
                    children: [
                      for (final c in choices)
                        ListRow(
                          title: c.label,
                          leading: c.icon == null ? null : IconTile(icon: c.icon, selected: c.value == value),
                          trailing: c.value == value ? SecwetIcon(SecwetIcons.check, size: 16, color: p.accent) : null,
                          onTap: () => Navigator.of(ctx).pop(c),
                        ),
                    ],
                  ),
                ],
              ),
            );
            if (picked != null) onChanged(picked.value);
          },
          child: Container(
            height: SecwetControl.touchTarget,
            padding: const EdgeInsets.symmetric(horizontal: SecwetSpace.s3),
            decoration: BoxDecoration(
              color: onDialog ? p.bg : p.surface,
              border: Border.all(color: error != null ? p.danger : p.borderStrong),
              borderRadius: BorderRadius.circular(SecwetRadius.control),
            ),
            child: Row(
              children: [
                if (current?.icon != null) ...[
                  SecwetIcon(current!.icon!, size: 16, color: p.textSecondary),
                  const SizedBox(width: SecwetSpace.s2),
                ],
                Expanded(
                  child: Text(current?.label ?? '', maxLines: 1, overflow: TextOverflow.ellipsis, style: SecwetText.md(p)),
                ),
                SecwetIcon(SecwetIcons.chevronDown, size: 16, color: p.textTertiary),
              ],
            ),
          ),
        ),
        if (error != null) ...[
          const SizedBox(height: SecwetSpace.s1),
          Text(error!, style: SecwetText.sm(p, color: p.danger)),
        ],
      ],
    );
  }
}

// ---------------------------------------------------------------------------
// Check and radio rows
// ---------------------------------------------------------------------------

/// Desktop Checkbox: an 18 px box (filled deep moss with a check when on) and its label.
class CheckRow extends StatelessWidget {
  const CheckRow({super.key, required this.label, required this.checked, required this.onChanged});

  final String label;
  final bool checked;
  final ValueChanged<bool> onChanged;

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    return Tappable(
      label: label,
      selected: checked,
      onTap: () => onChanged(!checked),
      child: SizedBox(
        height: SecwetControl.touchTarget,
        child: Row(
          children: [
            Container(
              width: 18,
              height: 18,
              alignment: Alignment.center,
              decoration: BoxDecoration(
                color: checked ? p.accentFill : p.bg,
                border: Border.all(color: checked ? p.accentFill : p.borderStrong.withValues(alpha: 0.3)),
                borderRadius: BorderRadius.circular(4),
              ),
              child: checked ? SecwetIcon(SecwetIcons.check, size: 14, color: p.onAccentFill) : null,
            ),
            const SizedBox(width: SecwetSpace.s2),
            Expanded(child: Text(label, style: SecwetText.md(p))),
          ],
        ),
      ),
    );
  }
}

/// A radio choice with its label (the environment delete options).
class RadioRow extends StatelessWidget {
  const RadioRow({super.key, required this.label, required this.selected, required this.onTap});

  final String label;
  final bool selected;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    return Tappable(
      label: label,
      selected: selected,
      onTap: onTap,
      child: ConstrainedBox(
        constraints: const BoxConstraints(minHeight: SecwetControl.touchTarget),
        child: Row(
          children: [
            Container(
              width: 18,
              height: 18,
              alignment: Alignment.center,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                color: p.bg,
                border: Border.all(color: selected ? p.accentFill : p.borderStrong.withValues(alpha: 0.3), width: selected ? 5 : 1),
              ),
            ),
            const SizedBox(width: SecwetSpace.s2),
            Expanded(child: Text(label, style: SecwetText.md(p))),
          ],
        ),
      ),
    );
  }
}

/// The read-only archive notice (desktop App.tsx banner).
class UnlinkedNotice extends StatelessWidget {
  const UnlinkedNotice({super.key});

  @override
  Widget build(BuildContext context) {
    return const Padding(
      padding: EdgeInsets.only(bottom: SecwetSpace.s3),
      child: SecwetNotice(
        badge: SecwetBadge('Unlinked', tone: BadgeTone.warning),
        text: 'This device was unlinked from Secwet. Sync is disabled. You can still view and export.',
      ),
    );
  }
}
