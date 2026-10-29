import 'package:flutter/widgets.dart';

import '../../theme/secwet_theme.dart';
import '../../theme/secwet_tokens.dart';
import '../../widgets/controls.dart';
import '../../widgets/icon.dart';
import '../../widgets/layout.dart';
import '../../widgets/overlays.dart';

/// Settings list row: title with inline badges, a description that wraps,
/// and an action. Wide actions (fields, selects) sit below the text so the
/// text never squeezes on a narrow phone.
class SettingRow extends StatelessWidget {
  const SettingRow({
    super.key,
    required this.title,
    this.badges = const [],
    this.meta,
    this.trailing,
    this.below,
    this.muted = false,
  });

  final String title;
  final List<Widget> badges;
  final String? meta;

  /// A compact action (small button, badge) on the right.
  final Widget? trailing;

  /// A full-width control under the text.
  final Widget? below;

  /// Dimmed (revoked devices, expired invitations).
  final bool muted;

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    final text = Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      mainAxisSize: MainAxisSize.min,
      children: [
        Wrap(
          spacing: SecwetSpace.s2,
          runSpacing: SecwetSpace.s1,
          crossAxisAlignment: WrapCrossAlignment.center,
          children: [
            Text(title, style: SecwetText.md(p, weight: FontWeight.w500, color: muted ? p.textSecondary : null)),
            // A pill cannot wrap; on a narrow row it shrinks instead of overflowing.
            for (final b in badges) FittedBox(fit: BoxFit.scaleDown, alignment: Alignment.centerLeft, child: b),
          ],
        ),
        if (meta != null) ...[
          const SizedBox(height: 2),
          Text(meta!, style: SecwetText.sm(p)),
        ],
      ],
    );
    return ConstrainedBox(
      constraints: const BoxConstraints(minHeight: SecwetControl.touchTarget),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          mainAxisSize: MainAxisSize.min,
          children: [
            Row(
              children: [
                Expanded(child: text),
                if (trailing != null) ...[const SizedBox(width: SecwetSpace.s3), trailing!],
              ],
            ),
            if (below != null) ...[const SizedBox(height: SecwetSpace.s3), below!],
          ],
        ),
      ),
    );
  }
}

/// One option of a [SelectControl].
class SelectOption<T> {
  const SelectOption(this.value, this.label);

  final T value;
  final String label;
}

/// Desktop SelectControl on a phone: shows the current choice and opens the
/// menu with the options; the current one carries a check.
class SelectControl<T> extends StatelessWidget {
  const SelectControl({super.key, required this.label, required this.value, required this.options, this.onChanged});

  /// Accessible name ("Appearance").
  final String label;
  final T value;
  final List<SelectOption<T>> options;
  final ValueChanged<T>? onChanged;

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    final current = options.where((o) => o.value == value).firstOrNull?.label ?? '';
    return Builder(
      builder: (anchor) => Opacity(
        opacity: onChanged == null ? 0.5 : 1,
        child: TouchTarget(child: Tappable(
          label: '$label: $current',
          onTap: onChanged == null
              ? null
              : () => showSecwetMenu(anchor, [
                    for (final o in options)
                      MenuEntry(
                        o.label,
                        icon: o.value == value ? SecwetIcons.check : SecwetIcons.dot,
                        onSelected: () => onChanged!(o.value),
                      ),
                  ]),
          child: Container(
            height: MobileControl.height,
            padding: const EdgeInsets.symmetric(horizontal: SecwetSpace.s3),
            decoration: BoxDecoration(
              color: InputSurface.background(context),
              border: Border.all(color: p.borderStrong),
              borderRadius: BorderRadius.circular(SecwetRadius.control),
            ),
            child: Row(
              children: [
                Expanded(child: Text(current, maxLines: 1, overflow: TextOverflow.ellipsis, style: SecwetText.md(p))),
                SecwetIcon(SecwetIcons.chevronDown, size: 16, color: p.textTertiary),
              ],
            ),
          ),
        )),
      ),
    );
  }
}

/// One choice of [ChoiceCards].
class Choice<T> {
  const Choice({required this.value, required this.title, required this.description, this.hint});

  final T value;
  final String title;
  final String description;

  /// Short note next to the title ("Recommended").
  final String? hint;
}

/// Desktop ChoiceCards: stacked cards, one selected. Selection changes the
/// border and a light tint only, never the type.
class ChoiceCards<T> extends StatelessWidget {
  const ChoiceCards({super.key, required this.label, required this.value, required this.choices, this.onChanged});

  final String label;
  final T value;
  final List<Choice<T>> choices;
  final ValueChanged<T>? onChanged;

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    return Semantics(
      label: label,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          for (final (i, c) in choices.indexed) ...[
            if (i > 0) const SizedBox(height: SecwetSpace.s2),
            Tappable(
              label: c.title,
              selected: c.value == value,
              onTap: onChanged == null ? null : () => onChanged!(c.value),
              child: Container(
                padding: const EdgeInsets.all(SecwetSpace.s3),
                // Desktop ChoiceCards: the border never changes; the
                // selected card gets the soft tint.
                decoration: BoxDecoration(
                  color: c.value == value ? p.accentTintSoft : p.bg,
                  border: Border.all(color: p.border),
                  borderRadius: BorderRadius.circular(SecwetRadius.card),
                ),
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Padding(padding: const EdgeInsets.only(top: 1), child: _Radio(on: c.value == value)),
                    const SizedBox(width: SecwetSpace.s3),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(c.title, style: SecwetText.md(p, weight: FontWeight.w500)),
                          // A line, not a pill: hints are a few words and a pill cannot wrap on a phone.
                          if (c.hint != null) Text(c.hint!, style: SecwetText.xs(p, color: p.accent)),
                          const SizedBox(height: 2),
                          Text(c.description, style: SecwetText.sm(p)),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ],
        ],
      ),
    );
  }
}

class _Radio extends StatelessWidget {
  const _Radio({required this.on});

  final bool on;

  @override
  Widget build(BuildContext context) => desktopRadio(context, on: on);
}

/// Short facts as a bulleted list.
class BulletList extends StatelessWidget {
  const BulletList({super.key, required this.lines});

  final List<String> lines;

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        for (final l in lines)
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 3),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Padding(
                  padding: const EdgeInsets.only(top: 7, right: SecwetSpace.s2),
                  child: Container(width: 4, height: 4, decoration: BoxDecoration(color: p.textTertiary, shape: BoxShape.circle)),
                ),
                Expanded(child: Text(l, style: SecwetText.sm(p))),
              ],
            ),
          ),
      ],
    );
  }
}

/// Short facts under a section ("What the relay sees").
class BulletCard extends StatelessWidget {
  const BulletCard({super.key, required this.title, required this.lines});

  final String title;
  final List<String> lines;

  @override
  Widget build(BuildContext context) {
    return SecwetCard(
      title: title,
      padding: const EdgeInsets.fromLTRB(14, 10, 14, 10),
      children: [BulletList(lines: lines)],
    );
  }
}

/// A notice with its tone badge and a gap below, as the desktop stacks them.
class SettingsNotice extends StatelessWidget {
  const SettingsNotice({super.key, required this.label, required this.text, this.tone = BadgeTone.warning, this.action});

  final String label;
  final String text;
  final BadgeTone tone;
  final Widget? action;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: SecwetSpace.s3),
      child: SecwetNotice(text: text, badge: SecwetBadge(label, tone: tone, dot: true), action: action),
    );
  }
}

/// A text field that saves when editing ends (return key or focus leaves).
class SaveOnDoneField extends StatefulWidget {
  const SaveOnDoneField({super.key, required this.initial, required this.onSave, this.hint, this.keyboardType, this.enabled = true});

  final String initial;
  final ValueChanged<String> onSave;
  final String? hint;
  final TextInputType? keyboardType;
  final bool enabled;

  @override
  State<SaveOnDoneField> createState() => _SaveOnDoneFieldState();
}

class _SaveOnDoneFieldState extends State<SaveOnDoneField> {
  // Set in initState: a lazy `late` initializer would first run in
  // didUpdateWidget and read the new value instead of the first one.
  late final TextEditingController _controller;
  late String _saved;

  @override
  void initState() {
    super.initState();
    _controller = TextEditingController(text: widget.initial);
    _saved = widget.initial;
  }

  @override
  void didUpdateWidget(SaveOnDoneField old) {
    super.didUpdateWidget(old);
    if (widget.initial != old.initial && _controller.text == _saved) {
      _controller.text = widget.initial;
      _saved = widget.initial;
    }
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  void _save() {
    if (_controller.text == _saved) return;
    _saved = _controller.text;
    widget.onSave(_controller.text);
  }

  @override
  Widget build(BuildContext context) {
    return IgnorePointer(
      ignoring: !widget.enabled,
      child: Opacity(
        opacity: widget.enabled ? 1 : 0.5,
        child: Focus(
          onFocusChange: (focused) {
            if (!focused) _save();
          },
          child: SecwetField(
            controller: _controller,
            hint: widget.hint,
            keyboardType: widget.keyboardType,
            autocorrect: false,
            onSubmitted: (_) => _save(),
          ),
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Formatting (as on desktop)
// ---------------------------------------------------------------------------

/// The app layer reports some times in Unix seconds and some in ms.
DateTime timeFrom(int value) =>
    DateTime.fromMillisecondsSinceEpoch(value > 100000000000 ? value : value * 1000);

const _months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

/// "Oct 29".
String formatDate(int value) {
  final d = timeFrom(value);
  return '${_months[d.month - 1]} ${d.day}';
}

/// "Oct 29, 2026" from an RFC 3339 time (plan end), or null.
String? formatIsoDate(String? iso) {
  final d = iso == null ? null : DateTime.tryParse(iso)?.toLocal();
  return d == null ? null : '${_months[d.month - 1]} ${d.day}, ${d.year}';
}

/// "Just now", "5 min. ago", "3 hr. ago", "2 days ago".
String formatAgo(int value, {DateTime? now}) {
  final diff = (now ?? DateTime.now()).difference(timeFrom(value));
  if (diff.inDays >= 1) return diff.inDays == 1 ? 'Yesterday' : '${diff.inDays} days ago';
  if (diff.inHours >= 1) return '${diff.inHours} hr. ago';
  if (diff.inMinutes >= 1) return '${diff.inMinutes} min. ago';
  return 'Just now';
}

String plural(int count, String noun) => '$count $noun${count == 1 ? '' : 's'}';

/// "4:59".
String formatCountdown(Duration d) {
  final s = d.inSeconds < 0 ? 0 : d.inSeconds;
  return '${s ~/ 60}:${(s % 60).toString().padLeft(2, '0')}';
}
