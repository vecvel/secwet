import 'package:flutter/widgets.dart';

import '../theme/secwet_theme.dart';
import '../theme/secwet_tokens.dart';
import 'icon.dart';

/// Tap target with no hover, focus, press or ripple styling (docs/ui-rules.md).
class Tappable extends StatelessWidget {
  const Tappable({super.key, required this.child, this.onTap, this.label, this.button = true, this.selected});

  final Widget child;
  final VoidCallback? onTap;
  final String? label;
  final bool button;
  final bool? selected;

  @override
  Widget build(BuildContext context) {
    return Semantics(
      button: button,
      enabled: onTap != null,
      selected: selected,
      label: label,
      child: GestureDetector(behavior: HitTestBehavior.opaque, onTap: onTap, child: child),
    );
  }
}

/// Gives a smaller control a tap area of at least 44 x 44 (the approved touch
/// target, like the desktop's coarse-pointer min-height). The control keeps
/// its own size and sits centered in the area.
class TouchTarget extends StatelessWidget {
  const TouchTarget({super.key, required this.child});

  final Widget child;

  @override
  Widget build(BuildContext context) => ConstrainedBox(
        constraints: const BoxConstraints(minWidth: SecwetControl.touchTarget, minHeight: SecwetControl.touchTarget),
        child: Align(widthFactor: 1, heightFactor: 1, child: child),
      );
}

/// 24 px moss tile holding an icon or an initial; filled when selected. The
/// same size in every layout. [solidBase] paints the tint over the page
/// background so content scrolling behind the bottom bar never shows through.
class IconTile extends StatelessWidget {
  const IconTile({super.key, this.icon, this.initial, this.selected = false, this.solidBase = false});

  final SecwetIcons? icon;
  final String? initial;
  final bool selected;
  final bool solidBase;

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    final fg = selected ? p.onAccentFill : p.accent;
    final tile = Color.alphaBlend(p.accentTint, solidBase ? p.bg : const Color(0x00000000));
    return Container(
      width: 24,
      height: 24,
      alignment: Alignment.center,
      decoration: BoxDecoration(
        color: selected ? p.accentFill : (solidBase ? tile : p.accentTint),
        borderRadius: BorderRadius.circular(SecwetRadius.small),
      ),
      child: initial != null
          ? Text(
              initial!.characters.take(1).toString().toUpperCase(),
              style: TextStyle(fontSize: SecwetFontSize.sm, fontWeight: FontWeight.w600, height: 1, color: fg),
            )
          : icon != null
              ? SecwetIcon(icon!, size: 16, color: fg)
              : null,
    );
  }
}

enum ButtonVariant { primary, secondary, tertiary, danger }

/// Desktop Button: primary is deep moss with light text in both themes,
/// danger deep red, secondary a quiet tinted fill, tertiary accent text.
/// 44 px tall (touch), or 32 px when [small] with a 44 px tap area.
class SecwetButton extends StatelessWidget {
  const SecwetButton({
    super.key,
    required this.label,
    this.onPressed,
    this.icon,
    this.variant = ButtonVariant.primary,
    this.small = false,
    this.expand = false,
  });

  final String label;
  final VoidCallback? onPressed;
  final SecwetIcons? icon;
  final ButtonVariant variant;
  final bool small;
  final bool expand;

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    final (Color? bg, Color fg, Border? border) = switch (variant) {
      ButtonVariant.primary => (p.accentFill, p.onAccentFill, null),
      ButtonVariant.danger => (p.dangerFill, p.onDangerFill, null),
      ButtonVariant.secondary => (
          p.textPrimary.withValues(alpha: 0.05),
          p.textPrimary,
          Border.all(color: p.textPrimary.withValues(alpha: 0.04)),
        ),
      ButtonVariant.tertiary => (null, p.accent, null),
    };
    final content = Row(
      mainAxisSize: expand ? MainAxisSize.max : MainAxisSize.min,
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        if (icon != null) ...[SecwetIcon(icon!, size: 16, color: fg), const SizedBox(width: SecwetSpace.s2)],
        Flexible(
          child: Text(
            label,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: TextStyle(fontSize: SecwetFontSize.md, fontWeight: FontWeight.w600, color: fg, height: 1.2),
          ),
        ),
      ],
    );
    return Opacity(
      opacity: onPressed == null ? 0.5 : 1,
      child: Tappable(
        onTap: onPressed,
        label: label,
        child: TouchTarget(
          child: Container(
            height: small ? SecwetControl.height : SecwetControl.touchTarget,
            padding: EdgeInsets.symmetric(horizontal: variant == ButtonVariant.tertiary ? SecwetSpace.s1 : SecwetSpace.s3),
            decoration: BoxDecoration(
              color: bg,
              border: border,
              borderRadius: BorderRadius.circular(SecwetRadius.control),
            ),
            child: content,
          ),
        ),
      ),
    );
  }
}

/// Square icon-only button: 44 px (touch), or 32 px when [small] with a
/// 44 px tap area.
class SecwetIconButton extends StatelessWidget {
  const SecwetIconButton({
    super.key,
    required this.icon,
    required this.label,
    this.onPressed,
    this.small = false,
    this.color,
    this.filled = false,
  });

  final SecwetIcons icon;
  final String label;
  final VoidCallback? onPressed;
  final bool small;
  final Color? color;

  /// Deep moss fill, like the desktop's primary icon button.
  final bool filled;

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    final size = small ? SecwetControl.height : SecwetControl.touchTarget;
    return Opacity(
      opacity: onPressed == null ? 0.5 : 1,
      child: Tappable(
        onTap: onPressed,
        label: label,
        child: TouchTarget(
          child: Container(
            width: size,
            height: size,
            alignment: Alignment.center,
            decoration: filled
                ? BoxDecoration(color: p.accentFill, borderRadius: BorderRadius.circular(SecwetRadius.control))
                : null,
            child: SecwetIcon(icon, size: 16, color: filled ? p.onAccentFill : (color ?? p.textSecondary)),
          ),
        ),
      ),
    );
  }
}

enum BadgeTone { neutral, accent, success, warning, danger }

/// Desktop Badge: outlined pill, 22 px, with a status dot in its tone.
class SecwetBadge extends StatelessWidget {
  const SecwetBadge(this.label, {super.key, this.tone = BadgeTone.neutral, this.dot});

  final String label;
  final BadgeTone tone;

  /// Defaults like desktop Badge.tsx: on for every tone but neutral.
  final bool? dot;

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    final dotColor = switch (tone) {
      BadgeTone.neutral => p.textTertiary,
      BadgeTone.accent => p.accent,
      BadgeTone.success => p.success,
      BadgeTone.warning => p.warning,
      BadgeTone.danger => p.danger,
    };
    return Container(
      height: 22,
      padding: const EdgeInsets.symmetric(horizontal: SecwetSpace.s2),
      decoration: BoxDecoration(
        color: p.bg,
        border: Border.all(color: p.borderStrong),
        borderRadius: BorderRadius.circular(SecwetRadius.pill),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          if (dot ?? tone != BadgeTone.neutral) ...[
            Container(width: 6, height: 6, decoration: BoxDecoration(color: dotColor, shape: BoxShape.circle)),
            const SizedBox(width: 6),
          ],
          Text(label, style: SecwetText.xs(p, color: p.textSecondary).copyWith(height: 1.2)),
        ],
      ),
    );
  }
}

/// One tab of [SegmentedTabs].
class TabSpec<T> {
  const TabSpec(this.value, this.label, {this.count});

  final T value;
  final String label;
  final int? count;
}

/// Desktop SegmentedTabs: underline tabs with count pills on one separator
/// line; wide rows scroll sideways. Selection changes color only.
class SegmentedTabs<T> extends StatelessWidget {
  const SegmentedTabs({super.key, required this.tabs, required this.selected, required this.onChanged, this.trailing});

  final List<TabSpec<T>> tabs;
  final T selected;
  final ValueChanged<T> onChanged;
  final Widget? trailing;

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    return Container(
      decoration: BoxDecoration(border: Border(bottom: BorderSide(color: p.borderSeparator))),
      child: Row(
        children: [
          Expanded(
            child: SingleChildScrollView(
              scrollDirection: Axis.horizontal,
              child: Row(
                children: [
                  for (final (i, tab) in tabs.indexed) ...[
                    if (i > 0) const SizedBox(width: SecwetSpace.s5),
                    _Tab(tab: tab, selected: tab.value == selected, onTap: () => onChanged(tab.value)),
                  ],
                ],
              ),
            ),
          ),
          if (trailing != null) ...[const SizedBox(width: SecwetSpace.s2), trailing!],
        ],
      ),
    );
  }
}

class _Tab<T> extends StatelessWidget {
  const _Tab({required this.tab, required this.selected, required this.onTap});

  final TabSpec<T> tab;
  final bool selected;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    return Tappable(
      onTap: onTap,
      selected: selected,
      label: tab.label,
      child: Container(
        height: SecwetControl.touchTarget,
        decoration: BoxDecoration(
          border: Border(
            bottom: BorderSide(
              width: 2,
              color: selected ? p.accent.withValues(alpha: p.accent.a * 0.65) : const Color(0x00000000),
            ),
          ),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(tab.label, style: SecwetText.md(p, color: selected ? p.textPrimary : p.textSecondary)),
            if (tab.count != null) ...[
              const SizedBox(width: SecwetSpace.s2),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 6),
                decoration: BoxDecoration(
                  color: selected ? p.accentTintSoft : p.surface,
                  border: Border.all(color: selected ? p.accentTintSoft : p.border),
                  borderRadius: BorderRadius.circular(SecwetRadius.count),
                ),
                child: Text(
                  '${tab.count}',
                  style: TextStyle(
                    fontSize: SecwetFontSize.xs,
                    height: 16 / SecwetFontSize.xs,
                    color: selected ? p.accent : p.textTertiary,
                    fontFeatures: const [FontFeature.tabularFigures()],
                  ),
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }
}

/// Desktop Notice: quiet card with an optional badge and action.
class SecwetNotice extends StatelessWidget {
  const SecwetNotice({super.key, required this.text, this.badge, this.action});

  final String text;
  final Widget? badge;
  final Widget? action;

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.symmetric(horizontal: SecwetSpace.s4, vertical: SecwetSpace.s3),
      decoration: BoxDecoration(
        color: p.surface,
        border: Border.all(color: p.border),
        borderRadius: BorderRadius.circular(SecwetRadius.card),
      ),
      child: Wrap(
        spacing: SecwetSpace.s3,
        runSpacing: SecwetSpace.s2,
        crossAxisAlignment: WrapCrossAlignment.center,
        children: [
          ?badge,
          Text(text, style: SecwetText.md(p, color: p.textSecondary)),
          ?action,
        ],
      ),
    );
  }
}

/// Desktop EmptyState: 40 px outlined icon box, title, body, actions.
class EmptyState extends StatelessWidget {
  const EmptyState({super.key, required this.icon, required this.title, this.body, this.action});

  final SecwetIcons icon;
  final String title;
  final String? body;
  final Widget? action;

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    return Padding(
      padding: const EdgeInsets.only(top: SecwetSpace.s2, bottom: SecwetSpace.s6),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(
            width: 40,
            height: 40,
            alignment: Alignment.center,
            decoration: BoxDecoration(
              color: p.surface,
              border: Border.all(color: p.borderStrong),
              borderRadius: BorderRadius.circular(SecwetRadius.control),
            ),
            child: SecwetIcon(icon, size: 20, color: p.textTertiary),
          ),
          const SizedBox(height: SecwetSpace.s4),
          Text(title, style: SecwetText.title(p)),
          if (body != null) ...[
            const SizedBox(height: SecwetSpace.s2),
            Text(body!, style: SecwetText.body(p).copyWith(color: p.textSecondary)),
          ],
          if (action != null) ...[const SizedBox(height: SecwetSpace.s4), action!],
        ],
      ),
    );
  }
}
