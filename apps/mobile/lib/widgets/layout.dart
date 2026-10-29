import 'package:flutter/material.dart' show InputBorder, InputDecoration, Material, MaterialType, TextField;
import 'package:flutter/widgets.dart';

import '../theme/secwet_theme.dart';
import '../theme/secwet_tokens.dart';
import 'controls.dart';
import 'icon.dart';

/// Card with an optional tinted header; rows inside are split by separators.
class SecwetCard extends StatelessWidget {
  const SecwetCard({super.key, this.title, this.headerTrailing, required this.children, this.padding});

  final String? title;
  final Widget? headerTrailing;
  final List<Widget> children;

  /// Padding around the children (for non-row content such as quick actions).
  final EdgeInsets? padding;

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    final rows = <Widget>[];
    for (final (i, child) in children.indexed) {
      if (i > 0 && padding == null) rows.add(Container(height: 1, color: p.borderSeparator));
      rows.add(child);
    }
    return Container(
      margin: const EdgeInsets.only(bottom: 14),
      decoration: BoxDecoration(
        color: p.surface,
        border: Border.all(color: p.border),
        borderRadius: BorderRadius.circular(SecwetRadius.card),
      ),
      clipBehavior: Clip.antiAlias,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          if (title != null)
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
              decoration: BoxDecoration(
                color: p.cardHeaderBg,
                border: Border(bottom: BorderSide(color: p.borderSeparator)),
              ),
              child: Row(
                children: [
                  Expanded(child: Text(title!, style: SecwetText.md(p, weight: FontWeight.w600))),
                  ?headerTrailing,
                ],
              ),
            ),
          if (padding != null) Padding(padding: padding!, child: Column(children: rows)) else ...rows,
        ],
      ),
    );
  }
}

/// List row: optional leading tile, title (with inline extras), one-line
/// meta, pills below, trailing widget. At least 44 px tall.
class ListRow extends StatelessWidget {
  const ListRow({
    super.key,
    required this.title,
    this.leading,
    this.titleExtra,
    this.meta,
    this.below,
    this.trailing,
    this.onTap,
    this.alignTop = false,
  });

  final String title;
  final Widget? leading;
  final Widget? titleExtra;
  final String? meta;
  final Widget? below;
  final Widget? trailing;
  final VoidCallback? onTap;
  final bool alignTop;

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    final row = ConstrainedBox(
      constraints: const BoxConstraints(minHeight: SecwetControl.touchTarget),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
        child: Row(
          crossAxisAlignment: alignTop ? CrossAxisAlignment.start : CrossAxisAlignment.center,
          children: [
            if (leading != null) ...[leading!, const SizedBox(width: SecwetSpace.s3)],
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                mainAxisSize: MainAxisSize.min,
                children: [
                  Row(
                    children: [
                      Flexible(
                        child: Text(
                          title,
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: SecwetText.md(p, weight: FontWeight.w500),
                        ),
                      ),
                      if (titleExtra != null) ...[const SizedBox(width: SecwetSpace.s2), titleExtra!],
                    ],
                  ),
                  if (meta != null)
                    Text(meta!, maxLines: 1, overflow: TextOverflow.ellipsis, style: SecwetText.sm(p)),
                  if (below != null) ...[const SizedBox(height: 6), below!],
                ],
              ),
            ),
            if (trailing != null) ...[const SizedBox(width: SecwetSpace.s3), trailing!],
          ],
        ),
      ),
    );
    return onTap == null ? row : Tappable(onTap: onTap, label: title, child: row);
  }
}

/// Wrapping row of pills (badges) under a list row title.
class PillRow extends StatelessWidget {
  const PillRow({super.key, required this.children});

  final List<Widget> children;

  @override
  Widget build(BuildContext context) => Wrap(spacing: 6, runSpacing: 6, children: children);
}

/// Overview statistic tile.
class StatTile extends StatelessWidget {
  const StatTile({super.key, required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
      decoration: BoxDecoration(
        color: p.surface,
        border: Border.all(color: p.border),
        borderRadius: BorderRadius.circular(SecwetRadius.card),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(label, style: SecwetText.sm(p)),
          Text(value, style: SecwetText.stat(p)),
        ],
      ),
    );
  }
}

/// Small dim section label with an optional action on the right.
class SectionLabel extends StatelessWidget {
  const SectionLabel(this.text, {super.key, this.trailing});

  final String text;
  final Widget? trailing;

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    return Padding(
      padding: const EdgeInsets.fromLTRB(2, 4, 2, 8),
      child: Row(
        children: [
          Expanded(child: Text(text, style: SecwetText.sm(p))),
          ?trailing,
        ],
      ),
    );
  }
}

/// A parent segment of a [TopBar] breadcrumb.
class Crumb {
  const Crumb(this.label, this.onTap);

  final String label;
  final VoidCallback onTap;
}

/// Screen top bar: the screen's title with its actions on the same row.
/// 52 px tall. A pushed screen leads with its parents as a breadcrumb
/// ("Projects · Payments API", as the desktop header and the approved
/// preview); each parent is a 44 px tap target that goes back to it. Never a
/// logo, wordmark, status badge or helper text (docs/design-decisions.md,
/// "Mobile unlock and header").
class TopBar extends StatelessWidget {
  const TopBar({super.key, required this.title, this.actions = const [], this.large = false, this.crumbs = const []});

  final String title;
  final List<Widget> actions;

  /// The page-title style (20 px, semibold) of the Overview and Groups tab
  /// roots; pushed screens and Settings keep the smaller title.
  final bool large;

  /// Parents of this screen, outermost first.
  final List<Crumb> crumbs;

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    final style = large ? SecwetText.pageTitle(p) : SecwetText.md(p, color: p.textPrimary, weight: FontWeight.w500);
    Widget dot() => Padding(
          padding: const EdgeInsets.symmetric(horizontal: SecwetSpace.s2),
          child: Container(
            width: 3,
            height: 3,
            decoration: BoxDecoration(color: p.textTertiary.withValues(alpha: 0.6), shape: BoxShape.circle),
          ),
        );
    return SizedBox(
      height: 52,
      child: Row(
        children: [
          for (final c in crumbs) ...[
            Flexible(
              child: Tappable(
                label: 'Back to ${c.label}',
                onTap: c.onTap,
                child: Container(
                  height: SecwetControl.touchTarget,
                  alignment: Alignment.centerLeft,
                  child: Text(c.label, maxLines: 1, overflow: TextOverflow.ellipsis, style: style.copyWith(color: p.textTertiary)),
                ),
              ),
            ),
            dot(),
          ],
          Expanded(
            flex: crumbs.isEmpty ? 1 : 2,
            child: Text(title, maxLines: 1, overflow: TextOverflow.ellipsis, style: style),
          ),
          for (final a in actions) ...[const SizedBox(width: SecwetSpace.s2), a],
        ],
      ),
    );
  }
}

/// Text input in the desktop Field style: label, 44 px control, help or error.
class SecwetField extends StatelessWidget {
  const SecwetField({
    super.key,
    this.label,
    this.controller,
    this.hint,
    this.help,
    this.error,
    this.obscure = false,
    this.multiline = false,
    this.autofocus = false,
    this.onChanged,
    this.onSubmitted,
    this.keyboardType,
    this.onDialog = false,
    this.autocorrect = true,
  });

  final String? label;
  final TextEditingController? controller;
  final String? hint;
  final String? help;
  final String? error;
  final bool obscure;
  final bool multiline;
  final bool autofocus;
  final ValueChanged<String>? onChanged;
  final ValueChanged<String>? onSubmitted;
  final TextInputType? keyboardType;

  /// Inside a dialog the control uses the page background, like desktop.
  final bool onDialog;
  final bool autocorrect;

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      mainAxisSize: MainAxisSize.min,
      children: [
        if (label != null) ...[
          Text(label!, style: SecwetText.sm(p, color: p.textSecondary).copyWith(fontWeight: FontWeight.w500)),
          const SizedBox(height: SecwetSpace.s1),
        ],
        _Control(
          controller: controller,
          hint: hint,
          invalid: error != null,
          obscure: obscure,
          multiline: multiline,
          autofocus: autofocus,
          onChanged: onChanged,
          onSubmitted: onSubmitted,
          keyboardType: keyboardType,
          background: onDialog ? p.bg : p.surface,
          autocorrect: autocorrect,
        ),
        if (error != null || help != null) ...[
          const SizedBox(height: SecwetSpace.s1),
          Text(error ?? help!, style: SecwetText.sm(p, color: error != null ? p.danger : p.textTertiary)),
        ],
      ],
    );
  }
}

/// Search input with the leading magnifier, as in the desktop lists.
class SearchField extends StatelessWidget {
  const SearchField({super.key, required this.hint, this.controller, this.onChanged});

  final String hint;
  final TextEditingController? controller;
  final ValueChanged<String>? onChanged;

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    return _Control(
      controller: controller,
      hint: hint,
      onChanged: onChanged,
      background: p.surface,
      border: p.border,
      leading: SecwetIcon(SecwetIcons.search, size: 16, color: p.textTertiary),
    );
  }
}

class _Control extends StatelessWidget {
  const _Control({
    this.controller,
    this.hint,
    this.invalid = false,
    this.obscure = false,
    this.multiline = false,
    this.autofocus = false,
    this.onChanged,
    this.onSubmitted,
    this.keyboardType,
    required this.background,
    this.border,
    this.leading,
    this.autocorrect = true,
  });

  final TextEditingController? controller;
  final String? hint;
  final bool invalid;
  final bool obscure;
  final bool multiline;
  final bool autofocus;
  final ValueChanged<String>? onChanged;
  final ValueChanged<String>? onSubmitted;
  final TextInputType? keyboardType;
  final Color background;
  final Color? border;
  final Widget? leading;
  final bool autocorrect;

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    final style = SecwetText.md(p).copyWith(height: 1.3);
    // Material TextField for selection handles and the paste menu; every
    // decoration is off so only the container below draws the control.
    final input = TextField(
      controller: controller,
      style: style,
      cursorColor: p.accent,
      obscureText: obscure,
      autocorrect: autocorrect && !obscure,
      enableSuggestions: autocorrect && !obscure,
      autofocus: autofocus,
      maxLines: multiline ? null : 1,
      minLines: multiline ? 4 : null,
      keyboardType: keyboardType ?? (multiline ? TextInputType.multiline : TextInputType.text),
      onChanged: onChanged,
      onSubmitted: onSubmitted,
      // `collapsed` only clears `border`; without these the theme's enabled
      // and focused borders draw a second outline inside the control.
      decoration: InputDecoration.collapsed(hintText: hint, hintStyle: style.copyWith(color: p.textTertiary)).copyWith(
        enabledBorder: InputBorder.none,
        focusedBorder: InputBorder.none,
        errorBorder: InputBorder.none,
        focusedErrorBorder: InputBorder.none,
        disabledBorder: InputBorder.none,
      ),
    );
    return Container(
      constraints: BoxConstraints(minHeight: multiline ? 88 : SecwetControl.touchTarget),
      padding: EdgeInsets.symmetric(horizontal: SecwetSpace.s3, vertical: multiline ? SecwetSpace.s2 : 0),
      decoration: BoxDecoration(
        color: background,
        border: Border.all(color: invalid ? p.danger : (border ?? p.borderStrong)),
        borderRadius: BorderRadius.circular(SecwetRadius.control),
      ),
      child: Row(
        crossAxisAlignment: multiline ? CrossAxisAlignment.start : CrossAxisAlignment.center,
        children: [
          if (leading != null) ...[leading!, const SizedBox(width: SecwetSpace.s2)],
          // TextField needs a Material ancestor; a transparent one draws nothing.
          Expanded(child: Material(type: MaterialType.transparency, child: input)),
        ],
      ),
    );
  }
}
