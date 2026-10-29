import 'dart:async';

import 'package:flutter/material.dart' show Material, MaterialType;
import 'package:flutter/widgets.dart';

import '../theme/secwet_theme.dart';
import '../theme/secwet_tokens.dart';
import 'controls.dart';
import 'icon.dart';
import 'layout.dart';

const _overlayShadow = [BoxShadow(color: Color(0x24000000), offset: Offset(0, 12), blurRadius: 32)];
const _ease = Cubic(0.16, 1, 0.3, 1);

/// Opens a dialog as a bottom sheet over the scrim (the desktop Dialog at
/// compact width). Resolves with the value passed to `Navigator.pop`.
Future<T?> showSecwetDialog<T>(BuildContext context, {required WidgetBuilder builder, bool dismissible = true}) async {
  final p = context.palette;
  final route = PageRouteBuilder<T>(
    opaque: false,
    barrierDismissible: dismissible,
    barrierColor: p.scrim,
    barrierLabel: 'Close',
    transitionDuration: const Duration(milliseconds: 280),
    reverseTransitionDuration: const Duration(milliseconds: 200),
    pageBuilder: (context, _, _) => builder(context),
    transitionsBuilder: (context, animation, _, child) => SlideTransition(
      position: Tween(begin: const Offset(0, 1), end: Offset.zero).animate(CurvedAnimation(parent: animation, curve: _ease)),
      child: child,
    ),
  );
  final result = await Navigator.of(context, rootNavigator: true).push<T>(route);
  // Resolve only once the sheet has slid away and left the tree, so a
  // caller that pushes a screen next (New entry, then the entry) never
  // builds it while the closing sheet and the keyboard inset still change.
  await route.completed;
  return result;
}

/// Desktop Dialog panel, docked to the bottom: header (title, description),
/// scrolling body, footer with right-aligned actions on the tinted bar.
class SecwetDialog extends StatelessWidget {
  const SecwetDialog({super.key, required this.title, this.description, this.children = const [], this.actions = const []});

  final String title;
  final String? description;
  final List<Widget> children;
  final List<Widget> actions;

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    final media = MediaQuery.of(context);
    // The home indicator area, unless the keyboard already covers it. The
    // last part of the sheet (footer, body or header) clears it.
    final homeInset = media.viewInsets.bottom > 0 ? 0.0 : media.padding.bottom;
    return Material(
      type: MaterialType.transparency,
      child: Padding(
        padding: EdgeInsets.only(bottom: media.viewInsets.bottom),
        child: Align(
          alignment: Alignment.bottomCenter,
          child: Container(
            constraints: BoxConstraints(maxHeight: media.size.height - media.padding.top - SecwetSpace.s8),
            decoration: BoxDecoration(
              color: p.surface,
              border: Border.all(color: p.border),
              borderRadius: const BorderRadius.vertical(top: Radius.circular(SecwetRadius.dialog)),
              boxShadow: _overlayShadow,
            ),
            clipBehavior: Clip.antiAlias,
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Padding(
                  padding: EdgeInsets.fromLTRB(
                    SecwetSpace.s5,
                    SecwetSpace.s5,
                    SecwetSpace.s5,
                    SecwetSpace.s3 + (children.isEmpty && actions.isEmpty ? homeInset : 0),
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(title, style: SecwetText.title(p)),
                      if (description != null) ...[
                        const SizedBox(height: SecwetSpace.s1),
                        Text(description!, style: SecwetText.md(p, color: p.textSecondary)),
                      ],
                    ],
                  ),
                ),
                if (children.isNotEmpty)
                  Flexible(
                    child: SingleChildScrollView(
                      padding: EdgeInsets.fromLTRB(
                        SecwetSpace.s5,
                        SecwetSpace.s2,
                        SecwetSpace.s5,
                        SecwetSpace.s3 + (actions.isEmpty ? homeInset : 0),
                      ),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.stretch,
                        children: [
                          for (final (i, c) in children.indexed) ...[
                            if (i > 0) const SizedBox(height: SecwetSpace.s4),
                            c,
                          ],
                        ],
                      ),
                    ),
                  ),
                if (actions.isNotEmpty)
                  Container(
                    padding: EdgeInsets.fromLTRB(
                      SecwetSpace.s5,
                      SecwetSpace.s4,
                      SecwetSpace.s5,
                      SecwetSpace.s4 + homeInset,
                    ),
                    decoration: BoxDecoration(
                      color: Color.alphaBlend(p.cardHeaderBg, p.surface),
                      border: Border(top: BorderSide(color: p.borderSeparator)),
                    ),
                    child: Row(
                      mainAxisAlignment: MainAxisAlignment.end,
                      children: [
                        for (final (i, a) in actions.indexed) ...[
                          if (i > 0) const SizedBox(width: SecwetSpace.s2),
                          a,
                        ],
                      ],
                    ),
                  ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

/// Asks to confirm a change. With [typedName] the user must type that name
/// before the confirm button works (large deletions). Resolves true when confirmed.
Future<bool> showConfirmDialog(
  BuildContext context, {
  required String title,
  required String message,
  required String confirmLabel,
  String? typedName,
  bool danger = true,
}) async {
  final confirmed = await showSecwetDialog<bool>(
    context,
    builder: (_) => _ConfirmDialog(
      title: title,
      message: message,
      confirmLabel: confirmLabel,
      typedName: typedName,
      danger: danger,
    ),
  );
  return confirmed ?? false;
}

class _ConfirmDialog extends StatefulWidget {
  const _ConfirmDialog({
    required this.title,
    required this.message,
    required this.confirmLabel,
    this.typedName,
    required this.danger,
  });

  final String title;
  final String message;
  final String confirmLabel;
  final String? typedName;
  final bool danger;

  @override
  State<_ConfirmDialog> createState() => _ConfirmDialogState();
}

class _ConfirmDialogState extends State<_ConfirmDialog> {
  final _typed = TextEditingController();

  @override
  void dispose() {
    _typed.dispose();
    super.dispose();
  }

  bool get _matches => widget.typedName == null || _typed.text.trim() == widget.typedName;

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    return SecwetDialog(
      title: widget.title,
      actions: [
        SecwetButton(
          label: 'Cancel',
          variant: ButtonVariant.secondary,
          onPressed: () => Navigator.of(context).pop(false),
        ),
        SecwetButton(
          label: widget.confirmLabel,
          variant: widget.danger ? ButtonVariant.danger : ButtonVariant.primary,
          onPressed: _matches ? () => Navigator.of(context).pop(true) : null,
        ),
      ],
      children: [
        Text(widget.message, style: SecwetText.md(p, color: p.textSecondary)),
        if (widget.typedName != null)
          Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text.rich(
                TextSpan(
                  style: SecwetText.md(p, color: p.textSecondary),
                  children: [
                    const TextSpan(text: 'Type '),
                    TextSpan(text: widget.typedName, style: TextStyle(color: p.textPrimary, fontWeight: FontWeight.w600)),
                    const TextSpan(text: ' to confirm.'),
                  ],
                ),
              ),
              const SizedBox(height: SecwetSpace.s2),
              SecwetField(
                controller: _typed,
                hint: widget.typedName,
                onDialog: true,
                autofocus: true,
                autocorrect: false,
                onChanged: (_) => setState(() {}),
              ),
            ],
          ),
      ],
    );
  }
}

/// One entry of a [SecwetMenuButton].
class MenuEntry {
  const MenuEntry(this.label, {this.icon, this.onSelected, this.danger = false}) : separator = false;

  const MenuEntry.separator()
      : label = '',
        icon = null,
        onSelected = null,
        danger = false,
        separator = true;

  final String label;
  final SecwetIcons? icon;
  final VoidCallback? onSelected;
  final bool danger;
  final bool separator;
}

/// Desktop Menu: a "more" trigger that opens a floating list under it
/// (above it near the bottom of the screen).
class SecwetMenuButton extends StatelessWidget {
  const SecwetMenuButton({super.key, required this.entries, this.icon = SecwetIcons.more, this.label = 'More', this.small = true});

  final List<MenuEntry> entries;
  final SecwetIcons icon;
  final String label;
  final bool small;

  @override
  Widget build(BuildContext context) {
    return SecwetIconButton(
      icon: icon,
      label: label,
      small: small,
      onPressed: () => showSecwetMenu(context, entries),
    );
  }
}

/// Opens the menu anchored to [context]'s render box.
Future<void> showSecwetMenu(BuildContext context, List<MenuEntry> entries) async {
  final box = context.findRenderObject() as RenderBox?;
  if (box == null) return;
  final overlay = Navigator.of(context, rootNavigator: true).overlay!.context.findRenderObject() as RenderBox;
  final anchor = box.localToGlobal(Offset.zero, ancestor: overlay) & box.size;
  final picked = await Navigator.of(context, rootNavigator: true).push<MenuEntry>(
    PageRouteBuilder<MenuEntry>(
      opaque: false,
      barrierDismissible: true,
      barrierColor: const Color(0x00000000),
      barrierLabel: 'Close menu',
      transitionDuration: const Duration(milliseconds: 120),
      pageBuilder: (context, _, _) => _MenuPanel(anchor: anchor, entries: entries),
      transitionsBuilder: (context, animation, _, child) => FadeTransition(opacity: animation, child: child),
    ),
  );
  picked?.onSelected?.call();
}

class _MenuPanel extends StatelessWidget {
  const _MenuPanel({required this.anchor, required this.entries});

  final Rect anchor;
  final List<MenuEntry> entries;

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    final screen = MediaQuery.sizeOf(context);
    final up = anchor.center.dy > screen.height * 0.6;
    final right = (screen.width - anchor.right).clamp(SecwetSpace.s2, screen.width);
    return Stack(
      children: [
        Positioned(
          right: right,
          top: up ? null : anchor.bottom + 4,
          bottom: up ? screen.height - anchor.top + 4 : null,
          child: Container(
            constraints: const BoxConstraints(minWidth: 220),
            padding: const EdgeInsets.all(SecwetSpace.s1),
            decoration: BoxDecoration(
              color: p.surface,
              border: Border.all(color: p.borderStrong),
              borderRadius: BorderRadius.circular(SecwetRadius.dialog),
              boxShadow: _overlayShadow,
            ),
            child: IntrinsicWidth(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  for (final e in entries)
                    if (e.separator)
                      Container(height: 1, margin: const EdgeInsets.symmetric(vertical: SecwetSpace.s1, horizontal: 2), color: p.border)
                    else
                      Tappable(
                        label: e.label,
                        onTap: () => Navigator.of(context).pop(e),
                        child: Container(
                          height: SecwetControl.touchTarget,
                          padding: const EdgeInsets.symmetric(horizontal: 10),
                          child: Row(
                            children: [
                              if (e.icon != null) ...[
                                SecwetIcon(e.icon!, size: 16, color: e.danger ? p.danger : p.textTertiary),
                                const SizedBox(width: 10),
                              ],
                              Text(e.label, style: SecwetText.md(p, color: e.danger ? p.danger : p.textPrimary)),
                            ],
                          ),
                        ),
                      ),
                ],
              ),
            ),
          ),
        ),
      ],
    );
  }
}

/// Short message that floats above the bottom bar and goes away by itself.
void showToast(BuildContext context, String message, {BadgeTone tone = BadgeTone.neutral}) {
  final overlay = Overlay.maybeOf(context, rootOverlay: true);
  if (overlay == null) return;
  late OverlayEntry entry;
  entry = OverlayEntry(builder: (context) => _Toast(message: message, tone: tone, onDone: () => entry.remove()));
  overlay.insert(entry);
}

class _Toast extends StatefulWidget {
  const _Toast({required this.message, required this.tone, required this.onDone});

  final String message;
  final BadgeTone tone;
  final VoidCallback onDone;

  @override
  State<_Toast> createState() => _ToastState();
}

class _ToastState extends State<_Toast> with SingleTickerProviderStateMixin {
  late final AnimationController _c = AnimationController(vsync: this, duration: const Duration(milliseconds: 320))..forward();
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    _timer = Timer(const Duration(seconds: 3), () async {
      await _c.reverse();
      widget.onDone();
    });
  }

  @override
  void dispose() {
    _timer?.cancel();
    _c.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    final bottom = MediaQuery.paddingOf(context).bottom + 56 + SecwetSpace.s4;
    final dot = switch (widget.tone) {
      BadgeTone.neutral => null,
      BadgeTone.accent => p.accent,
      BadgeTone.success => p.success,
      BadgeTone.warning => p.warning,
      BadgeTone.danger => p.danger,
    };
    return Positioned(
      left: SecwetSpace.s4,
      right: SecwetSpace.s4,
      bottom: bottom,
      child: FadeTransition(
        opacity: CurvedAnimation(parent: _c, curve: _ease),
        child: Center(
          child: Container(
            padding: const EdgeInsets.symmetric(horizontal: SecwetSpace.s3, vertical: SecwetSpace.s2),
            decoration: BoxDecoration(
              color: p.surface,
              border: Border.all(color: p.border),
              borderRadius: BorderRadius.circular(SecwetRadius.dialog),
              boxShadow: _overlayShadow,
            ),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                if (dot != null) ...[
                  Container(width: 6, height: 6, decoration: BoxDecoration(color: dot, shape: BoxShape.circle)),
                  const SizedBox(width: SecwetSpace.s2),
                ],
                Flexible(
                  child: Text(
                    widget.message,
                    style: SecwetText.sm(p, color: p.textPrimary).copyWith(decoration: TextDecoration.none),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
