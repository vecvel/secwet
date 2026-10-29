import 'package:flutter/widgets.dart';

import 'secwet_tokens.dart';

/// Palette lookup for widgets: `context.palette.accent`. Follows the OS
/// light or dark setting unless a [SecwetPaletteScope] pins one.
extension SecwetThemeContext on BuildContext {
  SecwetPalette get palette =>
      SecwetPaletteScope.maybeOf(this) ??
      (MediaQuery.platformBrightnessOf(this) == Brightness.dark ? SecwetPalette.dark : SecwetPalette.light);
}

/// Pins the palette for a subtree (the app root sets it from the platform
/// brightness; tests and previews can force one).
class SecwetPaletteScope extends InheritedWidget {
  const SecwetPaletteScope({super.key, required this.palette, required super.child});

  final SecwetPalette palette;

  static SecwetPalette? maybeOf(BuildContext context) =>
      context.dependOnInheritedWidgetOfExactType<SecwetPaletteScope>()?.palette;

  @override
  bool updateShouldNotify(SecwetPaletteScope oldWidget) => oldWidget.palette != palette;
}

/// Text styles from the tokens. System font only; no monospace anywhere.
abstract final class SecwetText {
  static const double lineHeight = 1.5;

  static TextStyle body(SecwetPalette p) =>
      TextStyle(fontSize: SecwetFontSize.base, height: lineHeight, color: p.textPrimary);
  static TextStyle md(SecwetPalette p, {Color? color, FontWeight weight = FontWeight.w400}) =>
      TextStyle(fontSize: SecwetFontSize.md, height: lineHeight, color: color ?? p.textPrimary, fontWeight: weight);
  static TextStyle sm(SecwetPalette p, {Color? color}) =>
      TextStyle(fontSize: SecwetFontSize.sm, height: lineHeight, color: color ?? p.textTertiary);
  static TextStyle xs(SecwetPalette p, {Color? color}) =>
      TextStyle(fontSize: SecwetFontSize.xs, height: lineHeight, color: color ?? p.textTertiary);
  /// Tab root titles (preview `.ptitle`: 20 px on a 28 px line).
  static TextStyle pageTitle(SecwetPalette p) =>
      TextStyle(fontSize: SecwetFontSize.xl, height: 1.4, fontWeight: FontWeight.w600, color: p.textPrimary);
  static TextStyle title(SecwetPalette p) =>
      TextStyle(fontSize: SecwetFontSize.lg, height: 1.3, fontWeight: FontWeight.w600, color: p.textPrimary);
  static TextStyle brand(SecwetPalette p) =>
      TextStyle(fontSize: 15, height: lineHeight, fontWeight: FontWeight.w600, color: p.textPrimary);
  static TextStyle stat(SecwetPalette p) =>
      TextStyle(fontSize: SecwetFontSize.xl, height: 1.4, fontWeight: FontWeight.w600, color: p.textPrimary);
}
