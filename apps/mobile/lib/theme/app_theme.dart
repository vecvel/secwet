import 'package:flutter/material.dart';

import 'secwet_tokens.dart';

/// Builds ThemeData from the generated tokens. Splash, highlight, hover and
/// focus overlays are removed to match the desktop design decisions.
ThemeData buildSecwetTheme(Brightness brightness) {
  final p = brightness == Brightness.dark ? SecwetPalette.dark : SecwetPalette.light;
  const transparent = WidgetStatePropertyAll<Color>(Colors.transparent);
  final controlShape = RoundedRectangleBorder(borderRadius: BorderRadius.circular(SecwetRadius.control));
  final border = OutlineInputBorder(
    borderRadius: BorderRadius.circular(SecwetRadius.control),
    borderSide: BorderSide(color: p.borderStrong),
  );

  return ThemeData(
    brightness: brightness,
    useMaterial3: true,
    scaffoldBackgroundColor: p.bg,
    canvasColor: p.bg,
    dividerColor: p.border,
    splashFactory: NoSplash.splashFactory,
    splashColor: Colors.transparent,
    highlightColor: Colors.transparent,
    hoverColor: Colors.transparent,
    focusColor: Colors.transparent,
    colorScheme: ColorScheme(
      brightness: brightness,
      primary: p.accent,
      onPrimary: p.accentContrast,
      secondary: p.accent,
      onSecondary: p.accentContrast,
      error: p.danger,
      onError: p.surface,
      surface: p.surface,
      onSurface: p.textPrimary,
      onSurfaceVariant: p.textSecondary,
      outline: p.borderStrong,
      outlineVariant: p.border,
    ),
    textTheme: TextTheme(
      headlineSmall: TextStyle(fontSize: SecwetFontSize.xl, fontWeight: FontWeight.w600, color: p.textPrimary),
      titleMedium: TextStyle(fontSize: SecwetFontSize.lg, fontWeight: FontWeight.w600, color: p.textPrimary),
      bodyMedium: TextStyle(fontSize: SecwetFontSize.base, color: p.textSecondary),
      labelSmall: TextStyle(fontSize: SecwetFontSize.xs, color: p.textTertiary),
    ),
    filledButtonTheme: FilledButtonThemeData(
      style: ButtonStyle(
        overlayColor: transparent,
        backgroundColor: WidgetStatePropertyAll(p.accentFill),
        foregroundColor: WidgetStatePropertyAll(p.onAccentFill),
        minimumSize: const WidgetStatePropertyAll(Size(0, SecwetControl.touchTarget)),
        shape: WidgetStatePropertyAll(controlShape),
      ),
    ),
    outlinedButtonTheme: OutlinedButtonThemeData(
      style: ButtonStyle(
        overlayColor: transparent,
        foregroundColor: WidgetStatePropertyAll(p.textPrimary),
        side: WidgetStatePropertyAll(BorderSide(color: p.borderStrong)),
        minimumSize: const WidgetStatePropertyAll(Size(0, SecwetControl.touchTarget)),
        shape: WidgetStatePropertyAll(controlShape),
      ),
    ),
    textButtonTheme: TextButtonThemeData(
      style: ButtonStyle(overlayColor: transparent, foregroundColor: WidgetStatePropertyAll(p.accent)),
    ),
    inputDecorationTheme: InputDecorationTheme(
      filled: true,
      fillColor: p.surfaceSunken,
      border: border,
      enabledBorder: border,
      focusedBorder: border,
      errorBorder: border.copyWith(borderSide: BorderSide(color: p.danger)),
      focusedErrorBorder: border.copyWith(borderSide: BorderSide(color: p.danger)),
      hintStyle: TextStyle(color: p.textTertiary),
    ),
    navigationBarTheme: NavigationBarThemeData(
      backgroundColor: p.bg,
      indicatorColor: p.accentTint,
      overlayColor: transparent,
      surfaceTintColor: Colors.transparent,
    ),
  );
}
