import 'package:flutter/material.dart';

import '../core/session.dart';
import '../theme/app_theme.dart';
import '../theme/secwet_theme.dart';
import 'auto_lock.dart';
import 'root_gate.dart';
import 'secwet_scope.dart';

/// Root widget: theme following the OS light or dark setting, the session
/// scope, auto-lock, and the gate that picks onboarding, unlock or the shell.
class SecwetApp extends StatelessWidget {
  const SecwetApp({super.key, required this.session});

  final SessionController session;

  @override
  Widget build(BuildContext context) {
    // Appearance follows the OS unless Settings picks light or dark.
    return ListenableBuilder(
      listenable: session,
      builder: (context, _) => MaterialApp(
        title: 'Secwet',
        debugShowCheckedModeBanner: false,
        theme: buildSecwetTheme(Brightness.light),
        darkTheme: buildSecwetTheme(Brightness.dark),
        themeMode: switch (session.theme) {
          'light' => ThemeMode.light,
          'dark' => ThemeMode.dark,
          _ => ThemeMode.system,
        },
        builder: (context, child) => SecwetScope(
          session: session,
          child: Builder(
            builder: (context) => DefaultTextStyle(
              style: SecwetText.body(context.palette),
              child: AutoLock(child: child!),
            ),
          ),
        ),
        home: const RootGate(),
      ),
    );
  }
}
