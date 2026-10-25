import 'package:flutter/material.dart';

import 'theme/app_theme.dart';
import 'theme/secwet_tokens.dart';

void main() => runApp(const SecwetApp());

class SecwetApp extends StatelessWidget {
  const SecwetApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Secwet',
      debugShowCheckedModeBanner: false,
      theme: buildSecwetTheme(Brightness.light),
      darkTheme: buildSecwetTheme(Brightness.dark),
      themeMode: ThemeMode.system,
      home: const HomeShell(),
    );
  }
}

/// Compact navigation: bottom bar with the same four destinations as desktop.
/// Screens are placeholders until the desktop layouts are approved.
class HomeShell extends StatefulWidget {
  const HomeShell({super.key});

  @override
  State<HomeShell> createState() => _HomeShellState();
}

class _HomeShellState extends State<HomeShell> {
  int _index = 0;

  static const _titles = ['Secrets', 'Devices', 'Recovery', 'Settings'];

  @override
  Widget build(BuildContext context) {
    final text = Theme.of(context).textTheme;
    return Scaffold(
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(SecwetSpace.s4),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(_titles[_index], style: text.headlineSmall),
              const SizedBox(height: SecwetSpace.s2),
              Text('Mobile screens follow the approved desktop layouts.', style: text.bodyMedium),
            ],
          ),
        ),
      ),
      bottomNavigationBar: NavigationBar(
        selectedIndex: _index,
        onDestinationSelected: (i) => setState(() => _index = i),
        destinations: const [
          NavigationDestination(icon: Icon(Icons.folder_outlined), label: 'Secrets'),
          NavigationDestination(icon: Icon(Icons.devices_outlined), label: 'Devices'),
          NavigationDestination(icon: Icon(Icons.support_outlined), label: 'Recovery'),
          NavigationDestination(icon: Icon(Icons.tune_outlined), label: 'Settings'),
        ],
      ),
    );
  }
}
