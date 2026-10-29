import 'package:flutter/widgets.dart';

import '../../app/secwet_scope.dart';
import '../../core/secwet_api.dart';
import '../../widgets/controls.dart';
import '../../widgets/layout.dart';
import '../../widgets/overlays.dart';
import 'settings_screen.dart';
import 'settings_widgets.dart';

/// Settings > General: appearance, auto-lock, home title and device name.
class GeneralTab extends StatelessWidget {
  const GeneralTab({super.key, required this.model});

  final SettingsModel model;

  Future<void> _save(BuildContext context, Future<void> Function(SecwetApi api) change) async {
    final scope = SecwetScope.read(context);
    try {
      await change(scope.api);
      await scope.session.reloadSettings();
      await model.load();
    } on SecwetException catch (e) {
      if (context.mounted) showToast(context, e.message, tone: BadgeTone.warning);
    }
  }

  @override
  Widget build(BuildContext context) {
    final session = SecwetScope.of(context).session;
    final settings = model.settings;
    final homeLabel = model.dashboard?.homeLabel;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const SectionLabel('Appearance & Locking'),
        SecwetCard(
          children: [
            SettingRow(
              title: 'Appearance',
              meta: "System follows your phone's light or dark setting.",
              below: SelectControl<String>(
                label: 'Appearance',
                value: session.theme,
                options: const [
                  SelectOption('system', 'System'),
                  SelectOption('light', 'Light'),
                  SelectOption('dark', 'Dark'),
                ],
                onChanged: (v) => _save(context, (api) => api.updateSettings(theme: v)),
              ),
            ),
            SettingRow(
              title: 'Lock Secwet after',
              meta: 'Idle time before revealed values hide and Secwet locks. Coming back after at least this long locks it too.',
              below: SelectControl<int>(
                label: 'Lock Secwet after',
                value: session.lockTimeoutMinutes,
                options: [
                  for (final m in {5, 15, 30, 60, session.lockTimeoutMinutes})
                    SelectOption(m, switch (m) { 0 => 'Never', 60 => '1 hour', _ => '$m minutes' }),
                ],
                onChanged: (v) => _save(context, (api) => api.updateSettings(lockTimeoutMinutes: v)),
              ),
            ),
          ],
        ),
        const SectionLabel('Workspace & Identity'),
        SecwetCard(
          children: [
            SettingRow(
              title: 'Home view title',
              meta: 'The title of the Overview tab.',
              below: SaveOnDoneField(
                initial: homeLabel == null || homeLabel.isEmpty ? 'Overview' : homeLabel,
                hint: 'Overview',
                onSave: (v) {
                  final config = model.dashboard;
                  if (config == null) return;
                  final label = v.trim().isEmpty ? 'Overview' : v.trim();
                  _save(
                    context,
                    (api) => api.setDashboard(
                      DashboardConfig(homeLabel: label, visibleKpis: config.visibleKpis, widgets: config.widgets),
                    ),
                  );
                },
              ),
            ),
            SettingRow(
              title: 'Device name',
              meta: 'Identifies this phone when approving or viewing paired devices.',
              below: SaveOnDoneField(
                initial: settings?.deviceName ?? '',
                hint: 'iPhone',
                onSave: (v) {
                  if (v.trim().isEmpty) return;
                  _save(context, (api) => api.updateSettings(deviceName: v.trim()));
                },
              ),
            ),
          ],
        ),
      ],
    );
  }
}
