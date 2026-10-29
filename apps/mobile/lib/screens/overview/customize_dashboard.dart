import 'package:flutter/widgets.dart';

import '../../core/secwet_api.dart';
import '../../theme/secwet_theme.dart';
import '../../theme/secwet_tokens.dart';
import '../../widgets/controls.dart';
import '../../widgets/layout.dart';
import '../../widgets/overlays.dart';
import '../groups/common.dart';

const allKpis = [('secrets', 'Secrets'), ('assets', 'Assets'), ('notes', 'Notes'), ('devices', 'Active Devices')];

const allWidgets = [
  ('recent_secrets', 'Recent Secrets'),
  ('recent_notes', 'Recent Notes'),
  ('quick_actions', 'Quick Actions'),
  ('checklist', 'Setup and Safety Checklist'),
];

/// Customize dashboard (desktop CustomizeDashboardDialog): Home title, the
/// visible KPI tiles, and which widgets show in what order. Resolves with
/// the saved config.
Future<DashboardConfig?> showCustomizeDashboard(BuildContext context, DashboardConfig config, Future<void> Function(DashboardConfig) save) =>
    showSecwetDialog<DashboardConfig>(context, builder: (_) => _CustomizeDialog(config: config, save: save));

class _CustomizeDialog extends StatefulWidget {
  const _CustomizeDialog({required this.config, required this.save});

  final DashboardConfig config;
  final Future<void> Function(DashboardConfig) save;

  @override
  State<_CustomizeDialog> createState() => _CustomizeDialogState();
}

class _CustomizeDialogState extends State<_CustomizeDialog> {
  late final _home = TextEditingController(text: widget.config.homeLabel.isEmpty ? 'Overview' : widget.config.homeLabel);
  late final List<String> _kpis = [for (final k in widget.config.visibleKpis) k == 'files' ? 'assets' : k];
  late final List<String> _order = [
    ...widget.config.widgets,
    for (final w in allWidgets)
      if (!widget.config.widgets.contains(w.$1)) w.$1,
  ];
  late final Set<String> _enabled = {...widget.config.widgets};
  bool _saving = false;
  String? _error;

  @override
  void dispose() {
    _home.dispose();
    super.dispose();
  }

  void _move(int i, int d) {
    final j = i + d;
    if (j < 0 || j >= _order.length) return;
    setState(() {
      final t = _order[i];
      _order[i] = _order[j];
      _order[j] = t;
    });
  }

  Future<void> _save() async {
    final config = DashboardConfig(
      homeLabel: _home.text.trim().isEmpty ? 'Overview' : _home.text.trim(),
      visibleKpis: [..._kpis],
      widgets: [for (final w in _order) if (_enabled.contains(w)) w],
    );
    setState(() => _saving = true);
    try {
      await widget.save(config);
      if (mounted) Navigator.of(context).pop(config);
    } catch (e) {
      if (mounted) {
        setState(() {
          _saving = false;
          _error = errorText(e, "Couldn't save the dashboard.");
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    Widget title(String t) => Text(t, style: SecwetText.sm(p, color: p.textSecondary).copyWith(fontWeight: FontWeight.w500));
    return SecwetDialog(
      title: 'Customize dashboard',
      description: 'Tailor the Home title, KPI metrics, and dashboard widgets.',
      actions: [
        SecwetButton(label: 'Cancel', variant: ButtonVariant.secondary, onPressed: () => Navigator.of(context).pop()),
        SecwetButton(label: 'Save changes', onPressed: _saving ? null : _save),
      ],
      children: [
        SecwetField(
          label: 'Home title',
          controller: _home,
          hint: 'e.g. Overview, Workspace, Command Center',
          help: 'Rename the Home view in the sidebar and top navigation.',
        ),
        Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            title('Visible KPI metrics'),
            for (final (id, label) in allKpis)
              CheckRow(
                label: label,
                checked: _kpis.contains(id),
                onChanged: (on) => setState(() => on ? _kpis.add(id) : _kpis.remove(id)),
              ),
          ],
        ),
        Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            title('Widgets & ordering'),
            for (final (i, id) in _order.indexed)
              if (allWidgets.where((w) => w.$1 == id).firstOrNull case final def?)
                Row(
                  children: [
                    Expanded(
                      child: CheckRow(
                        label: def.$2,
                        checked: _enabled.contains(id),
                        onChanged: (on) => setState(() => on ? _enabled.add(id) : _enabled.remove(id)),
                      ),
                    ),
                    SecwetButton(label: 'Up', variant: ButtonVariant.tertiary, onPressed: i == 0 ? null : () => _move(i, -1)),
                    const SizedBox(width: SecwetSpace.s2),
                    SecwetButton(
                      label: 'Down',
                      variant: ButtonVariant.tertiary,
                      onPressed: i == _order.length - 1 ? null : () => _move(i, 1),
                    ),
                  ],
                ),
          ],
        ),
        if (_error != null) Text(_error!, style: SecwetText.sm(p, color: p.danger)),
      ],
    );
  }
}
