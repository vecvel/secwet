import 'package:flutter/cupertino.dart' show CupertinoPageRoute;
import 'package:flutter/widgets.dart';

import '../screens/groups/groups_screen.dart';
import '../screens/overview/overview_screen.dart';
import '../screens/settings/settings_screen.dart';
import '../theme/secwet_theme.dart';
import '../theme/secwet_tokens.dart';
import '../widgets/controls.dart';
import '../widgets/icon.dart';
import 'secwet_scope.dart';

/// The three bottom tabs. Overview sits in the center and opens on launch.
enum ShellTab {
  groups('Groups', SecwetIcons.folder),
  overview('Overview', SecwetIcons.grid),
  settings('Settings', SecwetIcons.settings);

  const ShellTab(this.label, this.icon);

  final String label;
  final SecwetIcons icon;
}

/// Bottom bar height above the safe area (tokens: layout.bottomBarHeight).
const double kBottomBarHeight = 56;

/// Space a scrolling tab screen leaves at its bottom so its last row clears the bar.
double bottomBarClearance(BuildContext context) => kBottomBarHeight + MediaQuery.paddingOf(context).bottom + SecwetSpace.s4;

/// Pushes [screen] inside the current tab (the bar stays visible). [name]
/// lets a breadcrumb find the screen again ([openCrumb]).
Future<T?> pushScreen<T>(BuildContext context, Widget screen, {String? name}) =>
    Navigator.of(context).push<T>(CupertinoPageRoute<T>(builder: (_) => screen, settings: RouteSettings(name: name)));

/// A breadcrumb tap: goes back to the screen pushed as [name] when it is
/// below this one in the tab, otherwise back to the tab root and opens
/// [screen] there. With no [name], goes back to the tab root.
void openCrumb(BuildContext context, {String? name, Widget Function()? screen}) {
  final navigator = Navigator.of(context);
  var found = false;
  navigator.popUntil((route) {
    if (name != null && route.settings.name == name) found = true;
    return found || route.isFirst;
  });
  if (!found && screen != null) navigator.push(CupertinoPageRoute<void>(builder: (_) => screen(), settings: RouteSettings(name: name)));
}

/// Route name of a group screen, for [pushScreen] and [openCrumb].
String groupRouteName(String groupId) => 'group:$groupId';

/// Tab shell: one navigator per tab so each keeps its own stack, and the
/// bottom bar floating over the content with the desktop fade.
class SecwetShell extends StatefulWidget {
  const SecwetShell({super.key, this.initialTab = ShellTab.overview});

  final ShellTab initialTab;

  /// Switches tabs from anywhere inside the shell: `SecwetShell.of(context).select(ShellTab.settings)`.
  static SecwetShellState of(BuildContext context) => context.findAncestorStateOfType<SecwetShellState>()!;

  @override
  State<SecwetShell> createState() => SecwetShellState();
}

class SecwetShellState extends State<SecwetShell> {
  late ShellTab _tab = widget.initialTab;
  final _navigators = {for (final t in ShellTab.values) t: GlobalKey<NavigatorState>()};
  final _depth = {for (final t in ShellTab.values) t: ValueNotifier<int>(1)};

  ShellTab get tab => _tab;

  /// The navigator of [tab], for pushing a screen into another tab.
  NavigatorState? navigatorFor(ShellTab tab) => _navigators[tab]!.currentState;

  /// Shows [tab]; tapping the current tab returns it to its first screen.
  void select(ShellTab tab) {
    if (tab == _tab) {
      navigatorFor(tab)?.popUntil((r) => r.isFirst);
      return;
    }
    setState(() => _tab = tab);
  }

  static Widget _root(ShellTab tab) => switch (tab) {
        ShellTab.groups => const GroupsScreen(),
        ShellTab.overview => const OverviewScreen(),
        ShellTab.settings => const SettingsScreen(),
      };

  @override
  void dispose() {
    for (final d in _depth.values) {
      d.dispose();
    }
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    // Back on Android pops inside the current tab first.
    return PopScope(
      canPop: false,
      onPopInvokedWithResult: (didPop, _) {
        if (didPop) return;
        final nav = navigatorFor(_tab);
        if (nav != null && nav.canPop()) {
          nav.pop();
        } else if (_tab != ShellTab.overview) {
          select(ShellTab.overview);
        }
      },
      child: ColoredBox(
        color: p.bg,
        child: Stack(
          children: [
            IndexedStack(
              index: _tab.index,
              children: [
                for (final t in ShellTab.values)
                  HeroControllerScope.none(
                    child: Navigator(
                      key: _navigators[t],
                      observers: [_DepthObserver(_depth[t]!)],
                      onGenerateRoute: (_) => CupertinoPageRoute(builder: (_) => _root(t)),
                    ),
                  ),
              ],
            ),
            Positioned(
              left: 0,
              right: 0,
              bottom: 0,
              child: ValueListenableBuilder<int>(
                valueListenable: _depth[ShellTab.groups]!,
                builder: (context, groupsDepth, _) => BottomTabs(
                  selected: _tab,
                  onSelect: select,
                  // The Groups tab's first screen is the sidebar, on the sidebar color.
                  background: _tab == ShellTab.groups && groupsDepth <= 1 ? p.sidebarBg : p.bg,
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _DepthObserver extends NavigatorObserver {
  _DepthObserver(this.depth);

  final ValueNotifier<int> depth;

  @override
  void didPush(Route<dynamic> route, Route<dynamic>? previousRoute) => depth.value++;

  @override
  void didPop(Route<dynamic> route, Route<dynamic>? previousRoute) => depth.value--;

  @override
  void didRemove(Route<dynamic> route, Route<dynamic>? previousRoute) => depth.value--;
}

/// The mobile bottom bar (apps/desktop/src/layout/BottomTabs.module.css):
/// three equal tabs on one baseline, no top line, no blur. From 64 px above
/// the bar the color deepens from the page background to the sunken shade
/// and the opacity rises along one smootherstep curve, both full at 80%.
class BottomTabs extends StatelessWidget {
  const BottomTabs({super.key, required this.selected, required this.onSelect, required this.background});

  final ShellTab selected;
  final ValueChanged<ShellTab> onSelect;

  /// The page color behind the bar (sidebar color on the Groups list).
  final Color background;

  static const _fadeAbove = 64.0;

  // smootherstep(t) for t = 0, 0.1, ... 1.0, as in the CSS stops.
  static const _alphas = [0.0, 0.009, 0.058, 0.163, 0.317, 0.5, 0.683, 0.837, 0.942, 0.991, 1.0];

  LinearGradient _fade(Color bg, Color sunken) {
    final colors = <Color>[];
    final stops = <double>[];
    for (var i = 0; i <= 10; i++) {
      colors.add(Color.lerp(bg, sunken, i / 10)!.withValues(alpha: _alphas[i]));
      stops.add(i * 0.08);
    }
    colors.add(sunken);
    stops.add(1);
    return LinearGradient(begin: Alignment.topCenter, end: Alignment.bottomCenter, colors: colors, stops: stops);
  }

  @override
  Widget build(BuildContext context) {
    final session = SecwetScope.of(context).session;
    return ListenableBuilder(listenable: session, builder: (context, _) => _bar(context, session.homeLabel));
  }

  /// The Overview tab carries the Home view title, as the desktop sidebar does.
  Widget _bar(BuildContext context, String homeLabel) {
    final p = context.palette;
    final inset = MediaQuery.paddingOf(context).bottom;
    String label(ShellTab t) => t == ShellTab.overview ? homeLabel : t.label;
    return SizedBox(
      height: kBottomBarHeight + inset,
      child: Stack(
        clipBehavior: Clip.none,
        children: [
          Positioned(
            top: -_fadeAbove,
            left: 0,
            right: 0,
            bottom: 0,
            child: IgnorePointer(
              child: DecoratedBox(decoration: BoxDecoration(gradient: _fade(background, p.surfaceSunken))),
            ),
          ),
          Padding(
            padding: EdgeInsets.only(bottom: inset),
            child: Row(
              children: [
                for (final t in ShellTab.values)
                  Expanded(
                    child: Tappable(
                      label: label(t),
                      selected: t == selected,
                      onTap: () => onSelect(t),
                      child: SizedBox(
                        height: kBottomBarHeight,
                        child: Column(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            IconTile(icon: t.icon, selected: t == selected, solidBase: true),
                            const SizedBox(height: SecwetSpace.s1),
                            Text(
                              label(t),
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                              style: SecwetText.xs(p, color: t == selected ? p.textPrimary : p.textTertiary).copyWith(height: 1.2),
                            ),
                          ],
                        ),
                      ),
                    ),
                  ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

/// Standard tab screen: page color, safe top, 16 px gutters, a top bar, and
/// content that scrolls under the bottom bar but clears it at the end.
class ShellPage extends StatelessWidget {
  const ShellPage({super.key, required this.topBar, required this.children, this.background});

  final Widget topBar;
  final List<Widget> children;

  /// Page color; defaults to the page background (Groups list uses the sidebar color).
  final Color? background;

  @override
  Widget build(BuildContext context) {
    final p = context.palette;
    final list = ListView(
      padding: EdgeInsets.fromLTRB(SecwetSpace.s4, 0, SecwetSpace.s4, bottomBarClearance(context)),
      physics: const AlwaysScrollableScrollPhysics(parent: BouncingScrollPhysics()),
      children: [topBar, ...children],
    );
    return ColoredBox(
      color: background ?? p.bg,
      child: SafeArea(bottom: false, child: list),
    );
  }
}
