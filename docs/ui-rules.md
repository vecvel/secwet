# UI rules

Learned app-building rules from approved decisions on Secwet. They are also added to the clean-design-redesign-ui, clean-cross-platform-ui and redesign-ui skills; this file is the copy that survives a skill re-sync. Re-add this section to those skills if a re-sync drops it.

These come from approved decisions on earlier apps. They override framework defaults. When one conflicts with a project's established brand, preview both and ask.

**Process**
- Every UI question or recommendation is shown as a rendered visual preview; never ask a design question in text alone. Code changes follow approval.
- Use the latest stable version of every framework, library and toolchain (skip pre-releases such as alphas).
- Build production-ready from the start: one token source for every platform, light and dark both finished, real data shapes.

**Typography and text**
- System font only. No extra fonts, including no monospace (secret values, code names and IDs use the system font too).
- Selected or active states never change font weight or size; only color, tile or background change.

**Color and surfaces**
- Primary (filled) buttons use a deep fill dark enough for light text, in both themes; destructive buttons likewise use a deep red with light text.
- Selected backgrounds are subtle: a low-opacity accent tint (about 7 to 8 percent).
- No hover backgrounds anywhere, including sidebar and nav items.
- No blur or backdrop-filter effects: they render a hard edge. Use color gradients instead.
- No brand-colored tile behind the logo inside the app; the mark stands on its own in the accent color.

**Layout and spacing**
- Content fills the available width; no large empty gap on one side from a max-width cap.
- Icons inside selected backgrounds get equal padding on every side (for example a 24px tile in a 36px row, 6px all round).
- Logo, nav icons, group labels and (on macOS) window buttons share one left edge.
- No stray extra space, especially at the bottom of screens and bars; check safe-area insets are real before using them.
- Card and checklist rows must not wrap text awkwardly when narrow: move the action below the text (container queries) instead of squeezing the text.

**Navigation**
- Nav icons sit on small square tiles with the app's standard rounding, not full-width row highlights; projects or items can show an initial in the tile.
- Icon and tile size stays the same in the full sidebar, the narrow icon rail and mobile bottom tabs.
- The main or home screen sits in the center of mobile bottom tabs and is selected by default; it opens on launch.
- All bottom tabs share one size and one baseline; none is raised or enlarged.
- Sidebar groups get short dim labels, including one above the home item (for example "Home").

**Desktop window (macOS and other native shells)**
- No app title text next to the window buttons; integrate the buttons into the app chrome (overlay title bar).
- Equal space on both sides of the window buttons; put the logo and app name below the window-button row, not beside it.
- The whole header and the sidebar's top rows drag the window (except buttons, fields, tabs and menu items); double-click zooms. Do not rely on drag-region attributes that only react to the element itself.
- Ignore safe-area insets reported by desktop web views (rounded window corners); keep real insets on phones.

**Headers and chrome**
- Keep the header minimal: page context only, no status badges or helper text.

**Mobile bottom bar**
- No top border line.
- Solid and slightly darker toward the bottom edge, fading upward into the content along one eased curve (smootherstep, many stops) so there is no visible cut or band.
- Inactive tiles in the bar get a solid base so scrolling content never shows through them.

**Data and functionality**
- Full create, edit and delete for every main entity and its contents (for example projects, sub-groups and items), with typed-name confirmation for large deletions and duplicate-name checks.
- Include a home or overview screen that combines summary counts, recent changes and a setup or safety checklist driven by real state.

**Logo and icons**
- Logos are built from explicit mathematical construction (ratios, curves, booleans), generated from one source into every platform asset, and work on desktop, mobile, light and dark.
- The in-app logo is slightly larger than the nav icons so it never looks smaller.
- Icons are minimal: no extra detail such as keyboards on laptops or secondary devices unless it carries meaning.
- App icons sit on neutral light or dark backgrounds, not a brand-colored tile.
