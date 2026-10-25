# Design decisions

Approved 2026-10-23. Tokens live in `packages/design-tokens/tokens.json`; run `pnpm tokens` to regenerate CSS (`dist/tokens.css`) and Flutter (`apps/mobile/lib/theme/secwet_tokens.dart`).

| Decision | Value |
| --- | --- |
| Palette | Moss: quiet green on warm stone, light and dark following the OS |
| Corner rounding | Soft, 8px controls and cards, 12px dialogs |
| Borders | Text color at 8% (default) and 16% (inputs, secondary buttons) |
| Shadows | None, except one overlay shadow for dialogs |
| Controls | No hover, focus, outline or press styling; only selected, disabled, invalid, loading. Selected items change color and background only, never font weight or size |
| Navigation | Expanded (1024px and up): sidebar plus top bar. Medium (640 to 1023px): icon rail. Compact (under 640px): bottom tab bar with five tabs (Secrets, Devices, Overview in the center, Recovery, Settings); bar surface is translucent through most of its height and deepens to the darker sunken shade, fully solid over the bottom ~18px (80% of the gradient); opacity and color follow one smootherstep curve from 32px above the bar, so there is no visible band; no blur and no top line; content above the bar stays sharp; all tiles and labels sit on one line |
| Nav icons | Option C: every icon or project initial sits on a 24px moss tile (tint), filled when selected; the tile never changes size between sidebar, rail and bottom tabs. Sidebar items are 36px tall with 6px on every side of the tile, and get a soft rounded 8px tint (`accentTintSoft`, 7 to 8%) when selected (no hover state); window buttons, logo, group labels and tiles share one left edge at 18pt; rail items are 40px squares |
| Filled buttons | Deep moss `#3D6A4C` in both themes with light text; destructive buttons deep red `#B0372D` (`accentFill`, `dangerFill` tokens) |
| Icons | One custom outline set in the style of SF Symbols: 20pt grid, 1.5 stroke, round caps (`apps/desktop/src/components/Icon.tsx`) |
| Logo | Splash Twin: two liquid splashes on a diagonal, front one with a wet highlight; no colored background (moss in light, mint in dark); app icons are cream with a faint hairline in light mode and a subtle warm dark gradient (#31302E to #1C1C1B) with an 8% cream hairline in dark mode; the bundled macOS app uses an adaptive Icon Composer icon (Assets.car) and the dev app swaps its Dock icon with the system appearance; construction in `packages/brand` (`pnpm brand` regenerates every icon) |
| Font | System font only, no monospace |
| macOS window | Overlay title bar, no title text; window buttons (x 18 to 78) in their own drag row with equal 18pt space either side (`--titlebar-controls-width: 96px`), brand below |
| Header | Breadcrumb only, no status badges; content fills the full window width |

## Screens

| Screen | Status |
| --- | --- |
| Overview (counts, projects, recently changed, setup and safety checklist) | Built with mock data; opens on launch |
| Secrets (list, environments, filter; create, edit, copy to environment, delete) | Built with mock data |
| Projects and environments (create, rename, delete with typed confirmation) | Built with mock data |
| Devices, pairing (option A: this device shows the QR and a code to compare), revoke | Built with mock data |
| Recovery and backup (recovery key, encrypted export, key rotation) | Built with mock data; export saving not wired |
| Settings (plan, appearance, auto-lock, CLI snippet) | Built with mock data |

Pairing QR payload: `secwet://pair?v=1&s=<one-time session>&k=<ephemeral public key>`. It never carries the vault key or a reusable credential.

Keyboard users currently get no visible focus indicator. This was a deliberate choice; adding one subtle `:focus-visible` treatment in the shared control styles is the fix if that changes.
