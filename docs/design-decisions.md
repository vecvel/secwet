# Design decisions

Approved 2026-10-23. Tokens live in `packages/design-tokens/tokens.json`; run `pnpm tokens` to regenerate CSS (`dist/tokens.css`) and Flutter (`apps/mobile/lib/theme/secwet_tokens.dart`).

| Decision | Value |
| --- | --- |
| Palette | Moss: quiet green on warm stone, light and dark following the OS |
| Corner rounding | Soft, 8px controls and cards, 12px dialogs |
| Borders | Text color at 8% (default) and 16% (inputs, secondary buttons) |
| Shadows | None, except one overlay shadow for dialogs |
| Controls | No hover, focus, outline or press styling; only selected, disabled, invalid, loading. Selected items change color and background only, never font weight or size |
| Navigation | Expanded (1024px and up): sidebar plus top bar. Medium (640 to 1023px): icon rail. Compact (under 640px) and the mobile app: bottom tab bar with three tabs (Groups, Overview in the center, Settings), the same as desktop; Devices, Recovery, Sync and Plan live in Settings tabs, and the Groups tab is the sidebar as a screen (space switcher, groups, items, New); bar surface is translucent through most of its height and deepens to the darker sunken shade, fully solid over the bottom ~18px (80% of the gradient); opacity and color follow one smootherstep curve from 32px above the bar, so there is no visible band; no blur and no top line; content above the bar stays sharp; all tiles and labels sit on one line |
| Nav icons | Option C: every icon or project initial sits on a 24px moss tile (tint), filled when selected; the tile never changes size between sidebar, rail and bottom tabs. Sidebar items are 36px tall with 6px on every side of the tile, and get a soft rounded 8px tint (`accentTintSoft`, 7 to 8%) when selected (no hover state); window buttons, logo, group labels and tiles share one left edge at 18pt; rail items are 40px squares |
| Filled buttons | Deep moss `#3D6A4C` in both themes with light text; destructive buttons deep red `#B0372D` (`accentFill`, `dangerFill` tokens) |
| Icons | One custom outline set in the style of SF Symbols: 20pt grid, 1.5 stroke, round caps (`apps/desktop/src/components/Icon.tsx`) |
| Logo | Splash Twin: two liquid splashes on a diagonal, front one with a wet highlight; no colored background (moss in light, mint in dark); app icons are cream with a faint hairline in light mode and a subtle warm dark gradient (#31302E to #1C1C1B) with an 8% cream hairline in dark mode; the bundled macOS app uses an adaptive Icon Composer icon (Assets.car) and the dev app swaps its Dock icon with the system appearance; construction in `packages/brand` (`pnpm brand` regenerates every icon) |
| Font | System font only, no monospace |
| macOS window | Overlay title bar, no title text; window buttons (x 18 to 78) in their own drag row with equal 18pt space either side (`--titlebar-controls-width: 96px`), brand below |
| Header | Breadcrumb only, no status badges; content fills the full window width |

## Screens

Every screen runs on real data through the shared app layer (`crates/secwet-app`); the phone reaches it through `crates/secwet-ffi`.

| Screen | Desktop | Mobile |
| --- | --- | --- |
| Overview (counts, recently changed, recent notes, quick actions, setup and safety checklist, Customize dashboard) | Built; opens on launch | Built; center tab, opens on launch |
| Groups: spaces, groups and entries; entry with environments and Secrets / Assets / Notes tabs | Built (sidebar and main view) | Built (Groups tab, pushed group and entry screens) |
| Secrets (create, edit, reveal, copy with 30 s clear, copy to environment, delete) | Built | Built; iOS local-only expiring pasteboard item, Android sensitive clip |
| Assets (upload, preview, download) and rich-text notes | Built | Built (system document picker and save dialog) |
| Devices, pairing (this device shows the QR and a code; the other side scans or joins by link), revoke with or without remote wipe | Built | Built in Settings > Devices; a phone can pair either way |
| Recovery and backup (recovery key, encrypted export and restore) | Built | Built in Settings > Recovery |
| Sync, Plan (Free, Pro, Paused; Check for Pro) | Built in Settings | Built in Settings > Sync and Plan |
| Members, sharing and invitations (tree-wise roles) | Built | Built (Members screen, Invite flow, join with an invite link) |
| Settings > Security (key rotation, unlock, lock now) | Built; biometric section only when a biometric is usable | Built; read-only unlock row (system prompt always on; a phone without a screen lock stops at "Set a screen lock to use Secwet" before it opens) |
| Lock screen | Unlock button, biometric prompt when turned on | Blank; the system prompt opens by itself, no button |
| Onboarding (create, restore from export, join with an invite) | Silent create | Built; runs once |

Pairing QR payload: `secwet://pair?v=1&s=<one-time session>&k=<ephemeral public key>`. It never carries the master key or a reusable credential.

Keyboard users currently get no visible focus indicator. This was a deliberate choice; adding one subtle `:focus-visible` treatment in the shared control styles is the fix if that changes.

## Mobile app

Approved 2026-10-29 (preview: `docs/previews/mobile-theme.html`). Mobile reuses the desktop components exactly: outlined pills (`Badge`), underline tabs with count pills (`SegmentedTabs`), desktop buttons, cards, notices and the bottom-bar fade. Touch targets are 44px, matching the desktop's coarse-pointer styles. Wide tab rows scroll sideways.

**Mobile unlock and header (approved 2026-10-29):**
- There is no password unlock screen. Onboarding runs once. After that, every launch, and every return after the auto-lock timeout, shows a blank lock screen with only the system Face ID, Touch ID or fingerprint prompt, with the OS passcode or PIN as fallback. There is no Unlock button. If the prompt is cancelled, tapping the screen or reopening the app shows it again. The app-switcher snapshot always shows the blank lock screen.
- Phones must have a screen lock (PIN, passcode, pattern or biometrics). Secwet has no master password: the device keys live in the Keychain or Keystore, bound to the screen lock, and the recovery key is only for restoring access (a new phone, a lost device, a restore). If the phone has no screen lock, onboarding and unlock stop at one screen, "Set a screen lock to use Secwet", with a button that opens the phone's security settings, and continue once a lock is set. The recovery key is never asked for to unlock a phone every day.
- Why: the OS ties the keys to the screen lock and the secure hardware (Secure Enclave, Android hardware keystore), and the phone limits wrong guesses, so the keys can't be copied off and guessed offline. A Secwet-only PIN would need a password KDF that is not on the approved crypto list, and a short PIN protected only by the app can be guessed offline. Most password managers and banking apps also require a screen lock.
- Screen headers never show the logo or the wordmark. Each screen starts with its title, with that screen's actions on the same row. Every screen title uses the same style (20 px, semibold); on pushed screens the breadcrumb parents use it too, in the tertiary color.
- Every button and icon button on mobile is 44 px tall (the desktop touch rule); there is no smaller size. Inputs (fields, search, selects) use the surface color on the page and the page background inside a card, dialog or sheet, like the desktop `--input-bg`.
