# Secwet mobile

Flutter app for iOS and Android over the shared Rust app layer
(`crates/secwet-app`) through our own C ABI (`crates/secwet-ffi`). Details:
`docs/mobile-ffi.md`. Approved look: `docs/design-decisions.md` (Mobile app)
and `docs/previews/mobile-theme.html`.

## Run

```sh
flutter run                          # iOS simulator or Android device
flutter build ios --simulator --debug
flutter build apk --debug
flutter test && flutter analyze
```

The Rust library builds automatically: the Xcode "Build Rust" phase runs
`scripts/build_rust_ios.sh`, and Gradle runs `cargo ndk` before `preBuild`.
Needs the rustup iOS and Android targets and `cargo-ndk` (see the doc above).

## Layout

| Path | What |
| --- | --- |
| `lib/core/` | dart:ffi bindings, `SecwetApi` (every app-layer call, typed models), session, platform channel |
| `lib/app/` | app root, gate (onboarding, unlock, shell), tab shell with the bottom bar, auto-lock |
| `lib/widgets/` | desktop components: Button, Badge, SegmentedTabs, IconTile, cards and rows, Notice, EmptyState, Field, Dialog, ConfirmDialog, Menu, Toast |
| `lib/theme/` | tokens (`pnpm tokens`), icon set and brand mark (`pnpm brand`), all generated; SVG path parser |
| `lib/screens/` | onboarding, unlock; Groups, Overview, Settings and Sharing screens |
| `ios/Runner/SecwetPlatform.swift` | Keychain, clipboard, LocalAuthentication, document picker |
| `android/.../SecwetNative.kt` | Keystore, clipboard, BiometricPrompt; `SecwetPlatformChannel.kt` for files |
