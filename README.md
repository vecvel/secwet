# Secwet

Passwordless, end-to-end encrypted secrets manager for developers. Your secrets. Your devices. Your keys.

## Layout

```
apps/desktop          Tauri 2 desktop app (React + Vite UI, Rust host in src-tauri)
apps/mobile           Flutter app (iOS, Android)
crates/secwet-core    Shared security core: vault model, crypto traits, sync events
crates/secwet-cli     `secwet` command line (list, get, run with env injection)
crates/secwet-relay   Axum relay for encrypted sync events (never sees plaintext)
packages/design-tokens  Single source of design tokens for every client
docs/                 Design decisions and specs
```

## Status

Scaffold. The desktop Secrets, Devices, Recovery and Settings screens run on mock data (switch Free and Pro under Settings in dev builds). Vault encryption, device identity, pairing and sync are stubs; crypto must use audited libraries behind the traits in `secwet-core`.

Toolchain: Rust stable (Tauri 2 needs 1.90+), Node 25, pnpm 12, Flutter stable.

## Docs

- [docs/IMPLEMENTATION.md](docs/IMPLEMENTATION.md): how to build every feature, with specs, milestones and tests.
- [docs/design-decisions.md](docs/design-decisions.md) and [docs/ui-rules.md](docs/ui-rules.md): approved design and UI rules.

## Run

```bash
pnpm install
pnpm desktop:dev        # UI in a browser at http://localhost:1420
pnpm desktop:tauri      # native desktop window
cargo run -p secwet-cli -- --help
cargo run -p secwet-relay
cd apps/mobile && flutter run
```

Checks: `pnpm typecheck`, `pnpm desktop:build`, `cargo check --workspace`, `flutter analyze` and `flutter test` in `apps/mobile`.
