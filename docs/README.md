<p align="center">
  <img src="assets/icon-dark.png" width="128" height="128" alt="Secwet icon">
</p>

<h1 align="center">Secwet</h1>

<p align="center">
  Passwordless, end-to-end encrypted secrets manager for developers.<br>
  Your secrets. Your devices. Your keys.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/macOS-13%2B-1c1b19?logo=apple&logoColor=white" alt="macOS 13 or later">
  <img src="https://img.shields.io/badge/Apple%20Silicon%20%2B%20Intel-universal-5d7aa8" alt="Universal app">
  <img src="https://img.shields.io/badge/encryption-XChaCha20--Poly1305-3d6a4c" alt="XChaCha20-Poly1305 encryption">
  <img src="https://img.shields.io/badge/biometrics-Touch%20ID-6b8b59" alt="Touch ID native biometrics">
  <img src="https://img.shields.io/badge/network-local--first%20%2F%20zero%20telemetry-9bc27f" alt="Local-first and zero telemetry">
  <img src="https://img.shields.io/badge/built%20with-Rust%20%2B%20Tauri%202-b45f43?logo=rust&logoColor=white" alt="Built with Rust and Tauri 2">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-proprietary-6c685f" alt="Proprietary license"></a>
</p>

---

## Why Secwet

Most secret managers either force your credentials onto third-party cloud services with accounts, master passwords, and recurring subscriptions, or leave you juggling plain `.env` files that accidentally leak into git commits, shell histories, and unencrypted backups.

Secwet sits in between. It is passwordless, local-first, and end-to-end encrypted. Your master keys are stored directly in your operating system's secure enclave (macOS Keychain via native LocalAuthentication Touch ID). Your secrets are sealed with XChaCha20-Poly1305 before they ever touch disk and are never stored or transmitted in the clear.

When you build or deploy, Secwet injects your secrets directly into child processes in memory (`secwet run`) without ever writing a plaintext `.env` file to disk. When you copy a token, the native Rust host writes it directly to the system clipboard and automatically scrubs it after 30 seconds. The webview never receives the secret value.

It is lightweight, fast, and works 100% offline. No accounts, no email verification, and no telemetry.

## What it does

- **Groups & Items.** Organize credentials your way. No rigid project templates or required folder hierarchies. Group items by team, infrastructure domain, client, or microservice.
- **Environment Scopes.** Add optional environment scopes (General, Development, Staging, Production) only when an item needs them. Items without environments stay clean and simple.
- **Secrets & Key-Value.** Secret values are masked by default. Reveal on demand, inline edit, or copy directly. The clipboard automatically clears sensitive tokens after 30 seconds.
- **Encrypted Files & Certificates.** Store `.pem` certificates, private SSH keys (`id_ed25519`), service account credentials, and license files directly in Secwet with drag-and-drop encryption, metadata tracking, and secure export.
- **Operational Notes.** Keep runbooks, database connection strings, and architecture notes right next to the secrets they document.
- **CLI Process Injection.** `secwet run -- ./dev.sh` injects decrypted secrets into child process environments entirely in memory. Your secret tokens never land in shell history or on disk.
- **Biometrics & Touch ID.** Unlock Secwet in milliseconds with native macOS Touch ID or system passcode. Automatically locks when idle (1, 5, 15, 30, or 60 minutes), when the screen sleeps, or immediately with `Cmd+L`.
- **Zero-Leak Clipboard.** When copying secrets from the desktop app, the Rust host handles the system clipboard directly. Plaintext values are never passed into webview memory or stored in DOM state.
- **Device Identity & Pairing.** Passwordless device authorization using Ed25519 signing keys and X25519/HPKE encryption keys. Pair new devices with an ephemeral single-use QR payload and a 6-digit confirmation code.
- **Device Revocation & Key Rotation.** Revoke lost or decommissioned devices with one click. Rotate the master encryption key so revoked devices cannot read future changes.
- **Recovery Keys & Encrypted Backups.** Generate a 25-character Crockford Base32 recovery key to safeguard access. Export encrypted, versioned backups for secure cold storage.

## Safe by design

Every byte stored or transmitted by Secwet is governed by strict cryptographic boundaries:

1. **Authenticated Sealing (AEAD).** All record blobs (secrets, notes, files, metadata) are encrypted using XChaCha20-Poly1305 with random 192-bit nonces. Nonce reuse is practically impossible. Every payload binds canonical Postcard `RecordAad` (record UUID, version, parent UUID, and record type) into the Poly1305 MAC, preventing ciphertext cut-and-paste or record substitution attacks.
2. **Key Derivation (HKDF-SHA256).** Per-record encryption keys, sync event keys, and recovery keys are derived from the master key using HKDF-SHA256 with domain-separated salt and info parameters.
3. **Asymmetric Key Exchange (HPKE RFC 9180).** Device pairing and cross-device key distribution use Hybrid Public Key Encryption in Mode Base (`DHKEM(X25519, HKDF-SHA256)`, `HKDF-SHA256`, `ChaCha20Poly1305`).
4. **Device Identity & Non-Malleability (Ed25519).** Device identities and sync events are signed using Ed25519 with strict verification rules to prevent signature malleability.
5. **OS Secure Storage & Biometrics.** The master key never touches unencrypted storage. It is protected by the macOS Keychain (`keyring`) and unlocked via LocalAuthentication (`LAContext`) Touch ID.
6. **In-Memory Secret Scrubbing.** Sensitive keys and plaintext secrets are guarded with `secrecy::SecretString` and `zeroize::Zeroizing`. Plaintext memory is wiped on drop, and sensitive values are automatically redacted from `Debug` logs and error messages.
7. **Durable Local Storage.** Secwet storage uses an embedded SQLite database with Write-Ahead Logging (`PRAGMA journal_mode = WAL`), foreign key integrity, and immediate durability.

The core security model lives in [`crates/secwet-core/src/crypto.rs`](../crates/secwet-core/src/crypto.rs) and is covered by property tests and unit test suites.

## Private by default

Secwet has no telemetry, no tracking analytics, no user accounts, and no advertising code. The local desktop application and CLI run entirely offline.

The application webview operates under a strict Content Security Policy (CSP) with external network access blocked. When the optional relay sync is active, the relay server acts as a blind mailbox: it receives only sealed ciphertext envelopes with ephemeral routing IDs and never possesses the keys to decrypt store contents.

## CLI

Secwet includes a standalone, zero-dependency command line tool (`secwet`) that shares the same local store as the desktop application.

### Configuration (`.secwet.toml`)

Place a `.secwet.toml` in your project root to bind the directory to an item and environment:

```toml
item = "api-service"
env = "development"
```

### Commands

```bash
# List secret names and types (never prints values)
secwet list

# Run any command with secrets injected into its environment
secwet run -- npm run dev
secwet run -- python manage.py runserver
secwet run -- docker compose up

# Fetch a single secret value to stdout
secwet get DATABASE_URL

# Set or update a secret value from stdin
echo "sec_live_example_12345" | secwet set STRIPE_SECRET_KEY --kind api_key

# Import an existing .env file into Secwet
secwet import .env.production

# Export decrypted secrets to a file or stdout
secwet export --format dotenv --out .env.local

# View store status, device ID, epoch, and health
secwet status
```

## Workspace layout

```
secwet/
├── apps/
│   ├── desktop/             # macOS desktop app (Tauri 2, React, Vite, TypeScript)
│   │   ├── src/             # UI: Overview, Items, Secrets, Devices, Recovery, Settings
│   │   └── src-tauri/       # Rust desktop host, Touch ID biometrics, clipboard manager
│   └── mobile/              # Flutter mobile client (iOS, Android)
├── crates/
│   ├── secwet-core/         # Security core engine: XChaCha20, HKDF, HPKE, SQLite WAL, models
│   ├── secwet-cli/          # Command line tool with in-memory process environment injection
│   ├── secwet-proto/        # Wire protocol: Postcard AAD, serialized records, envelopes
│   └── secwet-relay/        # Minimal Axum relay for blind encrypted sync events
├── packages/
│   ├── design-tokens/       # Single source of truth for color, space, radius (CSS & Dart)
│   └── brand/               # Geometric brand generation (Splash Twin, macOS Assets.car)
└── docs/                    # Architecture, design decisions, and implementation specs
```

## Build it yourself

### Prerequisites

- **Rust**: 1.90+ stable (`rustup update stable`)
- **Node.js**: 22+ or 25+ with **pnpm** 12+ (`corepack enable`)
- **Xcode**: 15+ (for macOS desktop builds and Icon Composer compilation)

### Development

```bash
# Install dependencies
pnpm install

# Build tokens and brand assets
pnpm tokens
pnpm brand

# Run the desktop app in development
pnpm desktop:tauri

# Run the UI in browser mode (mock/dev)
pnpm desktop:dev

# Run the test suite across all crates
cargo test --workspace

# Build and run the CLI
cargo run -p secwet-cli -- --help
```

### Typecheck and verification

```bash
# TypeScript verification
pnpm typecheck

# Rust checks
cargo check --workspace
```

## Design system & Craft

Secwet is designed around quiet, tactile software principles:

- **Moss Palette.** Muted moss green (`#3D6A4C` in light, `#8FBE9C` in dark) against warm stone and cream backdrops that adapt naturally to system appearance.
- **Restraint.** No gratuitous drop shadows, no intrusive focus rings, and no hover animations. Controls emphasize selected, disabled, and invalid states with clear, purposeful contrast.
- **Custom Iconography.** Custom 20pt outline icons drawn with 1.5pt strokes and rounded caps, inspired by Apple's SF Symbols.
- **Splash Twin Mark.** The brand mark represents two liquid splashes on a diagonal with a wet highlight cut out of the front splash. The geometry is generated mathematically using closed Catmull-Rom splines and golden-ratio proportions (`packages/brand/geometry.mjs`), compiled to native macOS adaptive icons (`Assets.car`).

## License

Secwet is proprietary software. You are welcome to read the code, but you may not copy, modify or redistribute it without written permission. See [LICENSE](../LICENSE). Taking part in this project means following the [code of conduct](CODE_OF_CONDUCT.md).
