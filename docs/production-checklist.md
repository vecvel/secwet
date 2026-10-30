# Production checklist

Everything between today and real users on iOS, macOS and the hosted relay.
Tick items as they are done. Nothing ships to real users before the
independent security review (section 1).

## 1. Security (blocks launch)

- [ ] Fuzz targets for every parser of untrusted input (sync events, exports,
      invite and pairing links, relay request bodies); each runs 1 hour or more
      with no crash.
- [ ] `logs_contain_no_secrets` and the other security tests in the spec pass,
      including relay logs and Caddy access logs.
- [ ] Threat model written (devices, relay, network, lost device, malicious
      member, compromised relay) and reviewed by a person.
- [ ] Independent security review booked, done, and its findings fixed.
- [ ] Dependency audit clean: `cargo audit`, `pnpm audit`, Flutter packages.
- [ ] Secrets in CI only as GitHub secrets; deploy key limited to the deploy
      user; `SERVER_ROOT_PASSWORD` deleted after bootstrap.

## 2. Relay server

- [x] Container images, compose stack, HTTPS, backups and deploy workflows (`deploy/`).
- [x] Client IP rate limits work behind the proxy (`TRUST_PROXY`).
- [x] Test-only code kept out of the relay binary.
- [ ] Buy the VPS and domain; add the GitHub variables and secrets (`deploy/README.md`).
- [ ] Run "Relay: bootstrap server", save `SSH_KNOWN_HOSTS`, delete the root password secret.
- [ ] First deploy; `https://<domain>/health` answers; SSL Labs grade A or better.
- [ ] Off-server backups on (`RCLONE_REMOTE`); `BACKUP_PASSPHRASE` stored offline.
- [ ] Restore drill: restore a backup into a fresh database and sync a device against it.
- [ ] Uptime monitoring and alerts on `/health` (for example a free external checker).
- [ ] Required reviewers on the `production` GitHub environment.
- [ ] Load check: expected device count, WebSocket streams and snapshot sizes on the chosen server size.
- [ ] Before several relay servers: cross-instance stream notifications (Postgres LISTEN/NOTIFY).

## 3. Apps: shared

- [ ] Production relay URL as the default in Settings > Sync for desktop and mobile.
- [ ] Version numbers and build numbers set; changelog for the first release.
- [ ] Privacy policy and support pages online (needed by both stores).
- [ ] Crash reporting decision: none, or a privacy-preserving one with no secret
      data (and the privacy answers updated to match).

## 4. iOS

- [ ] Apple Developer Program membership; bundle ID `app.secwet...` registered.
- [ ] Signing certificate and provisioning profiles; Keychain access group matches the team.
- [ ] Rust FFI built for device (`aarch64-apple-ios`), not only the simulator.
- [ ] Real iPhone: Face ID and Touch ID unlock, passcode fallback, auto-lock,
      app-switcher privacy, clipboard expiry, QR pairing with the camera,
      invite and pairing deep links from outside the app, sync and sharing.
- [ ] `integration_test` passing on the current iOS simulator.
- [ ] `PrivacyInfo.xcprivacy` (required-reason APIs) and `NSFaceIDUsageDescription` text final.
- [ ] Export compliance answer (uses standard encryption).
- [ ] App Store Connect: listing, screenshots, privacy answers ("data not collected"
      if that stays true), age rating, TestFlight beta, then review.

## 5. macOS

- [ ] Choose distribution: Developer ID (signed, notarized DMG download) or the
      Mac App Store (sandboxed; check the Keychain, file picker and CLI install
      still work inside the sandbox).
- [ ] Developer ID Application certificate; hardened runtime; entitlements reviewed.
- [ ] Sign, notarize and staple the app; signed DMG; Gatekeeper opens it cleanly.
- [ ] Touch ID unlock, Keychain and clipboard clearing checked on the signed build.
- [ ] App icon assets from `pnpm brand` (`icons/Assets.car`).
- [ ] Update channel for direct downloads (Tauri updater with a signing key) or
      store updates.
- [ ] Release workflow that builds, signs and notarizes in CI with the
      certificates as GitHub secrets.

## 6. Later platforms

- [ ] Android: real-device run (Keystore unlock, BiometricPrompt, clipboard,
      scanner, document picker), Play signing key, Play Console listing.
- [ ] Windows: Windows Hello on a real machine, signed installer.
- [ ] Linux: fprintd on a real machine, packages (AppImage, deb).

## 7. Launch day

- [ ] Fresh backup taken; previous release image noted for rollback.
- [ ] Relay health and logs watched for the first hours.
- [ ] Support contact ready; known issues written down.
