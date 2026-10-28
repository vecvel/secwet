# Secwet Milestone 3 Reference Export Fixtures

This directory contains authoritative reference `.secwet` export fixtures for Milestone 3 (Recovery and Export) testing.

## Reference Recovery Key
- **Formatted**: `0M8N4-6M8N4-6M8N4-6M8N4-6M8N4` (or dynamically generated per manifest)
- **Crockford Alphabet**: `0123456789ABCDEFGHJKMNPQRSTVWXYZ` (no I, L, O, U)
- **Encryption**: `XChaCha20-Poly1305`
- **KDF**: `HKDF-SHA256` (`salt = secwet_id`, `info = b"secwet/v1/recovery"`)
- **AAD**: `postcard(("secwet-export", 1u8, secwet_id))`

## Fixture Inventory
See `manifest.json` for SHA-256 digests and validation expectations.
