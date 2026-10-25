//! Cryptographic primitives for Secwet.
//!
//! Features implemented:
//! - XChaCha20-Poly1305 record sealing and opening with canonical Postcard RecordAad binding.
//! - Blob framing: `[version: 1 byte = 0x01] || [nonce: 24 bytes] || [ciphertext with 16-byte Poly1305 tag]`.
//! - HKDF-SHA256 key derivations for record, event, and recovery keys.
//! - HPKE RFC 9180 Mode Base (DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305).
//! - Ed25519 signing and strict non-malleable verification.
//! - Device ID generation and UI key fingerprint calculation.
//! - Recovery key generation (125 bits formatted as 25 Crockford Base32 characters in 5 groups) and normalization.
//! - Masked `CryptoError` that never discloses whether MAC, padding, or format check failed.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use data_encoding::{Encoding, Specification};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use hpke::{
    aead::ChaCha20Poly1305 as HpkeAead, kdf::HkdfSha256 as HpkeKdf,
    kem::X25519HkdfSha256 as HpkeKem, Deserializable, Kem, OpModeR, OpModeS, Serializable,
};
use rand_core::{Rng, TryCryptoRng, TryRng};
use secwet_proto::{RecordAad, WrappedKey};
use sha2::{Digest, Sha256};
use std::sync::LazyLock;
use uuid::Uuid;
use x25519_dalek::StaticSecret;
use zeroize::Zeroizing;

// ============================================================================
// 1. Error Model & Random Number Generator
// ============================================================================

/// Generic cryptographic error.
///
/// Intentionally opaque to prevent padding or authentication oracles.
/// It never reveals whether MAC validation, length decoding, or format parsing failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CryptoError;

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "crypto error")
    }
}

impl std::error::Error for CryptoError {}

/// Cryptographically secure operating system random number generator wrapper.
#[derive(Clone, Copy, Debug, Default)]
pub struct OsRng;

impl TryRng for OsRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(getrandom::u32().expect("OS CSPRNG failure"))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(getrandom::u64().expect("OS CSPRNG failure"))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        getrandom::fill(dest).expect("OS CSPRNG failure");
        Ok(())
    }
}

impl TryCryptoRng for OsRng {}

// Blanket implementation provides Rng and CryptoRng for OsRng.

// ============================================================================
// 2. Blob Framing & Sealed Record Structure
// ============================================================================

pub const RECORD_BLOB_VERSION: u8 = 0x01;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
pub const MIN_RECORD_BLOB_LEN: usize = 1 + NONCE_LEN + TAG_LEN; // 41 bytes

/// In-memory representation of sealed ciphertext with its unique 24-byte nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

impl Sealed {
    pub fn new(nonce: [u8; NONCE_LEN], ciphertext: Vec<u8>) -> Self {
        Self { nonce, ciphertext }
    }

    pub fn to_blob(&self) -> Vec<u8> {
        encode_record_blob(&self.nonce, &self.ciphertext)
    }

    pub fn from_blob(blob: &[u8]) -> Result<Self, CryptoError> {
        let (nonce, ciphertext) = decode_record_blob(blob)?;
        Ok(Self {
            nonce,
            ciphertext: ciphertext.to_vec(),
        })
    }
}

/// Encodes components into SQLite blob format:
/// `[version: 1 byte = 0x01] || [nonce: 24 bytes] || [ciphertext with 16-byte Poly1305 tag]`.
pub fn encode_record_blob(nonce: &[u8; NONCE_LEN], ciphertext: &[u8]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());
    blob.push(RECORD_BLOB_VERSION);
    blob.extend_from_slice(nonce);
    blob.extend_from_slice(ciphertext);
    blob
}

/// Decodes an encoded record blob into nonce slice and ciphertext slice.
pub fn decode_record_blob(blob: &[u8]) -> Result<([u8; NONCE_LEN], &[u8]), CryptoError> {
    if blob.len() < MIN_RECORD_BLOB_LEN {
        return Err(CryptoError);
    }
    if blob[0] != RECORD_BLOB_VERSION {
        return Err(CryptoError);
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&blob[1..1 + NONCE_LEN]);
    let ciphertext = &blob[1 + NONCE_LEN..];
    Ok((nonce, ciphertext))
}

// ============================================================================
// 3. XChaCha20-Poly1305 Record Sealing & Opening
// ============================================================================

/// Seals a record payload under `k_rec` with strict AAD binding using XChaCha20-Poly1305.
///
/// Returns the framed blob: `[0x01] || [24-byte nonce] || [ciphertext + tag]`.
pub fn seal_record(k_rec: &[u8; 32], aad: &RecordAad, body: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let cipher = XChaCha20Poly1305::new(k_rec.into());
    let aad_bytes = postcard::to_stdvec(aad).map_err(|_| CryptoError)?;
    let payload = Payload {
        msg: body,
        aad: &aad_bytes,
    };
    let ciphertext = cipher
        .encrypt(&XNonce::from(nonce), payload)
        .map_err(|_| CryptoError)?;

    Ok(encode_record_blob(&nonce, &ciphertext))
}

/// Opens a framed record blob using `k_rec` and checks strict AAD binding.
///
/// Returns the decrypted plaintext bytes. Fails with `CryptoError` if any byte
/// is flipped, AAD mismatches, or the blob format is invalid.
pub fn open_record(k_rec: &[u8; 32], aad: &RecordAad, blob: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let (nonce, ciphertext) = decode_record_blob(blob)?;
    let cipher = XChaCha20Poly1305::new(k_rec.into());
    let aad_bytes = postcard::to_stdvec(aad).map_err(|_| CryptoError)?;
    let payload = Payload {
        msg: ciphertext,
        aad: &aad_bytes,
    };
    let plaintext = cipher
        .decrypt(&XNonce::from(nonce), payload)
        .map_err(|_| CryptoError)?;

    Ok(plaintext)
}

/// Seals a record payload into distinct nonce and ciphertext parts.
pub fn seal_record_parts(
    k_rec: &[u8; 32],
    aad: &RecordAad,
    body: &[u8],
) -> Result<Sealed, CryptoError> {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let cipher = XChaCha20Poly1305::new(k_rec.into());
    let aad_bytes = postcard::to_stdvec(aad).map_err(|_| CryptoError)?;
    let payload = Payload {
        msg: body,
        aad: &aad_bytes,
    };
    let ciphertext = cipher
        .encrypt(&XNonce::from(nonce), payload)
        .map_err(|_| CryptoError)?;

    Ok(Sealed { nonce, ciphertext })
}

/// Opens a record from distinct nonce and ciphertext parts.
pub fn open_record_parts(
    k_rec: &[u8; 32],
    aad: &RecordAad,
    sealed: &Sealed,
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(k_rec.into());
    let aad_bytes = postcard::to_stdvec(aad).map_err(|_| CryptoError)?;
    let payload = Payload {
        msg: &sealed.ciphertext,
        aad: &aad_bytes,
    };
    let plaintext = cipher
        .decrypt(&XNonce::from(sealed.nonce), payload)
        .map_err(|_| CryptoError)?;

    Ok(plaintext)
}

/// Authenticated encryption trait for record sealing and opening.
pub trait RecordCipher {
    fn seal(&self, plaintext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, CryptoError>;
    fn open(&self, ciphertext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

// ============================================================================
// 4. HKDF-SHA256 Key Derivations (RFC 5869)
// ============================================================================

/// Derives a 32-byte secret key using HKDF-SHA256 with the specified salt and info string.
pub fn derive_hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(info, &mut *okm)
        .expect("32 bytes is valid length for HKDF-SHA256");
    okm
}

/// Derives the record key `K_rec` from the vault key `k_v` and `vault_id`.
///
/// Uses `info = b"secwet/v1/record"` and `salt = vault_id.as_bytes()`.
pub fn derive_record_key(k_v: &[u8; 32], vault_id: &Uuid) -> Zeroizing<[u8; 32]> {
    derive_hkdf_sha256(k_v, vault_id.as_bytes(), b"secwet/v1/record")
}

/// Derives the event key `K_evt` from the vault key `k_v` and `vault_id`.
///
/// Uses `info = b"secwet/v1/event"` and `salt = vault_id.as_bytes()`.
pub fn derive_event_key(k_v: &[u8; 32], vault_id: &Uuid) -> Zeroizing<[u8; 32]> {
    derive_hkdf_sha256(k_v, vault_id.as_bytes(), b"secwet/v1/event")
}

/// Derives the recovery wrap key `K_r` from recovery secret bytes and `vault_id`.
///
/// Uses `info = b"secwet/v1/recovery"` and `salt = vault_id.as_bytes()`.
pub fn derive_recovery_key(recovery_secret: &[u8], vault_id: &Uuid) -> Zeroizing<[u8; 32]> {
    derive_hkdf_sha256(recovery_secret, vault_id.as_bytes(), b"secwet/v1/recovery")
}

/// Derives both `(K_rec, K_evt)` from the vault key `k_v` and `vault_id`.
pub fn derive_keys(k_v: &[u8; 32], vault_id: &Uuid) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    (
        derive_record_key(k_v, vault_id),
        derive_event_key(k_v, vault_id),
    )
}

// ============================================================================
// 5. HPKE Key Wrapping (RFC 9180 Mode Base)
// ============================================================================

/// Wraps a 32-byte secret key for a recipient device using HPKE RFC 9180 Mode Base
/// with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and ChaCha20Poly1305.
pub fn wrap_for_device(
    recipient_x25519_pub: &[u8; 32],
    info: &[u8],
    plaintext_key: &[u8; 32],
) -> Result<WrappedKey, CryptoError> {
    let pk =
        <HpkeKem as Kem>::PublicKey::from_bytes(recipient_x25519_pub).map_err(|_| CryptoError)?;

    let (encapped_key, mut sender_ctx) = hpke::setup_sender_with_rng::<HpkeAead, HpkeKdf, HpkeKem>(
        &OpModeS::Base,
        &pk,
        info,
        &mut OsRng,
    )
    .map_err(|_| CryptoError)?;

    let ciphertext = sender_ctx
        .seal(plaintext_key, b"")
        .map_err(|_| CryptoError)?;
    let mut enc = [0u8; 32];
    enc.copy_from_slice(&encapped_key.to_bytes());

    Ok(WrappedKey { enc, ciphertext })
}

/// Unwraps a wrapped key using our static X25519 private key and the bound info context.
pub fn unwrap_for_me(
    my_x25519_secret: &StaticSecret,
    info: &[u8],
    wrapped: &WrappedKey,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let encapped_key =
        <HpkeKem as Kem>::EncappedKey::from_bytes(&wrapped.enc).map_err(|_| CryptoError)?;
    let sk = <HpkeKem as Kem>::PrivateKey::from_bytes(&my_x25519_secret.to_bytes())
        .map_err(|_| CryptoError)?;

    let mut receiver_ctx = hpke::setup_receiver::<HpkeAead, HpkeKdf, HpkeKem>(
        &OpModeR::Base,
        &sk,
        &encapped_key,
        info,
    )
    .map_err(|_| CryptoError)?;

    let plaintext = receiver_ctx
        .open(&wrapped.ciphertext, b"")
        .map_err(|_| CryptoError)?;

    if plaintext.len() != 32 {
        return Err(CryptoError);
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&plaintext);
    Ok(key)
}

// ============================================================================
// 6. Ed25519 Signing & Strict Verification
// ============================================================================

/// Signs a binary payload using an Ed25519 signing key.
pub fn sign_payload(signing_key: &SigningKey, message: &[u8]) -> Signature {
    signing_key.sign(message)
}

/// Strictly verifies an Ed25519 signature over a message against a verifying key.
///
/// Rejects malleable, non-canonical, or invalid signatures.
pub fn verify_signature_strict(
    public_key: &VerifyingKey,
    message: &[u8],
    signature: &Signature,
) -> Result<(), CryptoError> {
    public_key
        .verify_strict(message, signature)
        .map_err(|_| CryptoError)
}

/// Strictly verifies an Ed25519 signature from raw 32-byte public key and 64-byte signature.
pub fn verify_signature_strict_bytes(
    public_key_bytes: &[u8; 32],
    message: &[u8],
    signature_bytes: &[u8; 64],
) -> Result<(), CryptoError> {
    let vk = VerifyingKey::from_bytes(public_key_bytes).map_err(|_| CryptoError)?;
    let sig = Signature::from_bytes(signature_bytes);
    vk.verify_strict(message, &sig).map_err(|_| CryptoError)
}

/// Device signing identity trait.
pub trait DeviceIdentity {
    fn public_key(&self) -> [u8; 32];
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], CryptoError>;
}

// ============================================================================
// 7. Device ID & UI Key Fingerprint
// ============================================================================

static CROCKFORD_BASE32: LazyLock<Encoding> = LazyLock::new(|| {
    let mut spec = Specification::new();
    spec.symbols.push_str("0123456789ABCDEFGHJKMNPQRSTVWXYZ");
    spec.translate
        .from
        .push_str("abcdefghjkmnpqrstvwxyzILOUilou");
    spec.translate.to.push_str("ABCDEFGHJKMNPQRSTVWXYZ11001100");
    spec.encoding()
        .expect("Valid Crockford Base32 specification")
});

/// Computes the deterministic 26-character Crockford Base32 device ID from an Ed25519 public key.
pub fn compute_device_id(ed25519_pub: &[u8; 32]) -> String {
    let digest = Sha256::digest(ed25519_pub);
    let encoded = CROCKFORD_BASE32.encode(&digest);
    encoded[..26].to_string()
}

/// Computes the 6-byte hex fingerprint of `SHA-256(ed25519_pub || x25519_pub)`
/// formatted as uppercase groups of 4: `XXXX XXXX XXXX` (e.g. `7F3A 18E0 91C2`).
pub fn compute_fingerprint(ed25519_pub: &[u8; 32], x25519_pub: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(ed25519_pub);
    hasher.update(x25519_pub);
    let digest = hasher.finalize();
    format!(
        "{:02X}{:02X} {:02X}{:02X} {:02X}{:02X}",
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5]
    )
}

// ============================================================================
// 8. Recovery Key Generation & Normalization
// ============================================================================

const CROCKFORD_CHARS: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

fn crockford_char_value(c: char) -> Option<u8> {
    match c {
        '0' => Some(0),
        '1' => Some(1),
        '2' => Some(2),
        '3' => Some(3),
        '4' => Some(4),
        '5' => Some(5),
        '6' => Some(6),
        '7' => Some(7),
        '8' => Some(8),
        '9' => Some(9),
        'A' => Some(10),
        'B' => Some(11),
        'C' => Some(12),
        'D' => Some(13),
        'E' => Some(14),
        'F' => Some(15),
        'G' => Some(16),
        'H' => Some(17),
        'J' => Some(18),
        'K' => Some(19),
        'M' => Some(20),
        'N' => Some(21),
        'P' => Some(22),
        'Q' => Some(23),
        'R' => Some(24),
        'S' => Some(25),
        'T' => Some(26),
        'V' => Some(27),
        'W' => Some(28),
        'X' => Some(29),
        'Y' => Some(30),
        'Z' => Some(31),
        _ => None,
    }
}

/// Formats 125-bit entropy (16 bytes with top 3 bits masked `& 0x1F`) as 25 Crockford Base32
/// characters in 5 groups: `XXXXX-XXXXX-XXXXX-XXXXX-XXXXX`.
pub fn format_recovery_key(entropy_16: &[u8; 16]) -> String {
    let mut masked = *entropy_16;
    masked[0] &= 0x1F;
    let val = u128::from_be_bytes(masked);

    let mut chars = Vec::with_capacity(29);
    for i in 0..25 {
        if i > 0 && i % 5 == 0 {
            chars.push(b'-');
        }
        let shift = (24 - i) * 5;
        let digit = ((val >> shift) & 0x1F) as usize;
        chars.push(CROCKFORD_CHARS[digit]);
    }
    String::from_utf8(chars).expect("Crockford base32 produces valid UTF-8")
}

/// Generates fresh 125-bit recovery entropy and formats it into 5 groups of 5 Crockford Base32 characters.
///
/// Returns `(formatted_string, raw_16_bytes_with_top_3_bits_masked)`.
pub fn generate_recovery_key() -> (String, Zeroizing<[u8; 16]>) {
    let mut raw = Zeroizing::new([0u8; 16]);
    OsRng.fill_bytes(&mut *raw);
    raw[0] &= 0x1F;
    let formatted = format_recovery_key(&raw);
    (formatted, raw)
}

/// Normalizes user-supplied recovery key input.
///
/// Rules:
/// - Strips whitespace, hyphens, and spaces.
/// - Converts to uppercase.
/// - Maps 'I' and 'L' to '1'.
/// - Maps 'O' to '0'.
/// - Verifies that the normalized string is exactly 25 valid Crockford Base32 characters.
pub fn normalize_recovery_key(input: &str) -> Result<String, CryptoError> {
    let mut normalized = String::with_capacity(25);
    for c in input.chars() {
        if c.is_whitespace() || c == '-' {
            continue;
        }
        let upper = c.to_ascii_uppercase();
        let mapped = match upper {
            'I' | 'L' => '1',
            'O' => '0',
            other => other,
        };
        if crockford_char_value(mapped).is_none() {
            return Err(CryptoError);
        }
        normalized.push(mapped);
    }

    if normalized.len() != 25 {
        return Err(CryptoError);
    }
    Ok(normalized)
}

/// Normalizes and parses a recovery key string into 125-bit entropy bytes (16 bytes, top 3 bits zero).
pub fn parse_recovery_key(input: &str) -> Result<Zeroizing<[u8; 16]>, CryptoError> {
    let normalized = normalize_recovery_key(input)?;
    let mut val = 0u128;
    for c in normalized.chars() {
        let digit = crockford_char_value(c).ok_or(CryptoError)?;
        val = (val << 5) | (digit as u128);
    }
    let bytes = val.to_be_bytes();
    Ok(Zeroizing::new(bytes))
}

/// Formats a 25-character normalized recovery key into 5 groups of 5 separated by hyphens.
pub fn format_normalized_recovery_key(normalized_25: &str) -> Result<String, CryptoError> {
    if normalized_25.len() != 25 {
        return Err(CryptoError);
    }
    let mut formatted = String::with_capacity(29);
    for (i, c) in normalized_25.chars().enumerate() {
        if i > 0 && i % 5 == 0 {
            formatted.push('-');
        }
        formatted.push(c);
    }
    Ok(formatted)
}
