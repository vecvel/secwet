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
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
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

/// Seals an arbitrary plaintext buffer under a 32-byte key with raw AAD using XChaCha20Poly1305.
///
/// Returns distinct `(nonce, ciphertext)` parts (where ciphertext includes the 16-byte Poly1305 tag).
pub fn seal_raw_parts(
    key: &[u8; 32],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<([u8; NONCE_LEN], Vec<u8>), CryptoError> {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let cipher = XChaCha20Poly1305::new(key.into());
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    let ciphertext = cipher
        .encrypt(&XNonce::from(nonce), payload)
        .map_err(|_| CryptoError)?;

    Ok((nonce, ciphertext))
}

/// Decrypts ciphertext parts using a 32-byte key with raw AAD using XChaCha20Poly1305.
pub fn open_raw_parts(
    key: &[u8; 32],
    aad: &[u8],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let payload = Payload {
        msg: ciphertext,
        aad,
    };
    let plaintext = cipher
        .decrypt(&XNonce::from(*nonce), payload)
        .map_err(|_| CryptoError)?;

    Ok(plaintext)
}

/// Seals an arbitrary plaintext buffer under a 32-byte key with raw AAD using XChaCha20Poly1305.
///
/// Returns the standard framed blob: `[0x01] || [24-byte nonce] || [ciphertext + 16-byte tag]`.
pub fn seal_raw(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let (nonce, ciphertext) = seal_raw_parts(key, aad, plaintext)?;
    Ok(encode_record_blob(&nonce, &ciphertext))
}

/// Opens a framed blob using a 32-byte key with raw AAD using XChaCha20Poly1305.
pub fn open_raw(key: &[u8; 32], aad: &[u8], blob: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let (nonce, ciphertext) = decode_record_blob(blob)?;
    open_raw_parts(key, aad, &nonce, ciphertext)
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

/// Derives the record key `K_rec` from the master key `k_v` and `secwet_id`.
///
/// Uses `info = b"secwet/v1/record"` and `salt = secwet_id.as_bytes()`.
pub fn derive_record_key(k_v: &[u8; 32], secwet_id: &Uuid) -> Zeroizing<[u8; 32]> {
    derive_hkdf_sha256(k_v, secwet_id.as_bytes(), b"secwet/v1/record")
}

/// Derives the event key `K_evt` from the master key `k_v` and `secwet_id`.
///
/// Uses `info = b"secwet/v1/event"` and `salt = secwet_id.as_bytes()`.
pub fn derive_event_key(k_v: &[u8; 32], secwet_id: &Uuid) -> Zeroizing<[u8; 32]> {
    derive_hkdf_sha256(k_v, secwet_id.as_bytes(), b"secwet/v1/event")
}

/// Derives the recovery wrap key `K_r` from recovery secret bytes and `secwet_id`.
///
/// Uses `info = b"secwet/v1/recovery"` and `salt = secwet_id.as_bytes()`.
pub fn derive_recovery_key(recovery_secret: &[u8], secwet_id: &Uuid) -> Zeroizing<[u8; 32]> {
    derive_hkdf_sha256(recovery_secret, secwet_id.as_bytes(), b"secwet/v1/recovery")
}

/// Derives both `(K_rec, K_evt)` from the master key `k_v` and `secwet_id`.
pub fn derive_keys(k_v: &[u8; 32], secwet_id: &Uuid) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    (
        derive_record_key(k_v, secwet_id),
        derive_event_key(k_v, secwet_id),
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

/// Derives the recovery wrap key `K_r` from a user-supplied recovery key string and `secwet_id`.
///
/// Normalizes and parses the Crockford Base32 string to extract the 125-bit entropy bytes,
/// then applies HKDF-SHA256 (`salt = secwet_id`, `info = b"secwet/v1/recovery"`).
pub fn derive_recovery_key_from_str(
    recovery_key_str: &str,
    secwet_id: &Uuid,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let parsed = parse_recovery_key(recovery_key_str)?;
    Ok(derive_recovery_key(&*parsed, secwet_id))
}

// ============================================================================
// 10. Device Pairing Cryptography (F14)
// ============================================================================

/// Generates an ephemeral X25519 keypair for pairing session initiation or join.
pub fn generate_ephemeral_x25519() -> (StaticSecret, [u8; 32]) {
    let secret = StaticSecret::random_from_rng(&mut OsRng);
    let public = X25519PublicKey::from(&secret);
    (secret, public.to_bytes())
}

/// Computes the X25519 Diffie-Hellman shared secret between our secret and peer's ephemeral public key.
pub fn compute_pairing_shared_secret(
    my_secret: &StaticSecret,
    peer_pub: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let peer_public = X25519PublicKey::from(*peer_pub);
    let shared = my_secret.diffie_hellman(&peer_public);
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(shared.as_bytes());
    Ok(key)
}

/// Formats the standard QR code URI for device pairing:
/// `secwet://pair?v=1&s=<session_id>&k=<base64url(A_eph_pub)>&r=<relay host>`
pub fn format_pairing_qr_payload(
    session_id: &Uuid,
    a_eph_pub: &[u8; 32],
    relay_host: &str,
) -> String {
    let k_encoded = data_encoding::BASE64URL_NOPAD.encode(a_eph_pub);
    format!(
        "secwet://pair?v=1&s={}&k={}&r={}",
        session_id, k_encoded, relay_host
    )
}

/// Parses a pairing URI and extracts session_id, peer ephemeral pub, and relay host.
pub fn parse_pairing_qr_payload(uri: &str) -> Result<(Uuid, [u8; 32], String), CryptoError> {
    let stripped = uri.strip_prefix("secwet://pair?").ok_or(CryptoError)?;
    let mut session_id = None;
    let mut peer_pub = None;
    let mut relay_host = None;

    for param in stripped.split('&') {
        let (k, v) = param.split_once('=').ok_or(CryptoError)?;
        match k {
            "s" => session_id = Uuid::parse_str(v).ok(),
            "k" => {
                if let Ok(bytes) = data_encoding::BASE64URL_NOPAD.decode(v.as_bytes()) {
                    if bytes.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&bytes);
                        peer_pub = Some(arr);
                    }
                }
            }
            "r" => relay_host = Some(v.to_string()),
            _ => {}
        }
    }

    match (session_id, peer_pub, relay_host) {
        (Some(s), Some(k), Some(r)) => Ok((s, k, r)),
        _ => Err(CryptoError),
    }
}

/// Seals device profile using XChaCha20-Poly1305 under HKDF key derived from shared secret.
pub fn seal_pairing_profile(
    shared_secret: &[u8; 32],
    profile: &secwet_proto::PairingProfile,
) -> Result<Vec<u8>, CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
    let mut key = [0u8; 32];
    hkdf.expand(b"secwet/v1/pair-profile", &mut key)
        .map_err(|_| CryptoError)?;

    let serialized = postcard::to_stdvec(profile).map_err(|_| CryptoError)?;
    let cipher = XChaCha20Poly1305::new((&key).into());
    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: &serialized,
                aad: b"secwet-pair-profile",
            },
        )
        .map_err(|_| CryptoError)?;

    let mut out = Vec::with_capacity(24 + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Opens device profile using XChaCha20-Poly1305 under HKDF key derived from shared secret.
pub fn open_pairing_profile(
    shared_secret: &[u8; 32],
    sealed: &[u8],
) -> Result<secwet_proto::PairingProfile, CryptoError> {
    if sealed.len() < 24 + 16 {
        return Err(CryptoError);
    }
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
    let mut key = [0u8; 32];
    hkdf.expand(b"secwet/v1/pair-profile", &mut key)
        .map_err(|_| CryptoError)?;

    let nonce = XNonce::try_from(&sealed[..24]).map_err(|_| CryptoError)?;
    let cipher = XChaCha20Poly1305::new((&key).into());

    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &sealed[24..],
                aad: b"secwet-pair-profile",
            },
        )
        .map_err(|_| CryptoError)?;

    postcard::from_bytes(&plaintext).map_err(|_| CryptoError)
}

/// Computes the 6-digit Short Authentication String (SAS) formatted as "XXX YYY".
pub fn compute_pairing_sas(
    shared_secret: &[u8; 32],
    session_id: &Uuid,
    a_eph_pub: &[u8; 32],
    n_eph_pub: &[u8; 32],
    sign_pub: &[u8; 32],
    enc_pub: &[u8; 32],
) -> Result<String, CryptoError> {
    let transcript_raw = postcard::to_stdvec(&(
        session_id.as_bytes(),
        a_eph_pub,
        n_eph_pub,
        sign_pub,
        enc_pub,
    ))
    .map_err(|_| CryptoError)?;
    let transcript: [u8; 32] = Sha256::digest(&transcript_raw).into();

    let hkdf = Hkdf::<Sha256>::new(Some(session_id.as_bytes()), shared_secret);
    let mut sas_bytes = [0u8; 4];
    hkdf.expand(&transcript, &mut sas_bytes)
        .map_err(|_| CryptoError)?;

    let num = u32::from_be_bytes(sas_bytes) % 1_000_000;
    Ok(format!("{:03} {:03}", num / 1000, num % 1000))
}

/// Wraps all active master keys for a newly approved recipient device.
pub fn wrap_master_keys_for_device(
    master_keys_by_epoch: &[(u32, [u8; 32])],
    recipient_enc_pub: &[u8; 32],
    recipient_device_id: &str,
    secwet_id: &Uuid,
) -> Result<Vec<secwet_proto::WrappedEpochKey>, CryptoError> {
    let mut out = Vec::with_capacity(master_keys_by_epoch.len());
    for (epoch, key) in master_keys_by_epoch {
        let info = secwet_proto::KeyWrapInfo {
            purpose: "secwet/v1/master-key",
            secwet_id: secwet_id.as_bytes(),
            key_epoch: *epoch,
            recipient_device_id,
        };
        let info_bytes = postcard::to_stdvec(&info).map_err(|_| CryptoError)?;
        let wrapped = wrap_for_device(recipient_enc_pub, &info_bytes, key)?;
        out.push(secwet_proto::WrappedEpochKey {
            epoch: *epoch,
            wrapped,
        });
    }
    Ok(out)
}

/// A master key and the epoch it belongs to.
pub type EpochKey = (u32, Zeroizing<[u8; 32]>);

/// Unwraps received master keys using our private X25519 encryption key.
pub fn unwrap_master_keys_for_me(
    wrapped_keys: &[secwet_proto::WrappedEpochKey],
    my_enc_secret: &StaticSecret,
    my_device_id: &str,
    secwet_id: &Uuid,
) -> Result<Vec<EpochKey>, CryptoError> {
    let mut out = Vec::with_capacity(wrapped_keys.len());
    for item in wrapped_keys {
        let info = secwet_proto::KeyWrapInfo {
            purpose: "secwet/v1/master-key",
            secwet_id: secwet_id.as_bytes(),
            key_epoch: item.epoch,
            recipient_device_id: my_device_id,
        };
        let info_bytes = postcard::to_stdvec(&info).map_err(|_| CryptoError)?;
        let key = unwrap_for_me(my_enc_secret, &info_bytes, &item.wrapped)?;
        out.push((item.epoch, key));
    }
    Ok(out)
}

/// Creates and signs a PairingApproval record.
pub fn create_pairing_approval(
    secwet_id: &Uuid,
    session_id: &Uuid,
    device_id: &str,
    sign_pub: &[u8; 32],
    enc_pub: &[u8; 32],
    signing_key: &SigningKey,
) -> Result<(secwet_proto::PairingApproval, [u8; 64]), CryptoError> {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| CryptoError)?
        .as_millis() as i64;

    let approval = secwet_proto::PairingApproval {
        secwet_id: *secwet_id.as_bytes(),
        session_id: *session_id.as_bytes(),
        device_id: device_id.to_string(),
        sign_pub: *sign_pub,
        enc_pub: *enc_pub,
        approved_at: now_ms,
    };
    let approval_bytes = postcard::to_stdvec(&approval).map_err(|_| CryptoError)?;
    let sig = signing_key.sign(&approval_bytes);
    Ok((approval, sig.to_bytes()))
}

/// Verifies a PairingApproval signature against an authorized device's public key.
pub fn verify_pairing_approval(
    approval: &secwet_proto::PairingApproval,
    signature: &[u8; 64],
    authorized_sign_pub: &[u8; 32],
) -> Result<(), CryptoError> {
    let approval_bytes = postcard::to_stdvec(approval).map_err(|_| CryptoError)?;
    verify_signature_strict_bytes(authorized_sign_pub, &approval_bytes, signature)
}
