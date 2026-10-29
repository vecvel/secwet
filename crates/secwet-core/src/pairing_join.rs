//! The new device's side of pairing.
//!
//! The approving device shows `secwet://pair?v=1&s=<session>&k=<A_eph_pub>&r=<relay>`.
//! This device generates its own identity and an ephemeral X25519 key,
//! posts the join (profile sealed to the shared secret), and shows the
//! 6-digit code. Once the approver compares the codes and approves, the
//! relay hands back the master keys wrapped to this device's encryption
//! key; [`PairingJoin::finish`] opens them and creates the local store.
//! Nothing secret is in the QR, and nothing is stored before approval.

use std::path::Path;

use ed25519_dalek::SigningKey;
use secwet_proto::{PairingJoinRequest, PairingProfile, PairingResultResponse};
use uuid::Uuid;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::crypto::{self, OsRng};
use crate::keys::KeyStore;
use crate::relay_client::RelayClient;
use crate::secwet::Secwet;
use crate::{Error, Result};

/// A join in progress on the new device. Holds the new identity in memory
/// only (zeroized on drop by the dalek types) until [`Self::finish`].
pub struct PairingJoin {
    session_id: Uuid,
    relay_url: String,
    device_name: String,
    device_id: String,
    sign_key: SigningKey,
    enc_secret: StaticSecret,
    code: String,
}

impl std::fmt::Debug for PairingJoin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairingJoin")
            .field("session_id", &self.session_id)
            .field("device_id", &self.device_id)
            .finish_non_exhaustive()
    }
}

/// Polls the relay for the approval of one join.
#[derive(Debug, Clone)]
pub struct PairingPoller {
    session_id: Uuid,
    relay_url: String,
    device_id: String,
}

impl PairingPoller {
    pub fn session_id(&self) -> Uuid {
        self.session_id
    }

    /// The approval with the wrapped keys, or `None` while pending.
    pub async fn poll(&self) -> Result<Option<PairingResultResponse>> {
        RelayClient::new(&self.relay_url, &self.device_id)
            .get_pairing_result(self.session_id)
            .await
    }
}

/// Relay URL from the QR's `r` field: a bare host gets https, except
/// loopback and private addresses used in development. A full URL is used
/// as is when it is https; plain http is accepted only for those local
/// addresses, since anyone can hand the phone a link that names a relay.
fn relay_url_from_host(host: &str) -> Result<String> {
    let host = host.trim().trim_end_matches('/');
    if host.is_empty() || host.chars().any(char::is_whitespace) {
        return Err(invalid_link());
    }
    if host.starts_with("https://") {
        return Ok(host.to_string());
    }
    if let Some(rest) = host.strip_prefix("http://") {
        let authority = rest.split('/').next().unwrap_or_default();
        return if is_local_host(host_name(authority)) {
            Ok(host.to_string())
        } else {
            Err(invalid_link())
        };
    }
    if host.contains("://") {
        return Err(invalid_link());
    }
    let local = is_local_host(host_name(host));
    Ok(format!("{}://{host}", if local { "http" } else { "https" }))
}

/// The host part of `host[:port]` or `[v6]:port`, without userinfo.
fn host_name(authority: &str) -> &str {
    let authority = authority.rsplit('@').next().unwrap_or_default();
    if let Some(v6) = authority.strip_prefix('[') {
        return v6.split(']').next().unwrap_or_default();
    }
    authority.split(':').next().unwrap_or_default()
}

/// Loopback, private (RFC 1918) and link-local mDNS names.
fn is_local_host(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    if name == "localhost" || name == "::1" || name.ends_with(".local") {
        return true;
    }
    match name.parse::<std::net::Ipv4Addr>() {
        Ok(ip) => ip.is_loopback() || ip.is_private(),
        Err(_) => false,
    }
}

fn invalid_link() -> Error {
    Error::Invalid {
        field: "link",
        message: "This pairing code isn't valid. Show a new code on your other device.".into(),
    }
}

impl PairingJoin {
    /// Parses the pairing link, generates this device's keys and joins the
    /// relay session. `platform` is shown on the approving device.
    pub async fn start(link: &str, device_name: &str, platform: &str) -> Result<PairingJoin> {
        let (session_id, a_eph_pub, relay_host) =
            crypto::parse_pairing_qr_payload(link.trim()).map_err(|_| invalid_link())?;
        let relay_url = relay_url_from_host(&relay_host)?;

        let sign_key = SigningKey::generate(&mut OsRng);
        let sign_pub = sign_key.verifying_key().to_bytes();
        let device_id = crypto::compute_device_id(&sign_pub);
        let enc_secret = StaticSecret::random_from_rng(&mut OsRng);
        let enc_pub = X25519PublicKey::from(&enc_secret).to_bytes();

        let (n_eph_secret, n_eph_pub) = crypto::generate_ephemeral_x25519();
        let shared = crypto::compute_pairing_shared_secret(&n_eph_secret, &a_eph_pub).map_err(|_| Error::Crypto)?;

        let name = match device_name.trim() {
            "" => "Phone",
            n => n,
        };
        let profile = PairingProfile {
            name: name.to_string(),
            platform: platform.to_string(),
        };
        let sealed_profile = crypto::seal_pairing_profile(&shared, &profile).map_err(|_| Error::Crypto)?;
        let join = PairingJoinRequest {
            n_eph_pub,
            sign_pub,
            enc_pub,
            sealed_profile,
        };
        RelayClient::new(&relay_url, &device_id)
            .join_pairing_session(session_id, &join)
            .await?;

        let code = crypto::compute_pairing_sas(&shared, &session_id, &a_eph_pub, &n_eph_pub, &sign_pub, &enc_pub)
            .map_err(|_| Error::Crypto)?;

        Ok(PairingJoin {
            session_id,
            relay_url,
            device_name: name.to_string(),
            device_id,
            sign_key,
            enc_secret,
            code,
        })
    }

    /// The 6-digit code to compare with the approving device.
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Fingerprint of this device's new keys, as the approver shows it.
    pub fn fingerprint(&self) -> String {
        let enc_pub = X25519PublicKey::from(&self.enc_secret).to_bytes();
        crypto::compute_fingerprint(&self.sign_key.verifying_key().to_bytes(), &enc_pub)
    }

    pub fn session_id(&self) -> Uuid {
        self.session_id
    }

    /// A handle for polling the relay without holding this join, so it can
    /// stay in a lock while the request runs.
    pub fn poller(&self) -> PairingPoller {
        PairingPoller {
            session_id: self.session_id,
            relay_url: self.relay_url.clone(),
            device_id: self.device_id.clone(),
        }
    }

    /// Opens the wrapped master keys and creates this device's store with
    /// the approved identity. The caller syncs afterwards to pull the data.
    pub fn finish(self, data_dir: &Path, result: &PairingResultResponse, keystore: &dyn KeyStore) -> Result<Secwet> {
        if result.device_id != self.device_id {
            return Err(Error::Crypto);
        }
        let mut keys = crypto::unwrap_master_keys_for_me(
            &result.wrapped_keys,
            &self.enc_secret,
            &self.device_id,
            &result.secwet_id,
        )
        .map_err(|_| Error::Crypto)?;
        keys.sort_by_key(|(epoch, _)| *epoch);
        // The relay refuses an approval without every epoch, so epoch 1 is here.
        let first = match keys.first() {
            Some((1, k)) => Zeroizing::new(**k),
            _ => return Err(Error::Crypto),
        };

        let mut secwet = Secwet::create_with_identity(
            data_dir,
            &self.device_name,
            result.secwet_id,
            &first,
            self.sign_key,
            self.enc_secret,
            "pro",
            None,
            keystore,
        )?;
        match adopt_and_link(&mut secwet, &keys[1..], &self.relay_url, keystore) {
            Ok(()) => Ok(secwet),
            Err(e) => {
                let _ = secwet.crypto_shred(keystore);
                Err(e)
            }
        }
    }
}

/// Later key epochs and the relay address, after the store exists.
fn adopt_and_link(
    secwet: &mut Secwet,
    later: &[crypto::EpochKey],
    relay_url: &str,
    keystore: &dyn KeyStore,
) -> Result<()> {
    for (epoch, key) in later {
        secwet.adopt_master_epoch(*epoch, key, keystore)?;
    }
    secwet.set_relay_url(relay_url)
}

#[cfg(test)]
mod tests {
    use super::relay_url_from_host;

    #[test]
    fn relay_url_from_qr_host() {
        assert_eq!(relay_url_from_host("https://relay.example.com/").unwrap(), "https://relay.example.com");
        assert_eq!(relay_url_from_host("http://127.0.0.1:8787").unwrap(), "http://127.0.0.1:8787");
        assert_eq!(relay_url_from_host("relay.example.com").unwrap(), "https://relay.example.com");
        assert_eq!(relay_url_from_host("127.0.0.1:8787").unwrap(), "http://127.0.0.1:8787");
        assert_eq!(relay_url_from_host("localhost:8787").unwrap(), "http://localhost:8787");
        assert_eq!(relay_url_from_host("172.20.0.5:8787").unwrap(), "http://172.20.0.5:8787");
        assert_eq!(relay_url_from_host("http://192.168.1.4:8787").unwrap(), "http://192.168.1.4:8787");
        assert_eq!(relay_url_from_host("http://mac.local:8787/").unwrap(), "http://mac.local:8787");
        assert_eq!(relay_url_from_host("http://[::1]:8787").unwrap(), "http://[::1]:8787");
        // Plain http to the internet: a link anyone can make, refused.
        assert!(relay_url_from_host("http://relay.example.com").is_err());
        assert!(relay_url_from_host("http://8.8.8.8:80").is_err());
        assert!(relay_url_from_host("http://127.0.0.1@evil.example.com").is_err());
        assert!(relay_url_from_host("http://10.0.0.1.evil.example.com").is_err());
        assert!(relay_url_from_host("ftp://relay.example.com").is_err());
        assert!(relay_url_from_host("").is_err());
        assert!(relay_url_from_host("a b").is_err());
    }
}
