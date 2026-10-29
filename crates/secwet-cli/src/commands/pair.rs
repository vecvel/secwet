//! CLI commands for device pairing.

use std::io::{self, Write};
use std::time::Duration;
use clap::{Args, Subcommand};
use ed25519_dalek::SigningKey;
use secwet_core::crypto::{
    compute_device_id, compute_fingerprint, compute_pairing_sas, compute_pairing_shared_secret,
    create_pairing_approval, generate_ephemeral_x25519, open_pairing_profile,
    parse_pairing_qr_payload, seal_pairing_profile, unwrap_master_keys_for_me,
    wrap_master_keys_for_device,
};
use secwet_core::keys::KeyStore;
use secwet_core::secwet::Secwet;
use secwet_core::{Error, RelayClient};
use secwet_proto::{PairingApproveRequest, PairingJoinRequest, PairingProfile};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

#[derive(Args, Debug)]
pub struct PairArgs {
    #[command(subcommand)]
    pub command: PairSubcommand,
}

#[derive(Subcommand, Debug)]
pub enum PairSubcommand {
    /// Start a pairing session on this authorized device
    Start,

    /// Join an existing pairing session from this new device
    Join {
        /// Pairing URI (e.g. secwet://pair?v=1&s=...&k=...&r=...)
        uri: String,

        /// Optional name for this device
        #[arg(long)]
        name: Option<String>,
    },
}

pub async fn handle_pair(
    secwet: Option<&mut Secwet>,
    keystore: &dyn KeyStore,
    args: PairArgs,
) -> Result<(), Error> {
    match args.command {
        PairSubcommand::Start => {
            let secwet = secwet.ok_or(Error::NotInitialized)?;
            // Pairing needs an active Pro plan; Free never calls the relay.
            secwet.ensure_relay_allowed(secwet_core::RelayOp::Sync)?;
            let secwet_id = secwet.secwet_id();
            let relay_url = secwet.relay_url()?;
            let device_id = secwet.device_id().0;
            let sign_key = secwet.device_sign_key().clone();

            let (a_eph_secret, a_eph_pub) = generate_ephemeral_x25519();
            let client = RelayClient::new(&relay_url, &device_id);

            println!("Creating pairing session on relay ({})...", relay_url);
            let session_resp = client
                .create_pairing_session(secwet_id, a_eph_pub, &sign_key)
                .await?;

            let session_id = session_resp.session_id;

            println!("\n=======================================================");
            println!("               SECWET DEVICE PAIRING");
            println!("=======================================================");
            println!("Scan or enter this pairing link on the new device:\n");
            println!("  {}", session_resp.qr_payload);
            println!("\nWaiting for the new device to join (expires in 5 minutes)...");

            // Poll loop for peer join
            let start = std::time::Instant::now();
            let timeout = Duration::from_secs(300);

            loop {
                if start.elapsed() > timeout {
                    println!("\nPairing session expired.");
                    return Err(Error::Relay {
                        code: "expired".into(),
                    });
                }

                tokio::time::sleep(Duration::from_millis(1500)).await;

                let status_resp = match client.get_pairing_status(session_id, &sign_key).await {
                    Ok(s) => s,
                    Err(_) => continue,
                };

                if status_resp.status == "joined" {
                    if let Some(join_req) = status_resp.join_payload {
                        let shared = compute_pairing_shared_secret(&a_eph_secret, &join_req.n_eph_pub)
                            .map_err(|_| Error::Crypto)?;

                        let profile = open_pairing_profile(&shared, &join_req.sealed_profile)
                            .map_err(|_| Error::Crypto)?;

                        let sas = compute_pairing_sas(
                            &shared,
                            &session_id,
                            &a_eph_pub,
                            &join_req.n_eph_pub,
                            &join_req.sign_pub,
                            &join_req.enc_pub,
                        )
                        .map_err(|_| Error::Crypto)?;

                        let fingerprint = compute_fingerprint(&join_req.sign_pub, &join_req.enc_pub);
                        let peer_device_id = compute_device_id(&join_req.sign_pub);

                        println!("\n-------------------------------------------------------");
                        println!("New device joined!");
                        println!("  Device Name: {}", profile.name);
                        println!("  Platform:    {}", profile.platform);
                        println!("  Fingerprint: {}", fingerprint);
                        println!("\n  COMPARISON CODE: {}", sas);
                        println!("-------------------------------------------------------");

                        print!("Do both screens show the same 6-digit code? [y/N]: ");
                        io::stdout().flush().map_err(|_| Error::Storage)?;

                        let mut answer = String::new();
                        io::stdin().read_line(&mut answer).map_err(|_| Error::Storage)?;

                        if answer.trim().eq_ignore_ascii_case("y") {
                            println!("Approving pairing and wrapping master keys...");

                            // Every epoch must be wrapped for the new device.
                            let mut master_keys = Vec::new();
                            for ep in 1..=secwet.key_epoch() {
                                let k_vec = secwet_core::collab::load_master_key(keystore, &secwet_id, ep)?
                                    .ok_or(Error::KeyStore)?;
                                let k: [u8; 32] = k_vec.as_slice().try_into().map_err(|_| Error::KeyStore)?;
                                master_keys.push((ep, k));
                            }

                            let wrapped_keys = wrap_master_keys_for_device(
                                &master_keys,
                                &join_req.enc_pub,
                                &peer_device_id,
                                &secwet_id,
                            )
                            .map_err(|_| Error::Crypto)?;

                            let (approval, signature) = create_pairing_approval(
                                &secwet_id,
                                &session_id,
                                &peer_device_id,
                                &join_req.sign_pub,
                                &join_req.enc_pub,
                                &sign_key,
                            )
                            .map_err(|_| Error::Crypto)?;

                            let approve_req = PairingApproveRequest {
                                approval,
                                signature,
                                wrapped_keys,
                            };

                            client.approve_pairing(session_id, &approve_req, &sign_key).await?;

                            // Register in local database
                            secwet.record_paired_device(
                                &peer_device_id,
                                &profile.name,
                                &profile.platform,
                                &join_req.sign_pub,
                                &join_req.enc_pub,
                            )?;

                            println!("Success! Device \"{}\" paired successfully.", profile.name);
                            return Ok(());
                        } else {
                            println!("Pairing cancelled by user.");
                            return Ok(());
                        }
                    }
                }
            }
        }
        PairSubcommand::Join { uri, name } => {
            let (session_id, a_eph_pub, relay_host) =
                parse_pairing_qr_payload(&uri).map_err(|_| Error::Invalid {
                    field: "uri",
                    message: "Invalid pairing QR payload".into(),
                })?;

            let relay_url = if relay_host.starts_with("http://") || relay_host.starts_with("https://") {
                relay_host
            } else {
                format!("http://{}", relay_host)
            };

            // Generate device credentials for this new installation
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed).map_err(|_| Error::Crypto)?;
            let n_sign_key = SigningKey::from_bytes(&seed);
            let n_sign_pub = n_sign_key.verifying_key().to_bytes();
            let n_device_id = compute_device_id(&n_sign_pub);

            let mut enc_seed = [0u8; 32];
            getrandom::fill(&mut enc_seed).map_err(|_| Error::Crypto)?;
            let n_enc_secret = StaticSecret::from(enc_seed);
            let n_enc_pub = X25519PublicKey::from(&n_enc_secret).to_bytes();

            let (n_eph_secret, n_eph_pub) = generate_ephemeral_x25519();
            let n_shared = compute_pairing_shared_secret(&n_eph_secret, &a_eph_pub)
                .map_err(|_| Error::Crypto)?;

            let dev_name = name.unwrap_or_else(|| "CLI Device".into());
            let profile = PairingProfile {
                name: dev_name,
                platform: "CLI".into(),
            };
            let sealed_profile = seal_pairing_profile(&n_shared, &profile).map_err(|_| Error::Crypto)?;

            let join_req = PairingJoinRequest {
                n_eph_pub,
                sign_pub: n_sign_pub,
                enc_pub: n_enc_pub,
                sealed_profile,
            };

            let client = RelayClient::new(&relay_url, &n_device_id);
            println!("Connecting to relay at {}...", relay_url);
            client.join_pairing_session(session_id, &join_req).await?;

            let sas = compute_pairing_sas(
                &n_shared,
                &session_id,
                &a_eph_pub,
                &n_eph_pub,
                &n_sign_pub,
                &n_enc_pub,
            )
            .map_err(|_| Error::Crypto)?;

            println!("\n=======================================================");
            println!("               PAIRING COMPARISON CODE");
            println!("=======================================================");
            println!("\n  COMPARISON CODE: {}", sas);
            println!("\nConfirm this code matches on your primary device.");
            println!("Waiting for approval on primary device...");

            let start = std::time::Instant::now();
            let timeout = Duration::from_secs(300);

            loop {
                if start.elapsed() > timeout {
                    println!("\nPairing timed out.");
                    return Err(Error::Relay {
                        code: "expired".into(),
                    });
                }

                tokio::time::sleep(Duration::from_millis(1500)).await;

                match client.get_pairing_result(session_id).await {
                    Ok(Some(res)) => {
                        println!("\nApproval received! Unwrapping master keys...");
                        let unwrapped = unwrap_master_keys_for_me(
                            &res.wrapped_keys,
                            &n_enc_secret,
                            &n_device_id,
                            &res.secwet_id,
                        )
                        .map_err(|_| Error::Crypto)?;

                        // Store keys in keystore
                        for (epoch, k_v) in unwrapped {
                            keystore.set(
                                &format!("secwet/{}/master-key/{}", res.secwet_id, epoch),
                                k_v.as_slice(),
                            )?;
                        }
                        keystore.set(
                            &format!("secwet/{}/device-sign", res.secwet_id),
                            &n_sign_pub,
                        )?;
                        keystore.set(
                            &format!("secwet/{}/device-enc", res.secwet_id),
                            &n_enc_pub,
                        )?;

                        println!("Pairing complete! Device {} is now registered.", n_device_id);
                        return Ok(());
                    }
                    Ok(None) => continue,
                    Err(err) => {
                        println!("\nPairing rejected: {:?}", err);
                        return Err(err);
                    }
                }
            }
        }
    }
}
