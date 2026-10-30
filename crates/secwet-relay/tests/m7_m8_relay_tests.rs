//! Device revocation, master key rotation and collaboration (tree-wise
//! RBAC, branch keys, invitations) relay test suite.
//!
//! Every signature is a real Ed25519 signature, every wrapped key a real HPKE
//! wrap. Requests are built by hand (with signed headers) so the suite
//! exercises the relay's wire contract directly.

use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::{Signer, SigningKey};
use reqwest::{
    header::{HeaderMap, HeaderValue},
    Method, StatusCode,
};
use secwet_core::crypto::{
    compute_device_id, create_pairing_approval, derive_hkdf_sha256, unwrap_for_me,
    verify_signature_strict_bytes, wrap_for_device, wrap_master_keys_for_device,
};
use secwet_proto::{
    canonical_registration_proof_bytes, canonical_request_bytes, AcceptInvitationRequest,
    AcceptInvitationResponse, AccessResponse, AckEventsRequest, BranchKeysResponse,
    BranchKeyDigest, BranchPublishStatement, BranchScopeDto, DeviceCertificate,
    DeviceCertificates, SignedDeviceCertificate, DeviceListResponse, DeviceWrappedKey, EventEnvelope,
    EventScope, InvitationDto, PairingApproveRequest, PairingJoinRequest, CreatePairingSessionRequest,
    CreatePairingSessionResponse, InvitationStatus, InviteCollaboratorRequest, KeyRotationRequest,
    KeyRotationResponse, KeyRotationStatement, KeyWrapInfo, MemberDto, MemberGrant,
    MemberGrantSet, MemberStatus, MembersResponse, PublishBranchKeysRequest, PullEventsResponse,
    PushEventsRequest, PushEventsResponse, RegisterSecwetRequest, RelayError, RelayErrorCode,
    RemoveMemberRequest, RevocationDirective, RevokeRequest, RevokeResponse, ScopeOp,
    ScopeTarget, ScopedBranchKey, SignedEvent, SignedGrantSet, SignedRevocation,
    SnapshotUploadRequest, TreeNode, TreeRole, UpdateMemberGrantsRequest, WrappedKeysResponse,
    HEADER_DEVICE, HEADER_NONCE, HEADER_SIGNATURE, HEADER_TIME, INVITATION_TTL_MS,
};
use secwet_relay::{
    create_router,
    db::{self, create_pool, run_migrations},
    rate_limit::RateLimitManager,
    sqlx::{PgPool, Row},
    AppState, RelayConfig,
};
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::OnceCell,
};
use uuid::Uuid;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

static MIGRATION_ONCE: OnceCell<()> = OnceCell::const_new();

// ============================================================================
// Harness
// ============================================================================

struct Relay {
    base: String,
    port: u16,
    pool: PgPool,
    http: reqwest::Client,
}

async fn start_relay() -> Relay {
    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://secwet:secwet@localhost:5432/secwet_relay".into());
    let pool = create_pool(&db_url).await.expect("connect to test Postgres");
    MIGRATION_ONCE
        .get_or_init(|| async {
            run_migrations(&pool).await.expect("run migrations");
        })
        .await;

    let mut config = RelayConfig::from_env();
    config.database_url = db_url;
    config.default_device_limit = 5;
    let state = AppState::new(pool.clone(), config, RateLimitManager::new());
    let router = create_router(Arc::new(state));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });

    Relay {
        base: format!("http://{addr}"),
        port: addr.port(),
        pool,
        http: reqwest::Client::new(),
    }
}

struct Device {
    sk: SigningKey,
    sign_pub: [u8; 32],
    enc_secret: StaticSecret,
    enc_pub: [u8; 32],
    id: String,
}

impl Device {
    fn new() -> Self {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("seed");
        let sk = SigningKey::from_bytes(&seed);
        let sign_pub = sk.verifying_key().to_bytes();
        let mut enc_seed = [0u8; 32];
        getrandom::fill(&mut enc_seed).expect("enc seed");
        let enc_secret = StaticSecret::from(enc_seed);
        let enc_pub = X25519PublicKey::from(&enc_secret).to_bytes();
        Self {
            id: compute_device_id(&sign_pub),
            sk,
            sign_pub,
            enc_secret,
            enc_pub,
        }
    }

    fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.sk.sign(msg).to_bytes()
    }
}

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).expect("random");
    out
}

fn signed_headers(method: &str, path: &str, body: &[u8], dev: &Device) -> HeaderMap {
    let time_ms = now_ms();
    let nonce: [u8; 16] = random_bytes();
    let body_hash: [u8; 32] = Sha256::digest(body).into();
    let canonical =
        canonical_request_bytes(method, path, time_ms, &nonce, &body_hash).expect("canonical");
    let sig = dev.sk.sign(&canonical).to_bytes();

    let mut h = HeaderMap::new();
    h.insert(HEADER_DEVICE, HeaderValue::from_str(&dev.id).unwrap());
    h.insert(HEADER_TIME, HeaderValue::from_str(&time_ms.to_string()).unwrap());
    h.insert(HEADER_NONCE, HeaderValue::from_str(&BASE64URL_NOPAD.encode(&nonce)).unwrap());
    h.insert(HEADER_SIGNATURE, HeaderValue::from_str(&BASE64URL_NOPAD.encode(&sig)).unwrap());
    h.insert(reqwest::header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    h
}

/// Raw response of a relay call.
struct Resp {
    status: StatusCode,
    body: Vec<u8>,
}

impl Resp {
    fn ok<T: DeserializeOwned>(&self) -> T {
        assert!(
            self.status.is_success(),
            "expected success, got {} {}",
            self.status,
            String::from_utf8_lossy(&self.body)
        );
        serde_json::from_slice(&self.body).expect("decode success body")
    }

    fn err(&self) -> RelayError {
        assert!(
            !self.status.is_success(),
            "expected an error, got {} {}",
            self.status,
            String::from_utf8_lossy(&self.body)
        );
        serde_json::from_slice(&self.body).unwrap_or_else(|_| {
            panic!(
                "decode error body ({}): {}",
                self.status,
                String::from_utf8_lossy(&self.body)
            )
        })
    }

    fn expect_err(&self, status: u16, code: RelayErrorCode) -> RelayError {
        let err = self.err();
        assert_eq!(self.status.as_u16(), status, "status for {:?}: {:?}", code, err);
        assert_eq!(err.error.code, code, "code: {:?}", err);
        err
    }
}

impl Relay {
    async fn call_raw(&self, method: Method, path: &str, body: Vec<u8>, dev: Option<&Device>) -> Resp {
        let mut req = self.http.request(method.clone(), format!("{}{}", self.base, path));
        if let Some(dev) = dev {
            req = req.headers(signed_headers(method.as_str(), path, &body, dev));
        } else {
            req = req.header(reqwest::header::CONTENT_TYPE, "application/json");
        }
        let resp = req.body(body).send().await.expect("send");
        Resp {
            status: resp.status(),
            body: resp.bytes().await.expect("body").to_vec(),
        }
    }

    async fn call<B: Serialize>(&self, method: Method, path: &str, body: Option<&B>, dev: &Device) -> Resp {
        let bytes = body.map(|b| serde_json::to_vec(b).unwrap()).unwrap_or_default();
        self.call_raw(method, path, bytes, Some(dev)).await
    }

    async fn get(&self, path: &str, dev: &Device) -> Resp {
        self.call::<()>(Method::GET, path, None, dev).await
    }

    async fn post<B: Serialize>(&self, path: &str, body: &B, dev: &Device) -> Resp {
        self.call(Method::POST, path, Some(body), dev).await
    }

    async fn put<B: Serialize>(&self, path: &str, body: &B, dev: &Device) -> Resp {
        self.call(Method::PUT, path, Some(body), dev).await
    }

    async fn post_unauth<B: Serialize>(&self, path: &str, body: &B) -> Resp {
        self.call_raw(Method::POST, path, serde_json::to_vec(body).unwrap(), None).await
    }
}

/// Registers a Pro workspace with `owner` as its first device.
async fn new_workspace(relay: &Relay, owner: &Device) -> Uuid {
    let secwet_id = Uuid::now_v7();
    let proof_bytes =
        canonical_registration_proof_bytes(&secwet_id, &owner.sign_pub, &owner.enc_pub).unwrap();
    let body = RegisterSecwetRequest {
        secwet_id,
        sign_pub: owner.sign_pub,
        enc_pub: owner.enc_pub,
        proof: owner.sign(&proof_bytes),
    };
    relay.post("/v1/secwets", &body, owner).await.ok::<serde_json::Value>();
    db::grant_entitlement(&relay.pool, secwet_id, "pro", 10, None)
        .await
        .expect("grant pro");
    secwet_id
}

/// Adds another owner device directly (pairing is covered by pairing_tests).
async fn add_owner_device(relay: &Relay, secwet_id: Uuid) -> Device {
    let dev = Device::new();
    db::add_device(&relay.pool, secwet_id, &dev.id, &dev.sign_pub, &dev.enc_pub)
        .await
        .expect("add device");
    dev
}

fn directive(secwet_id: Uuid, issuer: &Device, target: &str, wipe: bool) -> SignedRevocation {
    let directive = RevocationDirective {
        secwet_id,
        target_device_id: target.to_string(),
        issuer_device_id: issuer.id.clone(),
        wipe,
        issued_at: now_ms(),
    };
    let signature = issuer.sign(&directive.signing_bytes().unwrap());
    SignedRevocation { directive, signature }
}

fn revoke_path(secwet_id: Uuid, target: &str) -> String {
    format!("/v1/secwets/{secwet_id}/devices/{target}/revoke")
}

fn wrap_info(purpose: &str, secwet_id: Uuid, epoch: u32, device_id: &str) -> Vec<u8> {
    postcard::to_stdvec(&KeyWrapInfo {
        purpose,
        secwet_id: secwet_id.as_bytes(),
        key_epoch: epoch,
        recipient_device_id: device_id,
    })
    .unwrap()
}

fn rotation_request(
    secwet_id: Uuid,
    issuer: &Device,
    epoch: u32,
    recipients: &[&Device],
    key: &[u8; 32],
) -> KeyRotationRequest {
    let mut ids: Vec<String> = recipients.iter().map(|d| d.id.clone()).collect();
    ids.sort();
    let statement = KeyRotationStatement {
        secwet_id,
        epoch,
        issuer_device_id: issuer.id.clone(),
        recipients: ids,
        key_commitment: *derive_hkdf_sha256(key, secwet_id.as_bytes(), b"secwet/v1/key-commit"),
    };
    let wrapped = recipients
        .iter()
        .map(|d| DeviceWrappedKey {
            device_id: d.id.clone(),
            wrapped: wrap_for_device(
                &d.enc_pub,
                &wrap_info("master-key", secwet_id, epoch, &d.id),
                key,
            )
            .expect("hpke wrap"),
        })
        .collect();
    let signature = issuer.sign(&statement.signing_bytes().unwrap());
    KeyRotationRequest {
        statement,
        signature,
        wrapped,
    }
}

fn grant(node: TreeNode, space: Option<Uuid>, role: TreeRole) -> MemberGrant {
    MemberGrant {
        node,
        space_id: space,
        role,
    }
}

fn space_grant(space: Uuid, role: TreeRole) -> MemberGrant {
    grant(TreeNode::Space(space), Some(space), role)
}

fn signed_grants(
    secwet_id: Uuid,
    member_id: Uuid,
    version: u64,
    grants: Vec<MemberGrant>,
    issuer: &Device,
) -> SignedGrantSet {
    let set = MemberGrantSet {
        secwet_id,
        member_id,
        version,
        grants,
        issuer_device_id: issuer.id.clone(),
        issued_at: now_ms(),
    };
    let signature = issuer.sign(&set.signing_bytes().unwrap());
    SignedGrantSet { set, signature }
}

fn email_hash(secwet_id: Uuid, email: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"secwet-email-v1");
    h.update(secwet_id.as_bytes());
    h.update(email.trim().to_lowercase().as_bytes());
    h.finalize().into()
}

/// Inviter-side secrets of an invitation.
struct Invite {
    invitation_id: Uuid,
    member_id: Uuid,
    token: [u8; 32],
    email: String,
}

impl Invite {
    fn auth(&self) -> [u8; 32] {
        *derive_hkdf_sha256(&self.token, self.invitation_id.as_bytes(), b"secwet/v1/invite-auth")
    }
}

async fn create_invite(
    relay: &Relay,
    secwet_id: Uuid,
    inviter: &Device,
    email: &str,
    grants: Vec<MemberGrant>,
) -> (Invite, Resp) {
    let invite = Invite {
        invitation_id: Uuid::now_v7(),
        member_id: Uuid::now_v7(),
        token: random_bytes(),
        email: email.to_string(),
    };
    let token_hash: [u8; 32] = Sha256::digest(invite.auth()).into();
    let req = InviteCollaboratorRequest {
        invitation_id: invite.invitation_id,
        member_id: invite.member_id,
        email_hash: email_hash(secwet_id, email),
        token_hash,
        expires_at: now_ms() + INVITATION_TTL_MS,
        grants: signed_grants(secwet_id, invite.member_id, 1, grants, inviter),
    };
    let resp = relay
        .post(&format!("/v1/secwets/{secwet_id}/invitations"), &req, inviter)
        .await;
    (invite, resp)
}

fn accept_request(secwet_id: Uuid, invite: &Invite, dev: &Device, email: &str) -> AcceptInvitationRequest {
    let mut binding_info = b"secwet/v1/invite-binding".to_vec();
    binding_info.extend_from_slice(&dev.sign_pub);
    binding_info.extend_from_slice(&dev.enc_pub);
    let binding = *derive_hkdf_sha256(&invite.token, invite.invitation_id.as_bytes(), &binding_info);
    let proof_bytes = AcceptInvitationRequest::signing_bytes(
        &invite.invitation_id,
        &secwet_id,
        &dev.sign_pub,
        &dev.enc_pub,
        &binding,
    )
    .unwrap();
    AcceptInvitationRequest {
        secwet_id,
        email_hash: email_hash(secwet_id, email),
        auth: invite.auth(),
        sign_pub: dev.sign_pub,
        enc_pub: dev.enc_pub,
        binding,
        proof: dev.sign(&proof_bytes),
    }
}

fn accept_path(invite: &Invite) -> String {
    format!("/v1/invitations/{}/accept", invite.invitation_id)
}

/// Invites, accepts and activates a member; returns its device and member id.
async fn onboard_member(
    relay: &Relay,
    secwet_id: Uuid,
    owner: &Device,
    grants: Vec<MemberGrant>,
) -> (Device, Uuid) {
    let email = format!("member-{}@example.test", Uuid::now_v7());
    let (invite, resp) = create_invite(relay, secwet_id, owner, &email, grants).await;
    resp.ok::<InvitationDto>();
    let dev = Device::new();
    let accepted: AcceptInvitationResponse = relay
        .post_unauth(&accept_path(&invite), &accept_request(secwet_id, &invite, &dev, &email))
        .await
        .ok();
    assert_eq!(accepted.device_id, dev.id);
    relay
        .post(
            &format!("/v1/secwets/{secwet_id}/invitations/{}/activate", invite.invitation_id),
            &serde_json::json!({}),
            owner,
        )
        .await
        .ok::<InvitationDto>();
    (dev, invite.member_id)
}

fn event(
    secwet_id: Uuid,
    dev: &Device,
    seq: u64,
    scope: Option<EventScope>,
) -> SignedEvent {
    event_at(secwet_id, dev, seq, scope, 1)
}

fn event_at(
    secwet_id: Uuid,
    dev: &Device,
    seq: u64,
    scope: Option<EventScope>,
    key_epoch: u32,
) -> SignedEvent {
    let envelope = EventEnvelope {
        event_id: random_bytes(),
        secwet_id: *secwet_id.as_bytes(),
        device_id: dev.id.clone(),
        device_seq: seq,
        key_epoch,
        nonce: random_bytes(),
        ciphertext: random_bytes::<48>().to_vec(),
        scope,
    };
    let signature = dev.sign(&envelope.signing_bytes().unwrap());
    SignedEvent { envelope, signature }
}

fn content_scope(space: Uuid, op: ScopeOp) -> EventScope {
    EventScope {
        space_id: space,
        path: vec![Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7()],
        target: ScopeTarget::Content,
        op,
    }
}

async fn push(relay: &Relay, secwet_id: Uuid, dev: &Device, events: Vec<SignedEvent>) -> Resp {
    relay
        .post(&format!("/v1/secwets/{secwet_id}/events"), &PushEventsRequest { events }, dev)
        .await
}

async fn pull_all(relay: &Relay, secwet_id: Uuid, dev: &Device) -> PullEventsResponse {
    relay
        .get(&format!("/v1/secwets/{secwet_id}/events?after=0&limit=500"), dev)
        .await
        .ok()
}

fn publish_request(
    secwet_id: Uuid,
    space: Uuid,
    epoch: u32,
    rotate: bool,
    issuer: &Device,
    recipients: &[&Device],
) -> PublishBranchKeysRequest {
    let keys: Vec<ScopedBranchKey> = recipients
        .iter()
        .map(|d| {
            let bundle_key: [u8; 32] = random_bytes();
            ScopedBranchKey {
                space_id: space,
                epoch,
                device_id: d.id.clone(),
                wrapped: wrap_for_device(
                    &d.enc_pub,
                    &wrap_info("branch-bundle", secwet_id, epoch, &d.id),
                    &bundle_key,
                )
                .expect("hpke wrap"),
                sealed_bundle: random_bytes::<96>().to_vec(),
                statement: None,
            }
        })
        .collect();
    sign_publish(secwet_id, space, epoch, rotate, issuer, keys)
}

/// Signs a publish over exactly `keys` (digests sorted by device id).
fn sign_publish(
    secwet_id: Uuid,
    space: Uuid,
    epoch: u32,
    rotate: bool,
    issuer: &Device,
    keys: Vec<ScopedBranchKey>,
) -> PublishBranchKeysRequest {
    let mut digests: Vec<BranchKeyDigest> = keys
        .iter()
        .map(|k| BranchKeyDigest {
            device_id: k.device_id.clone(),
            digest: Sha256::digest(k.digest_input().unwrap()).into(),
        })
        .collect();
    digests.sort_by(|a, b| a.device_id.cmp(&b.device_id));
    let statement = BranchPublishStatement {
        secwet_id,
        space_id: space,
        epoch,
        rotate,
        issuer_device_id: issuer.id.clone(),
        digests,
    };
    let signature = issuer.sign(&statement.signing_bytes().unwrap());
    PublishBranchKeysRequest {
        statement,
        signature,
        keys,
    }
}

/// Shares `space` at branch epoch 1 with the owner device only.
async fn share_space(relay: &Relay, secwet_id: Uuid, owner: &Device, space: Uuid) {
    relay
        .post(
            &format!("/v1/secwets/{secwet_id}/spaces/{space}/keys"),
            &publish_request(secwet_id, space, 1, true, owner, &[owner]),
            owner,
        )
        .await
        .ok::<BranchScopeDto>();
}

/// Opens an authenticated WebSocket stream for `dev`; returns the socket after
/// the 101 handshake.
async fn open_stream(relay: &Relay, secwet_id: Uuid, dev: &Device) -> (TcpStream, String) {
    let path = format!("/v1/secwets/{secwet_id}/stream");
    let headers = signed_headers("GET", &path, b"", dev);
    let mut stream = TcpStream::connect(("127.0.0.1", relay.port)).await.expect("tcp");
    let mut req = format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n",
        relay.port
    );
    for name in [HEADER_DEVICE, HEADER_TIME, HEADER_NONCE, HEADER_SIGNATURE] {
        req.push_str(&format!("{}: {}\r\n", name, headers[name].to_str().unwrap()));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await.expect("handshake");
    let mut buf = [0u8; 2048];
    let n = stream.read(&mut buf).await.expect("handshake response");
    (stream, String::from_utf8_lossy(&buf[..n]).to_string())
}

async fn member_status(pool: &PgPool, secwet_id: Uuid, member_id: Uuid) -> String {
    secwet_relay::sqlx::query_scalar::<_, String>(
        "SELECT status FROM workspace_members WHERE secwet_id = $1 AND member_id = $2",
    )
    .bind(secwet_id)
    .bind(member_id)
    .fetch_one(pool)
    .await
    .expect("member status")
}

// ============================================================================
// Revocation
// ============================================================================

#[tokio::test]
async fn revoke_happy_path_stores_wipe_and_delivers_directive() {
    let relay = start_relay().await;
    let owner = Device::new();
    let secwet_id = new_workspace(&relay, &owner).await;
    let laptop = add_owner_device(&relay, secwet_id).await;

    let rev = directive(secwet_id, &owner, &laptop.id, true);
    let resp: RevokeResponse = relay
        .post(
            &revoke_path(secwet_id, &laptop.id),
            &RevokeRequest { wipe: true, revocation: rev.clone() },
            &owner,
        )
        .await
        .ok();
    assert_eq!(resp.device_id, laptop.id);
    assert!(resp.wipe_requested);
    assert!((resp.revoked_at - now_ms()).abs() < 60_000);

    // Stored: revoked_at, wipe flag, the signed directive.
    let row = db::get_device(&relay.pool, &laptop.id).await.unwrap().unwrap();
    assert!(row.revoked_at.is_some());
    assert!(row.wipe_requested);
    let stored: SignedRevocation = postcard::from_bytes(row.revocation.as_deref().unwrap()).unwrap();
    assert_eq!(stored, rev);

    // The device list mirrors the revocation.
    let list: DeviceListResponse = relay
        .get(&format!("/v1/secwets/{secwet_id}/devices"), &owner)
        .await
        .ok();
    assert_eq!(list.current_epoch, 1);
    let dto = list.devices.iter().find(|d| d.id == laptop.id).unwrap();
    assert!(dto.revoked_at.is_some() && dto.wipe_requested && dto.member_id.is_none());

    // Next signed request of the revoked device: 403 revoked + directive.
    let err = relay
        .get(&format!("/v1/secwets/{secwet_id}/entitlement"), &laptop)
        .await
        .expect_err(403, RelayErrorCode::Revoked);
    assert_eq!(err.revocation, Some(rev));
}

#[tokio::test]
async fn revoked_device_unsigned_or_forged_request_gets_no_directive() {
    let relay = start_relay().await;
    let owner = Device::new();
    let secwet_id = new_workspace(&relay, &owner).await;
    let laptop = add_owner_device(&relay, secwet_id).await;
    relay
        .post(
            &revoke_path(secwet_id, &laptop.id),
            &RevokeRequest { wipe: false, revocation: directive(secwet_id, &owner, &laptop.id, false) },
            &owner,
        )
        .await
        .ok::<RevokeResponse>();

    // Unsigned: only the device header.
    let resp = relay
        .http
        .get(format!("{}/v1/secwets/{secwet_id}/entitlement", relay.base))
        .header(HEADER_DEVICE, &laptop.id)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let err: RelayError = resp.json().await.unwrap();
    assert_eq!(err.error.code, RelayErrorCode::Revoked);
    assert!(err.revocation.is_none(), "unsigned request must not receive the directive");

    // Signed with somebody else's key under the revoked id.
    let impostor = Device { id: laptop.id.clone(), ..Device::new() };
    let err = relay
        .get(&format!("/v1/secwets/{secwet_id}/entitlement"), &impostor)
        .await
        .expect_err(403, RelayErrorCode::Revoked);
    assert!(err.revocation.is_none(), "badly signed request must not receive the directive");

    // The genuine device does receive it, with wipe = false.
    let err = relay
        .get(&format!("/v1/secwets/{secwet_id}/entitlement"), &laptop)
        .await
        .expect_err(403, RelayErrorCode::Revoked);
    assert!(!err.revocation.expect("directive").directive.wipe);
}

#[tokio::test]
async fn cannot_revoke_self() {
    let relay = start_relay().await;
    let owner = Device::new();
    let secwet_id = new_workspace(&relay, &owner).await;
    relay
        .post(
            &revoke_path(secwet_id, &owner.id),
            &RevokeRequest { wipe: false, revocation: directive(secwet_id, &owner, &owner.id, false) },
            &owner,
        )
        .await
        .expect_err(400, RelayErrorCode::CannotRevokeSelf);
}

#[tokio::test]
async fn replayed_revoke_is_already_revoked_and_bad_directives_fail() {
    let relay = start_relay().await;
    let owner = Device::new();
    let secwet_id = new_workspace(&relay, &owner).await;
    let laptop = add_owner_device(&relay, secwet_id).await;
    let phone = add_owner_device(&relay, secwet_id).await;

    // Directive signed by a different key than the caller's.
    let mut forged = directive(secwet_id, &owner, &laptop.id, true);
    forged.signature = phone.sign(&forged.directive.signing_bytes().unwrap());
    relay
        .post(&revoke_path(secwet_id, &laptop.id), &RevokeRequest { wipe: true, revocation: forged }, &owner)
        .await
        .expect_err(401, RelayErrorCode::BadSignature);

    // Directive naming another target than the path.
    relay
        .post(
            &revoke_path(secwet_id, &laptop.id),
            &RevokeRequest { wipe: true, revocation: directive(secwet_id, &owner, &phone.id, true) },
            &owner,
        )
        .await
        .expect_err(401, RelayErrorCode::BadSignature);

    // Stale directive (outside the 60 s window).
    let mut stale = directive(secwet_id, &owner, &laptop.id, true);
    stale.directive.issued_at -= 5 * 60_000;
    stale.signature = owner.sign(&stale.directive.signing_bytes().unwrap());
    relay
        .post(&revoke_path(secwet_id, &laptop.id), &RevokeRequest { wipe: true, revocation: stale }, &owner)
        .await
        .expect_err(401, RelayErrorCode::BadSignature);

    // Unknown target.
    relay
        .post(
            &revoke_path(secwet_id, "UNKNOWNDEVICE000000000000A"),
            &RevokeRequest {
                wipe: false,
                revocation: directive(secwet_id, &owner, "UNKNOWNDEVICE000000000000A", false),
            },
            &owner,
        )
        .await
        .expect_err(404, RelayErrorCode::NotFound);

    // Valid, then replayed byte-for-byte (fresh request nonce).
    let body = RevokeRequest { wipe: true, revocation: directive(secwet_id, &owner, &laptop.id, true) };
    relay.post(&revoke_path(secwet_id, &laptop.id), &body, &owner).await.ok::<RevokeResponse>();
    relay
        .post(&revoke_path(secwet_id, &laptop.id), &body, &owner)
        .await
        .expect_err(409, RelayErrorCode::AlreadyRevoked);
}

#[tokio::test]
async fn member_device_cannot_revoke_owner_device() {
    let relay = start_relay().await;
    let owner = Device::new();
    let secwet_id = new_workspace(&relay, &owner).await;
    let space = Uuid::now_v7();
    let (member_dev, _) =
        onboard_member(&relay, secwet_id, &owner, vec![space_grant(space, TreeRole::Admin)]).await;

    relay
        .post(
            &revoke_path(secwet_id, &owner.id),
            &RevokeRequest { wipe: true, revocation: directive(secwet_id, &member_dev, &owner.id, true) },
            &member_dev,
        )
        .await
        .expect_err(403, RelayErrorCode::Forbidden);
    assert!(db::get_device(&relay.pool, &owner.id).await.unwrap().unwrap().revoked_at.is_none());
}

#[tokio::test]
async fn revoked_device_rejected_on_every_endpoint_and_stream_closed() {
    let relay = start_relay().await;
    let owner = Device::new();
    let secwet_id = new_workspace(&relay, &owner).await;
    let laptop = add_owner_device(&relay, secwet_id).await;

    // Open stream for the laptop, then revoke it: the stream receives
    // {"type":"revoked","server_seq":0} and is closed.
    let (mut stream, handshake) = open_stream(&relay, secwet_id, &laptop).await;
    assert!(handshake.contains("101 Switching Protocols"), "{handshake}");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    relay
        .post(
            &revoke_path(secwet_id, &laptop.id),
            &RevokeRequest { wipe: false, revocation: directive(secwet_id, &owner, &laptop.id, false) },
            &owner,
        )
        .await
        .ok::<RevokeResponse>();

    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("stream notified in time")
        .expect("read frame");
    assert!(n > 2);
    assert_eq!(buf[0], 0x81, "unmasked text frame");
    let payload = String::from_utf8_lossy(&buf[2..2 + buf[1] as usize]);
    assert!(payload.contains(r#""type":"revoked""#), "{payload}");
    assert!(payload.contains(r#""server_seq":0"#), "{payload}");
    // Close frame follows (possibly in the same read).
    let mut rest = buf[2 + buf[1] as usize..n].to_vec();
    if rest.is_empty() {
        let mut more = vec![0u8; 64];
        let m = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut more))
            .await
            .expect("close in time")
            .expect("read close");
        rest = more[..m].to_vec();
    }
    assert!(rest.is_empty() || rest[0] == 0x88, "close frame or EOF expected");

    // Every authenticated endpoint now refuses the device.
    let ev = event(secwet_id, &laptop, 1, None);
    push(&relay, secwet_id, &laptop, vec![ev]).await.expect_err(403, RelayErrorCode::Revoked);
    relay
        .get(&format!("/v1/secwets/{secwet_id}/events?after=0"), &laptop)
        .await
        .expect_err(403, RelayErrorCode::Revoked);
    relay
        .get(&format!("/v1/secwets/{secwet_id}/keys"), &laptop)
        .await
        .expect_err(403, RelayErrorCode::Revoked);
    relay
        .post(
            &format!("/v1/secwets/{secwet_id}/keys"),
            &rotation_request(secwet_id, &laptop, 2, &[&owner], &random_bytes()),
            &laptop,
        )
        .await
        .expect_err(403, RelayErrorCode::Revoked);
    relay
        .get(&format!("/v1/secwets/{secwet_id}/devices"), &laptop)
        .await
        .expect_err(403, RelayErrorCode::Revoked);
    relay
        .get(&format!("/v1/secwets/{secwet_id}/branch-keys"), &laptop)
        .await
        .expect_err(403, RelayErrorCode::Revoked);
    relay
        .post(&format!("/v1/secwets/{secwet_id}/ack"), &AckEventsRequest { server_seq: 1 }, &laptop)
        .await
        .expect_err(403, RelayErrorCode::Revoked);

    // A new stream cannot be opened.
    let (_s, handshake) = open_stream(&relay, secwet_id, &laptop).await;
    assert!(handshake.starts_with("HTTP/1.1 403"), "{handshake}");
}

// ============================================================================
// Master key rotation
// ============================================================================

#[tokio::test]
async fn rotation_happy_path_and_keys_catch_up() {
    let relay = start_relay().await;
    let owner = Device::new();
    let secwet_id = new_workspace(&relay, &owner).await;
    let laptop = add_owner_device(&relay, secwet_id).await;

    let k2: [u8; 32] = random_bytes();
    let resp: KeyRotationResponse = relay
        .post(
            &format!("/v1/secwets/{secwet_id}/keys"),
            &rotation_request(secwet_id, &owner, 2, &[&owner, &laptop], &k2),
            &owner,
        )
        .await
        .ok();
    assert_eq!(resp.epoch, 2);

    let k3: [u8; 32] = random_bytes();
    relay
        .post(
            &format!("/v1/secwets/{secwet_id}/keys"),
            &rotation_request(secwet_id, &laptop, 3, &[&owner, &laptop], &k3),
            &laptop,
        )
        .await
        .ok::<KeyRotationResponse>();

    // Catch-up: the laptop fetches its wrapped keys and unwraps every epoch.
    let keys: WrappedKeysResponse =
        relay.get(&format!("/v1/secwets/{secwet_id}/keys"), &laptop).await.ok();
    assert_eq!(keys.current_epoch, 3);
    let epochs: Vec<u32> = keys.keys.iter().map(|k| k.epoch).collect();
    assert_eq!(epochs, vec![2, 3]);
    for (k, expected) in keys.keys.iter().zip([k2, k3]) {
        let plain = unwrap_for_me(
            &laptop.enc_secret,
            &wrap_info("master-key", secwet_id, k.epoch, &laptop.id),
            &k.wrapped,
        )
        .expect("unwrap");
        assert_eq!(*plain, expected);
    }

    let list: DeviceListResponse =
        relay.get(&format!("/v1/secwets/{secwet_id}/devices"), &owner).await.ok();
    assert_eq!(list.current_epoch, 3);

    // Skipping an epoch is an epoch conflict.
    relay
        .post(
            &format!("/v1/secwets/{secwet_id}/keys"),
            &rotation_request(secwet_id, &owner, 5, &[&owner, &laptop], &random_bytes()),
            &owner,
        )
        .await
        .expect_err(409, RelayErrorCode::EpochConflict);
}

#[tokio::test]
async fn rotation_recipients_must_match_active_owner_devices() {
    let relay = start_relay().await;
    let owner = Device::new();
    let secwet_id = new_workspace(&relay, &owner).await;
    let laptop = add_owner_device(&relay, secwet_id).await;
    let old = add_owner_device(&relay, secwet_id).await;
    relay
        .post(
            &revoke_path(secwet_id, &old.id),
            &RevokeRequest { wipe: true, revocation: directive(secwet_id, &owner, &old.id, true) },
            &owner,
        )
        .await
        .ok::<RevokeResponse>();
    let keys_path = format!("/v1/secwets/{secwet_id}/keys");

    // Missing an active owner device.
    relay
        .post(&keys_path, &rotation_request(secwet_id, &owner, 2, &[&owner], &random_bytes()), &owner)
        .await
        .expect_err(400, RelayErrorCode::InvalidRequest);

    // Including the revoked device.
    relay
        .post(
            &keys_path,
            &rotation_request(secwet_id, &owner, 2, &[&owner, &laptop, &old], &random_bytes()),
            &owner,
        )
        .await
        .expect_err(400, RelayErrorCode::InvalidRequest);

    // Including a member device.
    let space = Uuid::now_v7();
    let (member_dev, _) =
        onboard_member(&relay, secwet_id, &owner, vec![space_grant(space, TreeRole::Viewer)]).await;
    relay
        .post(
            &keys_path,
            &rotation_request(secwet_id, &owner, 2, &[&owner, &laptop, &member_dev], &random_bytes()),
            &owner,
        )
        .await
        .expect_err(400, RelayErrorCode::InvalidRequest);

    // Wrapped keys not matching the signed recipients.
    let mut req = rotation_request(secwet_id, &owner, 2, &[&owner, &laptop], &random_bytes());
    req.wrapped.pop();
    relay.post(&keys_path, &req, &owner).await.expect_err(400, RelayErrorCode::InvalidRequest);

    // Bad signature.
    let mut req = rotation_request(secwet_id, &owner, 2, &[&owner, &laptop], &random_bytes());
    req.signature = laptop.sign(&req.statement.signing_bytes().unwrap());
    relay.post(&keys_path, &req, &owner).await.expect_err(401, RelayErrorCode::BadSignature);

    // Member devices never rotate the master key.
    relay
        .post(
            &keys_path,
            &rotation_request(secwet_id, &member_dev, 2, &[&owner, &laptop], &random_bytes()),
            &member_dev,
        )
        .await
        .expect_err(403, RelayErrorCode::Forbidden);

    // Nothing changed.
    assert_eq!(
        relay.get(&keys_path, &owner).await.ok::<WrappedKeysResponse>().current_epoch,
        1
    );
}

#[tokio::test]
async fn concurrent_rotations_exactly_one_wins() {
    let relay = start_relay().await;
    let owner = Device::new();
    let secwet_id = new_workspace(&relay, &owner).await;
    let laptop = add_owner_device(&relay, secwet_id).await;
    let keys_path = format!("/v1/secwets/{secwet_id}/keys");

    let ka: [u8; 32] = random_bytes();
    let kb: [u8; 32] = random_bytes();
    let req_a = rotation_request(secwet_id, &owner, 2, &[&owner, &laptop], &ka);
    let req_b = rotation_request(secwet_id, &laptop, 2, &[&owner, &laptop], &kb);

    let (ra, rb) = tokio::join!(
        relay.post(&keys_path, &req_a, &owner),
        relay.post(&keys_path, &req_b, &laptop)
    );

    let wins = [&ra, &rb].iter().filter(|r| r.status.is_success()).count();
    assert_eq!(wins, 1, "exactly one rotation must win: {} / {}", ra.status, rb.status);
    let (winner_key, loser) = if ra.status.is_success() { (ka, &rb) } else { (kb, &ra) };
    loser.expect_err(409, RelayErrorCode::EpochConflict);

    // The loser adopts the winner's key from GET /keys.
    let loser_dev = if ra.status.is_success() { &laptop } else { &owner };
    let keys: WrappedKeysResponse = relay.get(&keys_path, loser_dev).await.ok();
    assert_eq!(keys.current_epoch, 2);
    assert_eq!(keys.keys.len(), 1);
    let plain = unwrap_for_me(
        &loser_dev.enc_secret,
        &wrap_info("master-key", secwet_id, 2, &loser_dev.id),
        &keys.keys[0].wrapped,
    )
    .unwrap();
    assert_eq!(*plain, winner_key);
}

// ============================================================================
// Invitations
// ============================================================================

#[tokio::test]
async fn invitation_create_accept_and_failure_modes() {
    let relay = start_relay().await;
    let owner = Device::new();
    let secwet_id = new_workspace(&relay, &owner).await;
    let space = Uuid::now_v7();
    let email = format!("Alice.{}@Example.test", Uuid::now_v7());

    let (invite, resp) =
        create_invite(&relay, secwet_id, &owner, &email, vec![space_grant(space, TreeRole::Editor)]).await;
    let dto: InvitationDto = resp.ok();
    assert_eq!(dto.status, InvitationStatus::Pending);
    assert_eq!(dto.created_by, owner.id);

    // Duplicate pending invitation for the same email.
    let (_dup, resp) = create_invite(
        &relay,
        secwet_id,
        &owner,
        &format!("  {}  ", email.to_uppercase()),
        vec![space_grant(space, TreeRole::Viewer)],
    )
    .await;
    resp.expect_err(409, RelayErrorCode::Exists);

    // Invalid grants.
    let (_bad, resp) = create_invite(&relay, secwet_id, &owner, "other@example.test", vec![]).await;
    resp.expect_err(400, RelayErrorCode::InvalidRequest);

    let invitee = Device::new();
    let path = accept_path(&invite);

    // Wrong email.
    relay
        .post_unauth(&path, &accept_request(secwet_id, &invite, &invitee, "mallory@example.test"))
        .await
        .expect_err(403, RelayErrorCode::InvalidInvitation);

    // Wrong auth (token).
    let wrong_token = Invite { token: random_bytes(), ..invite_clone(&invite) };
    relay
        .post_unauth(&path, &accept_request(secwet_id, &wrong_token, &invitee, &email))
        .await
        .expect_err(403, RelayErrorCode::InvalidInvitation);

    // Bad proof signature.
    let mut bad_proof = accept_request(secwet_id, &invite, &invitee, &email);
    bad_proof.proof = owner.sign(b"not the acceptance");
    relay.post_unauth(&path, &bad_proof).await.expect_err(401, RelayErrorCode::BadSignature);

    // Correct acceptance.
    let accepted: AcceptInvitationResponse =
        relay.post_unauth(&path, &accept_request(secwet_id, &invite, &invitee, &email)).await.ok();
    assert_eq!(accepted.secwet_id, secwet_id);
    assert_eq!(accepted.member_id, invite.member_id);
    assert_eq!(accepted.device_id, invitee.id);

    // Replayed acceptance (same or another device).
    relay
        .post_unauth(&path, &accept_request(secwet_id, &invite, &invitee, &email))
        .await
        .expect_err(409, RelayErrorCode::AlreadyJoined);
    relay
        .post_unauth(&path, &accept_request(secwet_id, &invite, &Device::new(), &email))
        .await
        .expect_err(409, RelayErrorCode::AlreadyJoined);

    // The member device is registered with its member id and sees its grants.
    let row = db::get_device(&relay.pool, &invitee.id).await.unwrap().unwrap();
    assert_eq!(row.member_id, Some(invite.member_id));
    let access: AccessResponse =
        relay.get(&format!("/v1/secwets/{secwet_id}/access"), &invitee).await.ok();
    assert_eq!(access.member_id, Some(invite.member_id));
    assert_eq!(access.grants.unwrap().set.grants, vec![space_grant(space, TreeRole::Editor)]);
    let owner_access: AccessResponse =
        relay.get(&format!("/v1/secwets/{secwet_id}/access"), &owner).await.ok();
    assert_eq!(owner_access, AccessResponse { member_id: None, grants: None });

    // Members list (owner): accepted invitation with the binding, invited member.
    let members: MembersResponse =
        relay.get(&format!("/v1/secwets/{secwet_id}/members"), &owner).await.ok();
    let inv = members.invitations.iter().find(|i| i.invitation_id == invite.invitation_id).unwrap();
    assert_eq!(inv.status, InvitationStatus::Accepted);
    let acceptance = inv.acceptance.as_ref().unwrap();
    assert_eq!(acceptance.sign_pub, invitee.sign_pub);
    assert_eq!(acceptance.enc_pub, invitee.enc_pub);
    let m = members.members.iter().find(|m| m.member_id == invite.member_id).unwrap();
    assert_eq!(m.status, MemberStatus::Invited);
    assert_eq!(m.devices.len(), 1);

    // A member device (non-admin) cannot list members.
    relay
        .get(&format!("/v1/secwets/{secwet_id}/members"), &invitee)
        .await
        .expect_err(403, RelayErrorCode::Forbidden);

    // Activation by the inviter.
    let activated: InvitationDto = relay
        .post(
            &format!("/v1/secwets/{secwet_id}/invitations/{}/activate", invite.invitation_id),
            &serde_json::json!({}),
            &owner,
        )
        .await
        .ok();
    assert_eq!(activated.status, InvitationStatus::Active);
    assert_eq!(member_status(&relay.pool, secwet_id, invite.member_id).await, "active");

    // Member devices do not count toward the owner device limit.
    assert_eq!(db::count_active_devices(&relay.pool, secwet_id).await.unwrap(), 1);
}

fn invite_clone(i: &Invite) -> Invite {
    Invite {
        invitation_id: i.invitation_id,
        member_id: i.member_id,
        token: i.token,
        email: i.email.clone(),
    }
}

#[tokio::test]
async fn expired_and_withdrawn_invitations_cannot_be_accepted() {
    let relay = start_relay().await;
    let owner = Device::new();
    let secwet_id = new_workspace(&relay, &owner).await;
    let space = Uuid::now_v7();

    // Expired.
    let email = "expired@example.test";
    let (invite, resp) =
        create_invite(&relay, secwet_id, &owner, email, vec![space_grant(space, TreeRole::Viewer)]).await;
    resp.ok::<InvitationDto>();
    secwet_relay::sqlx::query("UPDATE invitations SET expires_at = now() - interval '1 minute' WHERE id = $1")
        .bind(invite.invitation_id)
        .execute(&relay.pool)
        .await
        .unwrap();
    relay
        .post_unauth(&accept_path(&invite), &accept_request(secwet_id, &invite, &Device::new(), email))
        .await
        .expect_err(403, RelayErrorCode::InvalidInvitation);

    // An expired invitation no longer blocks a new one for the same email.
    let (_again, resp) =
        create_invite(&relay, secwet_id, &owner, email, vec![space_grant(space, TreeRole::Viewer)]).await;
    resp.ok::<InvitationDto>();

    // Withdrawn.
    let email2 = "withdrawn@example.test";
    let (invite2, resp) =
        create_invite(&relay, secwet_id, &owner, email2, vec![space_grant(space, TreeRole::Viewer)]).await;
    resp.ok::<InvitationDto>();
    let dto: InvitationDto = relay
        .call::<()>(
            Method::DELETE,
            &format!("/v1/secwets/{secwet_id}/invitations/{}", invite2.invitation_id),
            None,
            &owner,
        )
        .await
        .ok();
    assert_eq!(dto.status, InvitationStatus::Revoked);
    relay
        .post_unauth(&accept_path(&invite2), &accept_request(secwet_id, &invite2, &Device::new(), email2))
        .await
        .expect_err(403, RelayErrorCode::InvalidInvitation);
    assert_eq!(member_status(&relay.pool, secwet_id, invite2.member_id).await, "removed");

    // Unknown invitation.
    relay
        .call::<()>(
            Method::DELETE,
            &format!("/v1/secwets/{secwet_id}/invitations/{}", Uuid::now_v7()),
            None,
            &owner,
        )
        .await
        .expect_err(404, RelayErrorCode::NotFound);
}

#[tokio::test]
async fn member_admin_scope_limits_invitations() {
    let relay = start_relay().await;
    let owner = Device::new();
    let secwet_id = new_workspace(&relay, &owner).await;
    let space_a = Uuid::now_v7();
    let space_b = Uuid::now_v7();
    let (admin_a, _) =
        onboard_member(&relay, secwet_id, &owner, vec![space_grant(space_a, TreeRole::Admin)]).await;

    // Admin of A may invite into A.
    let (_ok, resp) = create_invite(
        &relay,
        secwet_id,
        &admin_a,
        "a-guest@example.test",
        vec![space_grant(space_a, TreeRole::Viewer)],
    )
    .await;
    resp.ok::<InvitationDto>();

    // ... but not into B, nor at workspace level.
    let (_no, resp) = create_invite(
        &relay,
        secwet_id,
        &admin_a,
        "b-guest@example.test",
        vec![space_grant(space_b, TreeRole::Viewer)],
    )
    .await;
    resp.expect_err(403, RelayErrorCode::Forbidden);
    let (_no, resp) = create_invite(
        &relay,
        secwet_id,
        &admin_a,
        "ws-guest@example.test",
        vec![grant(TreeNode::Workspace, None, TreeRole::Viewer)],
    )
    .await;
    resp.expect_err(403, RelayErrorCode::Forbidden);

    // Grant set issued by another device than the caller.
    let invite_id = Uuid::now_v7();
    let member_id = Uuid::now_v7();
    let req = InviteCollaboratorRequest {
        invitation_id: invite_id,
        member_id,
        email_hash: email_hash(secwet_id, "x@example.test"),
        token_hash: random_bytes(),
        expires_at: now_ms() + INVITATION_TTL_MS,
        grants: signed_grants(secwet_id, member_id, 1, vec![space_grant(space_a, TreeRole::Viewer)], &owner),
    };
    relay
        .post(&format!("/v1/secwets/{secwet_id}/invitations"), &req, &admin_a)
        .await
        .expect_err(400, RelayErrorCode::InvalidRequest);
}

#[tokio::test]
async fn member_grant_update_requires_newer_version() {
    let relay = start_relay().await;
    let owner = Device::new();
    let secwet_id = new_workspace(&relay, &owner).await;
    let space = Uuid::now_v7();
    let (_dev, member_id) =
        onboard_member(&relay, secwet_id, &owner, vec![space_grant(space, TreeRole::Viewer)]).await;
    let path = format!("/v1/secwets/{secwet_id}/members/{member_id}/grants");

    // Same version as stored: stale.
    let stale = UpdateMemberGrantsRequest {
        grants: signed_grants(secwet_id, member_id, 1, vec![space_grant(space, TreeRole::Editor)], &owner),
    };
    relay.put(&path, &stale, &owner).await.expect_err(409, RelayErrorCode::EpochConflict);

    // Newer version.
    let newer = UpdateMemberGrantsRequest {
        grants: signed_grants(secwet_id, member_id, 2, vec![space_grant(space, TreeRole::Editor)], &owner),
    };
    let dto: MemberDto = relay.put(&path, &newer, &owner).await.ok();
    assert_eq!(dto.grants.set.version, 2);
    assert_eq!(dto.grants.set.grants, vec![space_grant(space, TreeRole::Editor)]);

    // Replaying version 2 again is stale too.
    relay.put(&path, &newer, &owner).await.expect_err(409, RelayErrorCode::EpochConflict);

    // Enforcement rows were rebuilt.
    let roles: Vec<String> = secwet_relay::sqlx::query_scalar(
        "SELECT role FROM member_grants WHERE secwet_id = $1 AND member_id = $2",
    )
    .bind(secwet_id)
    .bind(member_id)
    .fetch_all(&relay.pool)
    .await
    .unwrap();
    assert_eq!(roles, vec!["editor".to_string()]);

    // Bad signature.
    let mut forged = UpdateMemberGrantsRequest {
        grants: signed_grants(secwet_id, member_id, 3, vec![space_grant(space, TreeRole::Admin)], &owner),
    };
    forged.grants.signature = Device::new().sign(&forged.grants.set.signing_bytes().unwrap());
    relay.put(&path, &forged, &owner).await.expect_err(401, RelayErrorCode::BadSignature);
}

// ============================================================================
// Scoped events
// ============================================================================

#[tokio::test]
async fn member_push_is_role_checked() {
    let relay = start_relay().await;
    let owner = Device::new();
    let secwet_id = new_workspace(&relay, &owner).await;
    let space = Uuid::now_v7();
    let (viewer, _) =
        onboard_member(&relay, secwet_id, &owner, vec![space_grant(space, TreeRole::Viewer)]).await;
    let (editor, _) =
        onboard_member(&relay, secwet_id, &owner, vec![space_grant(space, TreeRole::Editor)]).await;
    let unrelated = Uuid::now_v7();
    share_space(&relay, secwet_id, &owner, space).await;
    share_space(&relay, secwet_id, &owner, unrelated).await;

    // Viewer: a Write is consumed but rejected.
    let v1 = event(secwet_id, &viewer, 1, Some(content_scope(space, ScopeOp::Write)));
    let resp: PushEventsResponse = push(&relay, secwet_id, &viewer, vec![v1.clone()]).await.ok();
    assert_eq!(resp.accepted, 1);
    assert_eq!(resp.rejected, vec![v1.envelope.event_id]);

    // Retrying the rejected event is rejected again, not a sequence gap.
    let resp: PushEventsResponse = push(&relay, secwet_id, &viewer, vec![v1.clone()]).await.ok();
    assert_eq!(resp.rejected, vec![v1.envelope.event_id]);

    // Editor: Write accepted, Delete and unscoped rejected, Write in another
    // space rejected; the sequence keeps advancing across rejections.
    let w = event(secwet_id, &editor, 1, Some(content_scope(space, ScopeOp::Write)));
    let d = event(secwet_id, &editor, 2, Some(content_scope(space, ScopeOp::Delete)));
    let u = event(secwet_id, &editor, 3, None);
    let other = event(secwet_id, &editor, 4, Some(content_scope(unrelated, ScopeOp::Write)));
    let w2 = event(secwet_id, &editor, 5, Some(content_scope(space, ScopeOp::Write)));
    let resp: PushEventsResponse = push(
        &relay,
        secwet_id,
        &editor,
        vec![w.clone(), d.clone(), u.clone(), other.clone()],
    )
    .await
    .ok();
    assert_eq!(resp.accepted, 4);
    assert_eq!(
        resp.rejected,
        vec![d.envelope.event_id, u.envelope.event_id, other.envelope.event_id]
    );
    let resp: PushEventsResponse = push(&relay, secwet_id, &editor, vec![w2.clone()]).await.ok();
    assert!(resp.rejected.is_empty());

    // A sequence gap is still refused.
    let gap = event(secwet_id, &editor, 9, Some(content_scope(space, ScopeOp::Write)));
    push(&relay, secwet_id, &editor, vec![gap]).await.expect_err(400, RelayErrorCode::SeqGap);

    // Only the permitted writes were stored, with their routing space.
    let stored: Vec<(Vec<u8>, Option<Uuid>)> = secwet_relay::sqlx::query(
        "SELECT event_id, scope_space FROM events WHERE secwet_id = $1 ORDER BY server_seq",
    )
    .bind(secwet_id)
    .fetch_all(&relay.pool)
    .await
    .unwrap()
    .into_iter()
    .map(|r| (r.get("event_id"), r.get("scope_space")))
    .collect();
    assert_eq!(
        stored,
        vec![
            (w.envelope.event_id.to_vec(), Some(space)),
            (w2.envelope.event_id.to_vec(), Some(space)),
        ]
    );

    // Owner devices are unrestricted (unscoped and Delete accepted).
    let o1 = event(secwet_id, &owner, 1, None);
    let o2 = event(secwet_id, &owner, 2, Some(content_scope(space, ScopeOp::Delete)));
    let resp: PushEventsResponse = push(&relay, secwet_id, &owner, vec![o1, o2]).await.ok();
    assert_eq!(resp.accepted, 2);
    assert!(resp.rejected.is_empty());
}

#[tokio::test]
async fn member_pull_only_sees_granted_spaces() {
    let relay = start_relay().await;
    let owner = Device::new();
    let secwet_id = new_workspace(&relay, &owner).await;
    let space_a = Uuid::now_v7();
    let space_b = Uuid::now_v7();
    let (member_a, _) =
        onboard_member(&relay, secwet_id, &owner, vec![space_grant(space_a, TreeRole::Viewer)]).await;
    let (member_ws, _) = onboard_member(
        &relay,
        secwet_id,
        &owner,
        vec![grant(TreeNode::Workspace, None, TreeRole::Viewer)],
    )
    .await;

    share_space(&relay, secwet_id, &owner, space_a).await;
    share_space(&relay, secwet_id, &owner, space_b).await;
    let ea = event(secwet_id, &owner, 1, Some(content_scope(space_a, ScopeOp::Write)));
    let eb = event(secwet_id, &owner, 2, Some(content_scope(space_b, ScopeOp::Write)));
    let eu = event(secwet_id, &owner, 3, None);
    let ea2 = event(secwet_id, &owner, 4, Some(content_scope(space_a, ScopeOp::Container)));
    push(&relay, secwet_id, &owner, vec![ea.clone(), eb.clone(), eu.clone(), ea2.clone()])
        .await
        .ok::<PushEventsResponse>();

    let ids = |r: &PullEventsResponse| -> Vec<[u8; 16]> {
        r.events.iter().map(|e| e.event.envelope.event_id).collect()
    };

    let owner_view = pull_all(&relay, secwet_id, &owner).await;
    assert_eq!(
        ids(&owner_view),
        vec![ea.envelope.event_id, eb.envelope.event_id, eu.envelope.event_id, ea2.envelope.event_id]
    );
    // Scoped events round-trip with their scope and still verify.
    let pulled = &owner_view.events[0].event;
    assert_eq!(pulled.envelope.scope, ea.envelope.scope);
    assert_eq!(pulled, &ea);

    let a_view = pull_all(&relay, secwet_id, &member_a).await;
    assert_eq!(ids(&a_view), vec![ea.envelope.event_id, ea2.envelope.event_id]);

    let ws_view = pull_all(&relay, secwet_id, &member_ws).await;
    assert_eq!(
        ids(&ws_view),
        vec![ea.envelope.event_id, eb.envelope.event_id, ea2.envelope.event_id]
    );

    // Pagination counts only visible events.
    let page: PullEventsResponse = relay
        .get(&format!("/v1/secwets/{secwet_id}/events?after=0&limit=1"), &member_a)
        .await
        .ok();
    assert_eq!(ids(&page), vec![ea.envelope.event_id]);
    assert!(page.has_more);
}

#[tokio::test]
async fn member_cannot_access_snapshot() {
    let relay = start_relay().await;
    let owner = Device::new();
    let secwet_id = new_workspace(&relay, &owner).await;
    let space = Uuid::now_v7();
    let (member_dev, _) =
        onboard_member(&relay, secwet_id, &owner, vec![space_grant(space, TreeRole::Admin)]).await;
    let path = format!("/v1/secwets/{secwet_id}/snapshot");
    let snap = SnapshotUploadRequest {
        server_seq: 0,
        key_epoch: 1,
        nonce: random_bytes(),
        ciphertext: vec![7; 32],
    };
    relay.put(&path, &snap, &owner).await.ok::<serde_json::Value>();
    relay.get(&path, &member_dev).await.expect_err(403, RelayErrorCode::Forbidden);
    relay.put(&path, &snap, &member_dev).await.expect_err(403, RelayErrorCode::Forbidden);
    relay.get(&path, &owner).await.ok::<serde_json::Value>();

    // Member devices cannot pair new (owner) devices either.
    relay
        .post(
            "/v1/pairing",
            &secwet_proto::CreatePairingSessionRequest { secwet_id, a_eph_pub: random_bytes() },
            &member_dev,
        )
        .await
        .expect_err(403, RelayErrorCode::Forbidden);
}

// ============================================================================
// Branch keys
// ============================================================================

#[tokio::test]
async fn branch_key_publish_epochs_and_recipients() {
    let relay = start_relay().await;
    let owner = Device::new();
    let secwet_id = new_workspace(&relay, &owner).await;
    let laptop = add_owner_device(&relay, secwet_id).await;
    let space = Uuid::now_v7();
    let other_space = Uuid::now_v7();
    let (member_dev, _) =
        onboard_member(&relay, secwet_id, &owner, vec![space_grant(space, TreeRole::Editor)]).await;
    let (outsider, _) = onboard_member(
        &relay,
        secwet_id,
        &owner,
        vec![space_grant(other_space, TreeRole::Viewer)],
    )
    .await;
    let path = format!("/v1/secwets/{secwet_id}/spaces/{space}/keys");

    // rotate = false before the space was ever shared: conflict.
    relay
        .post(&path, &publish_request(secwet_id, space, 1, false, &owner, &[&owner]), &owner)
        .await
        .expect_err(409, RelayErrorCode::EpochConflict);

    // First share opens epoch 1.
    let scope: BranchScopeDto = relay
        .post(&path, &publish_request(secwet_id, space, 1, true, &owner, &[&owner, &laptop]), &owner)
        .await
        .ok();
    assert_eq!(scope.current_epoch, 1);

    // rotate = true at epoch 1 again: conflict. Skipping to 3: conflict.
    relay
        .post(&path, &publish_request(secwet_id, space, 1, true, &owner, &[&owner]), &owner)
        .await
        .expect_err(409, RelayErrorCode::EpochConflict);
    relay
        .post(&path, &publish_request(secwet_id, space, 3, true, &owner, &[&owner]), &owner)
        .await
        .expect_err(409, RelayErrorCode::EpochConflict);

    // Adding the member's bundle at the current epoch.
    relay
        .post(&path, &publish_request(secwet_id, space, 1, false, &owner, &[&member_dev]), &owner)
        .await
        .ok::<BranchScopeDto>();
    // rotate = false at a non-current epoch: conflict.
    relay
        .post(&path, &publish_request(secwet_id, space, 2, false, &owner, &[&member_dev]), &owner)
        .await
        .expect_err(409, RelayErrorCode::EpochConflict);

    // A recipient without any grant in this space.
    relay
        .post(&path, &publish_request(secwet_id, space, 1, false, &owner, &[&outsider]), &owner)
        .await
        .expect_err(400, RelayErrorCode::InvalidRequest);

    // Recipients not matching the bundles.
    let mut req = publish_request(secwet_id, space, 1, false, &owner, &[&owner, &laptop]);
    req.keys.pop();
    relay.post(&path, &req, &owner).await.expect_err(400, RelayErrorCode::InvalidRequest);

    // Statement for another space than the path.
    relay
        .post(&path, &publish_request(secwet_id, other_space, 1, false, &owner, &[&owner]), &owner)
        .await
        .expect_err(400, RelayErrorCode::InvalidRequest);

    // Bad signature.
    let mut req = publish_request(secwet_id, space, 1, false, &owner, &[&owner]);
    req.signature = laptop.sign(&req.statement.signing_bytes().unwrap());
    relay.post(&path, &req, &owner).await.expect_err(401, RelayErrorCode::BadSignature);

    // An editor (not admin) cannot publish.
    relay
        .post(
            &path,
            &publish_request(secwet_id, space, 1, false, &member_dev, &[&member_dev]),
            &member_dev,
        )
        .await
        .expect_err(403, RelayErrorCode::Forbidden);

    // Concurrent rotations to epoch 2: exactly one wins.
    let ra_req = publish_request(secwet_id, space, 2, true, &owner, &[&owner, &laptop, &member_dev]);
    let rb_req = publish_request(secwet_id, space, 2, true, &laptop, &[&owner, &laptop]);
    let (ra, rb) = tokio::join!(relay.post(&path, &ra_req, &owner), relay.post(&path, &rb_req, &laptop));
    let wins = [&ra, &rb].iter().filter(|r| r.status.is_success()).count();
    assert_eq!(wins, 1, "{} / {}", ra.status, rb.status);
    let loser = if ra.status.is_success() { &rb } else { &ra };
    loser.expect_err(409, RelayErrorCode::EpochConflict);

    // The member device fetches only its own bundles and only its spaces.
    let keys: BranchKeysResponse =
        relay.get(&format!("/v1/secwets/{secwet_id}/branch-keys"), &member_dev).await.ok();
    assert!(keys.keys.iter().all(|k| k.device_id == member_dev.id && k.space_id == space));
    assert!(keys.keys.iter().any(|k| k.epoch == 1));
    assert_eq!(
        keys.scopes,
        vec![BranchScopeDto { space_id: space, current_epoch: 2, recipients: vec![] }]
    );
    let bundle_key = unwrap_for_me(
        &member_dev.enc_secret,
        &wrap_info("branch-bundle", secwet_id, 1, &member_dev.id),
        &keys.keys.iter().find(|k| k.epoch == 1).unwrap().wrapped,
    );
    assert!(bundle_key.is_ok(), "bundle key unwraps for its recipient");

    let outsider_keys: BranchKeysResponse =
        relay.get(&format!("/v1/secwets/{secwet_id}/branch-keys"), &outsider).await.ok();
    assert!(outsider_keys.keys.is_empty());
    assert!(outsider_keys.scopes.is_empty());

    let owner_keys: BranchKeysResponse =
        relay.get(&format!("/v1/secwets/{secwet_id}/branch-keys"), &owner).await.ok();
    assert!(owner_keys.keys.iter().any(|k| k.epoch == 1));
}

// ============================================================================
// Member removal
// ============================================================================

#[tokio::test]
async fn member_removal_revokes_all_devices() {
    let relay = start_relay().await;
    let owner = Device::new();
    let secwet_id = new_workspace(&relay, &owner).await;
    let space = Uuid::now_v7();
    let (member_dev, member_id) =
        onboard_member(&relay, secwet_id, &owner, vec![space_grant(space, TreeRole::Editor)]).await;
    // A second device of the same member (registered directly; members cannot pair).
    let second = Device::new();
    secwet_relay::sqlx::query(
        "INSERT INTO devices (id, secwet_id, sign_pub, enc_pub, member_id) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&second.id)
    .bind(secwet_id)
    .bind(&second.sign_pub[..])
    .bind(&second.enc_pub[..])
    .bind(member_id)
    .execute(&relay.pool)
    .await
    .unwrap();

    relay
        .post(
            &format!("/v1/secwets/{secwet_id}/spaces/{space}/keys"),
            &publish_request(secwet_id, space, 1, true, &owner, &[&owner, &member_dev, &second]),
            &owner,
        )
        .await
        .ok::<BranchScopeDto>();

    let path = format!("/v1/secwets/{secwet_id}/members/{member_id}/remove");

    // Missing one device's revocation.
    relay
        .post(
            &path,
            &RemoveMemberRequest { revocations: vec![directive(secwet_id, &owner, &member_dev.id, true)] },
            &owner,
        )
        .await
        .expect_err(400, RelayErrorCode::InvalidRequest);

    // A member cannot remove itself.
    relay
        .post(
            &path,
            &RemoveMemberRequest { revocations: vec![directive(secwet_id, &member_dev, &second.id, true)] },
            &member_dev,
        )
        .await
        .expect_err(400, RelayErrorCode::CannotRevokeSelf);

    let dto: MemberDto = relay
        .post(
            &path,
            &RemoveMemberRequest {
                revocations: vec![
                    directive(secwet_id, &owner, &member_dev.id, true),
                    directive(secwet_id, &owner, &second.id, false),
                ],
            },
            &owner,
        )
        .await
        .ok();
    assert_eq!(dto.status, MemberStatus::Removed);
    assert!(dto.removed_at.is_some());
    assert!(dto.devices.iter().all(|d| d.revoked_at.is_some()));
    assert!(dto.devices.iter().find(|d| d.id == member_dev.id).unwrap().wipe_requested);
    assert!(!dto.devices.iter().find(|d| d.id == second.id).unwrap().wipe_requested);

    // Branch key rows of the member are gone; the owner's remain.
    let remaining: Vec<String> = secwet_relay::sqlx::query_scalar(
        "SELECT device_id FROM branch_keys WHERE secwet_id = $1",
    )
    .bind(secwet_id)
    .fetch_all(&relay.pool)
    .await
    .unwrap();
    assert_eq!(remaining, vec![owner.id.clone()]);

    // Member devices are revoked and receive their directive.
    let err = relay
        .get(&format!("/v1/secwets/{secwet_id}/events?after=0"), &member_dev)
        .await
        .expect_err(403, RelayErrorCode::Revoked);
    assert!(err.revocation.unwrap().directive.wipe);

    // Removing again: not found.
    relay
        .post(&path, &RemoveMemberRequest { revocations: vec![] }, &owner)
        .await
        .expect_err(404, RelayErrorCode::NotFound);
}

// ============================================================================
// Zero-knowledge leakage scan over every table, including the collaboration ones
// ============================================================================

#[tokio::test]
async fn relay_never_stores_plaintext_including_collaboration_tables() {
    let relay = start_relay().await;
    let owner = Device::new();
    let secwet_id = new_workspace(&relay, &owner).await;
    let laptop = add_owner_device(&relay, secwet_id).await;
    let space = Uuid::now_v7();

    // Canary email: only ever sent as a salted hash.
    let canary_email = format!("canary.{}@leak.example.test", Uuid::now_v7().simple());
    let (invite, resp) = create_invite(
        &relay,
        secwet_id,
        &owner,
        &canary_email,
        vec![space_grant(space, TreeRole::Editor)],
    )
    .await;
    resp.ok::<InvitationDto>();
    let member_dev = Device::new();
    relay
        .post_unauth(&accept_path(&invite), &accept_request(secwet_id, &invite, &member_dev, &canary_email))
        .await
        .ok::<AcceptInvitationResponse>();

    // Rotation, branch keys, scoped events, revocation: populate every new table.
    let master_key: [u8; 32] = random_bytes();
    relay
        .post(
            &format!("/v1/secwets/{secwet_id}/keys"),
            &rotation_request(secwet_id, &owner, 2, &[&owner, &laptop], &master_key),
            &owner,
        )
        .await
        .ok::<KeyRotationResponse>();
    relay
        .post(
            &format!("/v1/secwets/{secwet_id}/spaces/{space}/keys"),
            &publish_request(secwet_id, space, 1, true, &owner, &[&owner, &laptop, &member_dev]),
            &owner,
        )
        .await
        .ok::<BranchScopeDto>();
    push(
        &relay,
        secwet_id,
        &member_dev,
        vec![event(secwet_id, &member_dev, 1, Some(content_scope(space, ScopeOp::Write)))],
    )
    .await
    .ok::<PushEventsResponse>();
    relay
        .post(
            &revoke_path(secwet_id, &laptop.id),
            &RevokeRequest { wipe: true, revocation: directive(secwet_id, &owner, &laptop.id, true) },
            &owner,
        )
        .await
        .ok::<RevokeResponse>();

    let new_tables = [
        "workspace_members",
        "member_grants",
        "invitations",
        "branch_scopes",
        "branch_keys",
    ];
    let columns = secwet_relay::sqlx::query(
        "SELECT table_name, column_name, data_type FROM information_schema.columns \
         WHERE table_schema = 'public' AND data_type IN ('text', 'character varying', 'bytea')",
    )
    .fetch_all(&relay.pool)
    .await
    .unwrap();
    let tables: std::collections::BTreeSet<String> =
        columns.iter().map(|c| c.get::<String, _>("table_name")).collect();
    // branch_scopes holds only UUIDs and integers, so it has no column to scan.
    for t in new_tables.iter().filter(|t| **t != "branch_scopes") {
        assert!(tables.contains(*t), "table {t} is scanned");
    }

    let needles: Vec<Vec<u8>> = vec![
        canary_email.as_bytes().to_vec(),
        canary_email.to_lowercase().as_bytes().to_vec(),
        canary_email.split('@').next().unwrap().as_bytes().to_vec(),
        invite.token.to_vec(),
        invite.auth().to_vec(),
        master_key.to_vec(),
        b"PLAINTEXT".to_vec(),
        b"SUPER_SECRET".to_vec(),
    ];

    for col in &columns {
        let table: String = col.get("table_name");
        let column: String = col.get("column_name");
        let data_type: String = col.get("data_type");
        let sql = if data_type == "bytea" {
            format!("SELECT \"{column}\" AS val FROM \"{table}\" WHERE \"{column}\" IS NOT NULL")
        } else {
            format!("SELECT convert_to(\"{column}\"::text, 'UTF8') AS val FROM \"{table}\" WHERE \"{column}\" IS NOT NULL")
        };
        let rows = secwet_relay::sqlx::query(&sql).fetch_all(&relay.pool).await.unwrap();
        for row in rows {
            let val: Vec<u8> = row.get("val");
            for needle in &needles {
                assert!(
                    !val.windows(needle.len()).any(|w| w == needle.as_slice()),
                    "plaintext leak in {table}.{column}"
                );
            }
        }
    }

    // The email is stored only as its salted hash.
    let stored_hash: Vec<u8> = secwet_relay::sqlx::query_scalar(
        "SELECT email_hash FROM invitations WHERE id = $1",
    )
    .bind(invite.invitation_id)
    .fetch_one(&relay.pool)
    .await
    .unwrap();
    assert_eq!(stored_hash, email_hash(secwet_id, &canary_email).to_vec());
}

// ============================================================================
// Event signatures over the legacy layout keep verifying
// ============================================================================

#[tokio::test]
async fn unscoped_owner_events_round_trip_and_ack() {
    let relay = start_relay().await;
    let owner = Device::new();
    let secwet_id = new_workspace(&relay, &owner).await;
    let e1 = event(secwet_id, &owner, 1, None);
    let resp: PushEventsResponse = push(&relay, secwet_id, &owner, vec![e1.clone()]).await.ok();
    assert_eq!(resp.accepted, 1);
    let pulled = pull_all(&relay, secwet_id, &owner).await;
    assert_eq!(pulled.events.len(), 1);
    assert_eq!(pulled.events[0].event, e1);
    relay
        .post(
            &format!("/v1/secwets/{secwet_id}/ack"),
            &AckEventsRequest { server_seq: resp.latest_server_seq },
            &owner,
        )
        .await
        .ok::<serde_json::Value>();

    // Wrong signature layout (full envelope instead of legacy bytes) is refused.
    let mut bad = event(secwet_id, &owner, 2, None);
    bad.signature = owner.sign(&postcard::to_stdvec(&bad.envelope).unwrap());
    push(&relay, secwet_id, &owner, vec![bad]).await.expect_err(401, RelayErrorCode::BadSignature);
}

// ============================================================================
// Remediation round: epochs, digests, statements, cut-offs, head, expiry
// ============================================================================

async fn event_count(pool: &PgPool, secwet_id: Uuid) -> i64 {
    secwet_relay::sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE secwet_id = $1")
        .bind(secwet_id)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn stale_epoch_rejects_whole_batch() {
    let relay = start_relay().await;
    let owner = Device::new();
    let secwet_id = new_workspace(&relay, &owner).await;
    let space = Uuid::now_v7();
    share_space(&relay, secwet_id, &owner, space).await;
    relay
        .post(
            &format!("/v1/secwets/{secwet_id}/keys"),
            &rotation_request(secwet_id, &owner, 2, &[&owner], &random_bytes()),
            &owner,
        )
        .await
        .ok::<KeyRotationResponse>();

    // A good event followed by one under the old master key epoch: 409, nothing stored.
    let good = event_at(secwet_id, &owner, 1, None, 2);
    let stale = event_at(secwet_id, &owner, 2, None, 1);
    push(&relay, secwet_id, &owner, vec![good.clone(), stale])
        .await
        .expect_err(409, RelayErrorCode::EpochConflict);
    assert_eq!(event_count(&relay.pool, secwet_id).await, 0);

    // Scoped event under a branch epoch that is not current.
    let wrong_branch = event_at(secwet_id, &owner, 1, Some(content_scope(space, ScopeOp::Write)), 2);
    push(&relay, secwet_id, &owner, vec![wrong_branch])
        .await
        .expect_err(409, RelayErrorCode::EpochConflict);

    // Scoped event in a space that was never shared.
    let unshared =
        event_at(secwet_id, &owner, 1, Some(content_scope(Uuid::now_v7(), ScopeOp::Write)), 1);
    push(&relay, secwet_id, &owner, vec![unshared])
        .await
        .expect_err(409, RelayErrorCode::EpochConflict);

    // The device_seq was not advanced: re-encrypted events start at 1 again.
    let scoped_ok = event_at(secwet_id, &owner, 2, Some(content_scope(space, ScopeOp::Write)), 1);
    let resp: PushEventsResponse =
        push(&relay, secwet_id, &owner, vec![good, scoped_ok]).await.ok();
    assert_eq!(resp.accepted, 2);
    assert_eq!(event_count(&relay.pool, secwet_id).await, 2);

    // Member events: the role check comes first, so an event the member may
    // not author is consumed (rejected) even at a stale epoch.
    let (viewer, _) =
        onboard_member(&relay, secwet_id, &owner, vec![space_grant(space, TreeRole::Viewer)]).await;
    let stale_unpermitted =
        event_at(secwet_id, &viewer, 1, Some(content_scope(space, ScopeOp::Write)), 5);
    let resp: PushEventsResponse =
        push(&relay, secwet_id, &viewer, vec![stale_unpermitted.clone()]).await.ok();
    assert_eq!(resp.rejected, vec![stale_unpermitted.envelope.event_id]);
}

#[tokio::test]
async fn branch_digest_mismatch_rejected_and_statements_delivered() {
    let relay = start_relay().await;
    let owner = Device::new();
    let secwet_id = new_workspace(&relay, &owner).await;
    let laptop = add_owner_device(&relay, secwet_id).await;
    let space = Uuid::now_v7();
    let path = format!("/v1/secwets/{secwet_id}/spaces/{space}/keys");

    // Bundle altered after signing.
    let mut req = publish_request(secwet_id, space, 1, true, &owner, &[&owner, &laptop]);
    req.keys[0].sealed_bundle[0] ^= 1;
    relay.post(&path, &req, &owner).await.expect_err(400, RelayErrorCode::InvalidRequest);

    // Digest list not covering a bundle.
    let mut req = publish_request(secwet_id, space, 1, true, &owner, &[&owner, &laptop]);
    req.statement.digests.pop();
    req.signature = owner.sign(&req.statement.signing_bytes().unwrap());
    relay.post(&path, &req, &owner).await.expect_err(400, RelayErrorCode::InvalidRequest);

    // Digests out of order.
    let mut req = publish_request(secwet_id, space, 1, true, &owner, &[&owner, &laptop]);
    req.statement.digests.reverse();
    req.signature = owner.sign(&req.statement.signing_bytes().unwrap());
    relay.post(&path, &req, &owner).await.expect_err(400, RelayErrorCode::InvalidRequest);

    // A valid publish: every delivered bundle carries the signed statement.
    let req = publish_request(secwet_id, space, 1, true, &owner, &[&owner, &laptop]);
    let scope: BranchScopeDto = relay.post(&path, &req, &owner).await.ok();
    let mut expected = vec![owner.id.clone(), laptop.id.clone()];
    expected.sort();
    assert_eq!(scope.recipients, expected);

    let keys: BranchKeysResponse =
        relay.get(&format!("/v1/secwets/{secwet_id}/branch-keys"), &laptop).await.ok();
    assert_eq!(keys.keys.len(), 1);
    let key = &keys.keys[0];
    let statement = key.statement.as_ref().expect("statement delivered");
    verify_signature_strict_bytes(
        &owner.sign_pub,
        &statement.statement.signing_bytes().unwrap(),
        &statement.signature,
    )
    .expect("statement signature verifies");
    let mut plain = key.clone();
    plain.statement = None;
    let digest: [u8; 32] = Sha256::digest(plain.digest_input().unwrap()).into();
    let entry = statement.statement.digests.iter().find(|d| d.device_id == laptop.id).unwrap();
    assert_eq!(entry.digest, digest);
    // Owner callers see recipients of the current epoch.
    assert_eq!(keys.scopes[0].recipients, expected);
}

#[tokio::test]
async fn rotation_requires_commitment_and_statements_are_returned() {
    let relay = start_relay().await;
    let owner = Device::new();
    let secwet_id = new_workspace(&relay, &owner).await;
    let keys_path = format!("/v1/secwets/{secwet_id}/keys");

    let mut req = rotation_request(secwet_id, &owner, 2, &[&owner], &random_bytes());
    req.statement.key_commitment = [0u8; 32];
    req.signature = owner.sign(&req.statement.signing_bytes().unwrap());
    relay.post(&keys_path, &req, &owner).await.expect_err(400, RelayErrorCode::InvalidRequest);

    let r2 = rotation_request(secwet_id, &owner, 2, &[&owner], &random_bytes());
    let r3 = rotation_request(secwet_id, &owner, 3, &[&owner], &random_bytes());
    relay.post(&keys_path, &r2, &owner).await.ok::<KeyRotationResponse>();
    relay.post(&keys_path, &r3, &owner).await.ok::<KeyRotationResponse>();

    let keys: WrappedKeysResponse = relay.get(&keys_path, &owner).await.ok();
    assert_eq!(keys.statements.len(), 2);
    for (st, req) in keys.statements.iter().zip([&r2, &r3]) {
        assert_eq!(st.statement, req.statement);
        assert_eq!(st.signature, req.signature);
        verify_signature_strict_bytes(
            &owner.sign_pub,
            &st.statement.signing_bytes().unwrap(),
            &st.signature,
        )
        .unwrap();
    }
}

#[tokio::test]
async fn revoked_seq_and_head_seq_are_reported() {
    let relay = start_relay().await;
    let owner = Device::new();
    let secwet_id = new_workspace(&relay, &owner).await;
    let laptop = add_owner_device(&relay, secwet_id).await;
    let space = Uuid::now_v7();
    share_space(&relay, secwet_id, &owner, space).await;

    let resp: PushEventsResponse = push(
        &relay,
        secwet_id,
        &owner,
        vec![event(secwet_id, &owner, 1, None), event(secwet_id, &owner, 2, None)],
    )
    .await
    .ok();
    let head = resp.latest_server_seq;

    // Pull reports the head.
    assert_eq!(pull_all(&relay, secwet_id, &owner).await.head_seq, head);

    // A member accepting now learns the head; with no visible events its pull
    // still reports the head so it can advance.
    let email = "head@example.test";
    let (invite, resp) =
        create_invite(&relay, secwet_id, &owner, email, vec![space_grant(space, TreeRole::Viewer)]).await;
    resp.ok::<InvitationDto>();
    let member = Device::new();
    let accepted: AcceptInvitationResponse = relay
        .post_unauth(&accept_path(&invite), &accept_request(secwet_id, &invite, &member, email))
        .await
        .ok();
    assert_eq!(accepted.head_seq, head);
    let member_view = pull_all(&relay, secwet_id, &member).await;
    assert!(member_view.events.is_empty());
    assert_eq!(member_view.head_seq, head);

    // Revocation records the head at revocation time.
    relay
        .post(
            &revoke_path(secwet_id, &laptop.id),
            &RevokeRequest { wipe: false, revocation: directive(secwet_id, &owner, &laptop.id, false) },
            &owner,
        )
        .await
        .ok::<RevokeResponse>();
    let list: DeviceListResponse =
        relay.get(&format!("/v1/secwets/{secwet_id}/devices"), &owner).await.ok();
    let dto = list.devices.iter().find(|d| d.id == laptop.id).unwrap();
    assert_eq!(dto.revoked_seq, Some(head));
    assert_eq!(list.devices.iter().find(|d| d.id == owner.id).unwrap().revoked_seq, None);
}

async fn ack(relay: &Relay, secwet_id: Uuid, dev: &Device, seq: u64) {
    relay
        .post(&format!("/v1/secwets/{secwet_id}/ack"), &AckEventsRequest { server_seq: seq }, dev)
        .await
        .ok::<serde_json::Value>();
}

#[tokio::test]
async fn member_cursor_expires_only_for_visible_pruning() {
    let relay = start_relay().await;
    let owner = Device::new();
    let secwet_id = new_workspace(&relay, &owner).await;
    let space_a = Uuid::now_v7();
    let space_b = Uuid::now_v7();
    share_space(&relay, secwet_id, &owner, space_a).await;
    share_space(&relay, secwet_id, &owner, space_b).await;
    let (member, _) =
        onboard_member(&relay, secwet_id, &owner, vec![space_grant(space_a, TreeRole::Viewer)]).await;

    // Events the member cannot see are pruned.
    let resp: PushEventsResponse = push(
        &relay,
        secwet_id,
        &owner,
        vec![
            event(secwet_id, &owner, 1, Some(content_scope(space_b, ScopeOp::Write))),
            event(secwet_id, &owner, 2, None),
        ],
    )
    .await
    .ok();
    let head = resp.latest_server_seq;
    ack(&relay, secwet_id, &owner, head).await;
    ack(&relay, secwet_id, &member, head).await;
    assert_eq!(db::run_retention_for_secwet(&relay.pool, secwet_id, 30).await.unwrap(), 2);

    // The owner's old cursor is expired; the member's is not.
    relay
        .get(&format!("/v1/secwets/{secwet_id}/events?after=0"), &owner)
        .await
        .expect_err(410, RelayErrorCode::CursorExpired);
    let view: PullEventsResponse =
        relay.get(&format!("/v1/secwets/{secwet_id}/events?after=0"), &member).await.ok();
    assert!(view.events.is_empty());

    // Now an event visible to the member is pruned.
    let resp: PushEventsResponse = push(
        &relay,
        secwet_id,
        &owner,
        vec![event(secwet_id, &owner, 3, Some(content_scope(space_a, ScopeOp::Write)))],
    )
    .await
    .ok();
    let head2 = resp.latest_server_seq;
    ack(&relay, secwet_id, &owner, head2).await;
    ack(&relay, secwet_id, &member, head2).await;
    assert_eq!(db::run_retention_for_secwet(&relay.pool, secwet_id, 30).await.unwrap(), 1);
    relay
        .get(&format!("/v1/secwets/{secwet_id}/events?after=0"), &member)
        .await
        .expect_err(410, RelayErrorCode::CursorExpired);
    relay
        .get(&format!("/v1/secwets/{secwet_id}/events?after={head}"), &member)
        .await
        .expect_err(410, RelayErrorCode::CursorExpired);
    let view: PullEventsResponse = relay
        .get(&format!("/v1/secwets/{secwet_id}/events?after={head2}"), &member)
        .await
        .ok();
    assert!(view.events.is_empty());
    assert_eq!(view.head_seq, head2);
}

#[tokio::test]
async fn retention_keeps_unscoped_events_after_the_snapshot() {
    let relay = start_relay().await;
    let owner = Device::new();
    let secwet_id = new_workspace(&relay, &owner).await;
    push(
        &relay,
        secwet_id,
        &owner,
        (1..=3).map(|i| event(secwet_id, &owner, i, None)).collect(),
    )
    .await
    .ok::<PushEventsResponse>();
    let seqs: Vec<u64> =
        pull_all(&relay, secwet_id, &owner).await.events.iter().map(|e| e.server_seq).collect();
    relay
        .put(
            &format!("/v1/secwets/{secwet_id}/snapshot"),
            &SnapshotUploadRequest {
                server_seq: seqs[0],
                key_epoch: 1,
                nonce: random_bytes(),
                ciphertext: vec![1; 16],
            },
            &owner,
        )
        .await
        .ok::<serde_json::Value>();
    relay
        .post(
            &format!("/v1/secwets/{secwet_id}/ack"),
            &AckEventsRequest { server_seq: seqs[2] },
            &owner,
        )
        .await
        .ok::<serde_json::Value>();
    // Acked through the third event, but only the first is covered by the snapshot.
    assert_eq!(db::run_retention_for_secwet(&relay.pool, secwet_id, 30).await.unwrap(), 1);
    let left: Vec<u64> = relay
        .get(&format!("/v1/secwets/{secwet_id}/events?after={}", seqs[0]), &owner)
        .await
        .ok::<PullEventsResponse>()
        .events
        .iter()
        .map(|e| e.server_seq)
        .collect();
    assert_eq!(left, seqs[1..].to_vec());
}

#[tokio::test]
async fn pairing_approval_must_cover_every_epoch() {
    let relay = start_relay().await;
    let owner = Device::new();
    let secwet_id = new_workspace(&relay, &owner).await;
    relay
        .post(
            &format!("/v1/secwets/{secwet_id}/keys"),
            &rotation_request(secwet_id, &owner, 2, &[&owner], &random_bytes()),
            &owner,
        )
        .await
        .ok::<KeyRotationResponse>();

    let session: CreatePairingSessionResponse = relay
        .post(
            "/v1/pairing",
            &CreatePairingSessionRequest { secwet_id, a_eph_pub: random_bytes() },
            &owner,
        )
        .await
        .ok();
    let newcomer = Device::new();
    relay
        .post_unauth(
            &format!("/v1/pairing/{}/join", session.session_id),
            &PairingJoinRequest {
                n_eph_pub: random_bytes(),
                sign_pub: newcomer.sign_pub,
                enc_pub: newcomer.enc_pub,
                sealed_profile: vec![0; 32],
            },
        )
        .await
        .ok::<serde_json::Value>();

    let approve = |epochs: Vec<(u32, [u8; 32])>| {
        let (approval, signature) = create_pairing_approval(
            &secwet_id,
            &session.session_id,
            &newcomer.id,
            &newcomer.sign_pub,
            &newcomer.enc_pub,
            &owner.sk,
        )
        .unwrap();
        PairingApproveRequest {
            approval,
            signature,
            wrapped_keys: wrap_master_keys_for_device(&epochs, &newcomer.enc_pub, &newcomer.id, &secwet_id)
                .unwrap(),
        }
    };
    let path = format!("/v1/pairing/{}/approve", session.session_id);

    relay
        .post(&path, &approve(vec![(1, random_bytes())]), &owner)
        .await
        .expect_err(409, RelayErrorCode::EpochConflict);
    assert!(db::get_device(&relay.pool, &newcomer.id).await.unwrap().is_none());

    relay
        .post(&path, &approve(vec![(1, random_bytes()), (2, random_bytes())]), &owner)
        .await
        .ok::<serde_json::Value>();
    let keys: WrappedKeysResponse =
        relay.get(&format!("/v1/secwets/{secwet_id}/keys"), &newcomer).await.ok();
    assert_eq!(keys.keys.iter().map(|k| k.epoch).collect::<Vec<_>>(), vec![1, 2]);
}

#[tokio::test]
async fn space_admin_lists_only_members_of_its_spaces() {
    let relay = start_relay().await;
    let owner = Device::new();
    let secwet_id = new_workspace(&relay, &owner).await;
    let space_a = Uuid::now_v7();
    let space_b = Uuid::now_v7();
    let (admin_a, admin_a_id) =
        onboard_member(&relay, secwet_id, &owner, vec![space_grant(space_a, TreeRole::Admin)]).await;
    let (viewer_a, viewer_a_id) =
        onboard_member(&relay, secwet_id, &owner, vec![space_grant(space_a, TreeRole::Viewer)]).await;
    let (_viewer_b, viewer_b_id) =
        onboard_member(&relay, secwet_id, &owner, vec![space_grant(space_b, TreeRole::Viewer)]).await;
    let (_both, both_id) = onboard_member(
        &relay,
        secwet_id,
        &owner,
        vec![space_grant(space_a, TreeRole::Viewer), space_grant(space_b, TreeRole::Viewer)],
    )
    .await;

    let path = format!("/v1/secwets/{secwet_id}/members");
    let view: MembersResponse = relay.get(&path, &admin_a).await.ok();
    let mut ids: Vec<Uuid> = view.members.iter().map(|m| m.member_id).collect();
    ids.sort();
    let mut expected = vec![admin_a_id, viewer_a_id];
    expected.sort();
    assert_eq!(ids, expected);
    assert!(view.invitations.iter().all(|i| expected.contains(&i.member_id)));
    assert!(!ids.contains(&viewer_b_id) && !ids.contains(&both_id));

    let full: MembersResponse = relay.get(&path, &owner).await.ok();
    assert_eq!(full.members.len(), 4);

    relay.get(&path, &viewer_a).await.expect_err(403, RelayErrorCode::Forbidden);
}

#[tokio::test]
async fn accept_hides_state_from_wrong_tokens() {
    let relay = start_relay().await;
    let owner = Device::new();
    let secwet_id = new_workspace(&relay, &owner).await;
    let space = Uuid::now_v7();
    let email = "state@example.test";
    let (invite, resp) =
        create_invite(&relay, secwet_id, &owner, email, vec![space_grant(space, TreeRole::Viewer)]).await;
    resp.ok::<InvitationDto>();
    let dev = Device::new();
    relay
        .post_unauth(&accept_path(&invite), &accept_request(secwet_id, &invite, &dev, email))
        .await
        .ok::<AcceptInvitationResponse>();

    // Already used + wrong token: indistinguishable from an unknown invitation.
    let wrong = Invite { token: random_bytes(), ..invite_clone(&invite) };
    relay
        .post_unauth(&accept_path(&invite), &accept_request(secwet_id, &wrong, &Device::new(), email))
        .await
        .expect_err(403, RelayErrorCode::InvalidInvitation);
    let unknown = Invite { invitation_id: Uuid::now_v7(), ..invite_clone(&invite) };
    relay
        .post_unauth(&accept_path(&unknown), &accept_request(secwet_id, &unknown, &Device::new(), email))
        .await
        .expect_err(403, RelayErrorCode::InvalidInvitation);
    // Right token on the used invitation: already_joined.
    relay
        .post_unauth(&accept_path(&invite), &accept_request(secwet_id, &invite, &Device::new(), email))
        .await
        .expect_err(409, RelayErrorCode::AlreadyJoined);
}

// ============================================================================
// Second remediation round: device certificates, member push ordering
// ============================================================================

fn certificate(secwet_id: Uuid, certifier: &Device, subject: &Device, issued_at: i64) -> SignedDeviceCertificate {
    let certificate = DeviceCertificate {
        secwet_id,
        device_id: subject.id.clone(),
        sign_pub: subject.sign_pub,
        enc_pub: subject.enc_pub,
        member_id: None,
        certifier_device_id: certifier.id.clone(),
        issued_at,
    };
    let signature = certifier.sign(&certificate.signing_bytes().unwrap());
    SignedDeviceCertificate { certificate, signature }
}

#[tokio::test]
async fn device_certificates_post_get_and_rejections() {
    let relay = start_relay().await;
    let owner = Device::new();
    let secwet_id = new_workspace(&relay, &owner).await;
    let laptop = add_owner_device(&relay, secwet_id).await;
    let space = Uuid::now_v7();
    let (member, _) =
        onboard_member(&relay, secwet_id, &owner, vec![space_grant(space, TreeRole::Viewer)]).await;
    let path = format!("/v1/secwets/{secwet_id}/certificates");

    let t0 = now_ms();
    let self_cert = certificate(secwet_id, &owner, &owner, t0);
    let laptop_cert = certificate(secwet_id, &owner, &laptop, t0);
    relay
        .post(&path, &DeviceCertificates { certificates: vec![self_cert.clone(), laptop_cert.clone()] }, &owner)
        .await
        .ok::<serde_json::Value>();

    // Idempotent; a newer certificate replaces, an older one is ignored.
    let newer = certificate(secwet_id, &owner, &laptop, t0 + 1000);
    let older = certificate(secwet_id, &owner, &laptop, t0 - 1000);
    relay
        .post(&path, &DeviceCertificates { certificates: vec![laptop_cert.clone(), newer.clone()] }, &owner)
        .await
        .ok::<serde_json::Value>();
    relay
        .post(&path, &DeviceCertificates { certificates: vec![older] }, &owner)
        .await
        .ok::<serde_json::Value>();

    // Any authenticated device, members included, can read them.
    let got: DeviceCertificates = relay.get(&path, &member).await.ok();
    assert_eq!(got.certificates.len(), 2);
    assert!(got.certificates.contains(&self_cert));
    assert!(got.certificates.contains(&newer));

    // Forged signature.
    let mut forged = certificate(secwet_id, &owner, &member, t0);
    forged.signature = laptop.sign(&forged.certificate.signing_bytes().unwrap());
    relay
        .post(&path, &DeviceCertificates { certificates: vec![forged] }, &owner)
        .await
        .expect_err(401, RelayErrorCode::BadSignature);

    // A certificate whose certifier is not the caller (even if validly signed by it).
    let by_laptop = certificate(secwet_id, &laptop, &member, t0);
    relay
        .post(&path, &DeviceCertificates { certificates: vec![by_laptop] }, &owner)
        .await
        .expect_err(400, RelayErrorCode::InvalidRequest);

    // Device id not derived from the certified key.
    let mut mismatched = certificate(secwet_id, &owner, &member, t0);
    mismatched.certificate.device_id = laptop.id.clone();
    mismatched.signature = owner.sign(&mismatched.certificate.signing_bytes().unwrap());
    relay
        .post(&path, &DeviceCertificates { certificates: vec![mismatched] }, &owner)
        .await
        .expect_err(400, RelayErrorCode::InvalidRequest);

    // Another workspace.
    let mut foreign = certificate(secwet_id, &owner, &member, t0);
    foreign.certificate.secwet_id = Uuid::now_v7();
    foreign.signature = owner.sign(&foreign.certificate.signing_bytes().unwrap());
    relay
        .post(&path, &DeviceCertificates { certificates: vec![foreign] }, &owner)
        .await
        .expect_err(400, RelayErrorCode::InvalidRequest);

    // Nothing from the rejected requests was stored; retention never touches them.
    db::run_retention_for_secwet(&relay.pool, secwet_id, 0).await.unwrap();
    let got: DeviceCertificates = relay.get(&path, &owner).await.ok();
    assert_eq!(got.certificates.len(), 2);
}

#[tokio::test]
async fn downgraded_member_stale_event_is_consumed_not_conflicting() {
    let relay = start_relay().await;
    let owner = Device::new();
    let secwet_id = new_workspace(&relay, &owner).await;
    let space_a = Uuid::now_v7();
    let space_b = Uuid::now_v7();
    let space_c = Uuid::now_v7(); // granted but never shared
    share_space(&relay, secwet_id, &owner, space_a).await;
    share_space(&relay, secwet_id, &owner, space_b).await;
    let (member, member_id) = onboard_member(
        &relay,
        secwet_id,
        &owner,
        vec![
            space_grant(space_a, TreeRole::Editor),
            space_grant(space_b, TreeRole::Editor),
            space_grant(space_c, TreeRole::Editor),
        ],
    )
    .await;

    // Downgrade on A to viewer, then rotate A's branch key to epoch 2.
    relay
        .put(
            &format!("/v1/secwets/{secwet_id}/members/{member_id}/grants"),
            &UpdateMemberGrantsRequest {
                grants: signed_grants(
                    secwet_id,
                    member_id,
                    2,
                    vec![
                        space_grant(space_a, TreeRole::Viewer),
                        space_grant(space_b, TreeRole::Editor),
                        space_grant(space_c, TreeRole::Editor),
                    ],
                    &owner,
                ),
            },
            &owner,
        )
        .await
        .ok::<MemberDto>();
    relay
        .post(
            &format!("/v1/secwets/{secwet_id}/spaces/{space_a}/keys"),
            &publish_request(secwet_id, space_a, 2, true, &owner, &[&owner, &member]),
            &owner,
        )
        .await
        .ok::<BranchScopeDto>();

    // Offline edits made before the downgrade: a write in A at the stale
    // epoch 1, a write in the unshared space C, then a permitted write in B.
    let stale_a = event_at(secwet_id, &member, 1, Some(content_scope(space_a, ScopeOp::Write)), 1);
    let unshared_c = event_at(secwet_id, &member, 2, Some(content_scope(space_c, ScopeOp::Write)), 1);
    let ok_b = event_at(secwet_id, &member, 3, Some(content_scope(space_b, ScopeOp::Write)), 1);
    let resp: PushEventsResponse = push(
        &relay,
        secwet_id,
        &member,
        vec![stale_a.clone(), unshared_c.clone(), ok_b.clone()],
    )
    .await
    .ok();
    assert_eq!(resp.accepted, 3);
    assert_eq!(resp.rejected, vec![stale_a.envelope.event_id, unshared_c.envelope.event_id]);
    let stored: Vec<Vec<u8>> = secwet_relay::sqlx::query_scalar(
        "SELECT event_id FROM events WHERE secwet_id = $1 ORDER BY server_seq",
    )
    .bind(secwet_id)
    .fetch_all(&relay.pool)
    .await
    .unwrap();
    assert_eq!(stored, vec![ok_b.envelope.event_id.to_vec()]);

    // A permitted event at a stale epoch still rejects the whole batch.
    push(
        &relay,
        secwet_id,
        &member,
        vec![event_at(secwet_id, &member, 4, Some(content_scope(space_b, ScopeOp::Write)), 7)],
    )
    .await
    .expect_err(409, RelayErrorCode::EpochConflict);
    // ... and the sequence continued from the consumed events.
    push(
        &relay,
        secwet_id,
        &member,
        vec![event_at(secwet_id, &member, 4, Some(content_scope(space_b, ScopeOp::Write)), 1)],
    )
    .await
    .ok::<PushEventsResponse>();
}
