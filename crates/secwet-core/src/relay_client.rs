//! Relay client for authenticated zero-knowledge communications with the relay server.
//!
//! Section 8.2 & Section 8.4:
//! Client generates Ed25519 signatures over canonical request bytes and handles
//! store registration and entitlement queries.

use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::SigningKey;
use reqwest::header::{HeaderMap, HeaderValue};
use secwet_proto::{
    canonical_registration_proof_bytes, canonical_request_bytes, AckEventsRequest,
    CreatePairingSessionRequest, CreatePairingSessionResponse, EntitlementResponse, HealthResponse,
    PairingApproveRequest, PairingJoinRequest, PairingResultResponse, PairingSessionStatusResponse,
    PullEventsResponse, PushEventsRequest, PushEventsResponse, RegisterSecwetRequest,
    RegisterSecwetResponse, RelayError, SignedEvent, SnapshotResponse, SnapshotUploadRequest,
    HEADER_DEVICE, HEADER_NONCE, HEADER_SIGNATURE, HEADER_TIME,
};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::{crypto::sign_payload, Error};

#[derive(Debug, Clone)]
pub struct RelayClient {
    base_url: String,
    device_id: String,
    client: reqwest::Client,
}

impl RelayClient {
    pub fn new(base_url: impl Into<String>, device_id: impl Into<String>) -> Self {
        let base = base_url.into().trim_end_matches('/').to_string();
        Self {
            base_url: base,
            device_id: device_id.into(),
            client: reqwest::Client::new(),
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    /// Checks unauthenticated relay server health.
    pub async fn health(&self) -> Result<HealthResponse, Error> {
        let url = format!("{}/health", self.base_url);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|_| Error::Offline)?;

        if !resp.status().is_success() {
            return Err(Error::Relay {
                code: format!("status_{}", resp.status().as_u16()),
            });
        }

        resp.json::<HealthResponse>()
            .await
            .map_err(|_| Error::Relay {
                code: "invalid_response".into(),
            })
    }

    /// Registers the workspace and initial device with cryptographic proof.
    pub async fn register(
        &self,
        secwet_id: Uuid,
        sign_pub: [u8; 32],
        enc_pub: [u8; 32],
        signing_key: &SigningKey,
    ) -> Result<RegisterSecwetResponse, Error> {
        let path = "/v1/secwets";
        let url = format!("{}{}", self.base_url, path);

        // 1. Create proof signature over canonical registration bytes
        let proof_canonical = canonical_registration_proof_bytes(&secwet_id, &sign_pub, &enc_pub)
            .map_err(|_| Error::Crypto)?;
        let proof_sig = sign_payload(signing_key, &proof_canonical);

        let register_req = RegisterSecwetRequest {
            secwet_id,
            sign_pub,
            enc_pub,
            proof: proof_sig.to_bytes(),
        };

        let body_bytes = serde_json::to_vec(&register_req).map_err(|_| Error::Storage)?;
        let headers = self.build_auth_headers("POST", path, &body_bytes, signing_key)?;

        let resp = self
            .client
            .post(&url)
            .headers(headers)
            .header("Content-Type", "application/json")
            .body(body_bytes)
            .send()
            .await
            .map_err(|_| Error::Offline)?;

        if !resp.status().is_success() {
            return Err(parse_error_response(resp).await);
        }

        resp.json::<RegisterSecwetResponse>()
            .await
            .map_err(|_| Error::Relay {
                code: "invalid_response".into(),
            })
    }

    /// Queries the workspace plan and entitlements.
    pub async fn get_entitlement(
        &self,
        secwet_id: Uuid,
        signing_key: &SigningKey,
    ) -> Result<EntitlementResponse, Error> {
        let path = format!("/v1/secwets/{}/entitlement", secwet_id);
        let url = format!("{}{}", self.base_url, path);

        let empty_body = b"";
        let headers = self.build_auth_headers("GET", &path, empty_body, signing_key)?;

        let resp = self
            .client
            .get(&url)
            .headers(headers)
            .send()
            .await
            .map_err(|_| Error::Offline)?;

        if !resp.status().is_success() {
            return Err(parse_error_response(resp).await);
        }

        resp.json::<EntitlementResponse>()
            .await
            .map_err(|_| Error::Relay {
                code: "invalid_response".into(),
            })
    }

    /// Creates a pairing session on the relay.
    pub async fn create_pairing_session(
        &self,
        secwet_id: Uuid,
        a_eph_pub: [u8; 32],
        signing_key: &SigningKey,
    ) -> Result<CreatePairingSessionResponse, Error> {
        let path = "/v1/pairing";
        let url = format!("{}{}", self.base_url, path);

        let req = CreatePairingSessionRequest {
            secwet_id,
            a_eph_pub,
        };
        let body_bytes = serde_json::to_vec(&req).map_err(|_| Error::Storage)?;
        let headers = self.build_auth_headers("POST", path, &body_bytes, signing_key)?;

        let resp = self
            .client
            .post(&url)
            .headers(headers)
            .header("Content-Type", "application/json")
            .body(body_bytes)
            .send()
            .await
            .map_err(|_| Error::Offline)?;

        if !resp.status().is_success() {
            return Err(parse_error_response(resp).await);
        }

        resp.json::<CreatePairingSessionResponse>()
            .await
            .map_err(|_| Error::Relay {
                code: "invalid_response".into(),
            })
    }

    /// Submits a join request for a new device to a pairing session.
    pub async fn join_pairing_session(
        &self,
        session_id: Uuid,
        req: &PairingJoinRequest,
    ) -> Result<(), Error> {
        let path = format!("/v1/pairing/{}/join", session_id);
        let url = format!("{}{}", self.base_url, path);

        let body_bytes = serde_json::to_vec(req).map_err(|_| Error::Storage)?;

        let resp = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .body(body_bytes)
            .send()
            .await
            .map_err(|_| Error::Offline)?;

        if !resp.status().is_success() {
            return Err(parse_error_response(resp).await);
        }

        Ok(())
    }

    /// Checks the current status of a pairing session.
    pub async fn get_pairing_status(
        &self,
        session_id: Uuid,
        signing_key: &SigningKey,
    ) -> Result<PairingSessionStatusResponse, Error> {
        let path = format!("/v1/pairing/{}", session_id);
        let url = format!("{}{}", self.base_url, path);

        let headers = self.build_auth_headers("GET", &path, b"", signing_key)?;

        let resp = self
            .client
            .get(&url)
            .headers(headers)
            .send()
            .await
            .map_err(|_| Error::Offline)?;

        if !resp.status().is_success() {
            return Err(parse_error_response(resp).await);
        }

        resp.json::<PairingSessionStatusResponse>()
            .await
            .map_err(|_| Error::Relay {
                code: "invalid_response".into(),
            })
    }

    /// Approves a pairing session, registering the new device.
    pub async fn approve_pairing(
        &self,
        session_id: Uuid,
        req: &PairingApproveRequest,
        signing_key: &SigningKey,
    ) -> Result<(), Error> {
        let path = format!("/v1/pairing/{}/approve", session_id);
        let url = format!("{}{}", self.base_url, path);

        let body_bytes = serde_json::to_vec(req).map_err(|_| Error::Storage)?;
        let headers = self.build_auth_headers("POST", &path, &body_bytes, signing_key)?;

        let resp = self
            .client
            .post(&url)
            .headers(headers)
            .header("Content-Type", "application/json")
            .body(body_bytes)
            .send()
            .await
            .map_err(|_| Error::Offline)?;

        if !resp.status().is_success() {
            return Err(parse_error_response(resp).await);
        }

        Ok(())
    }

    /// Polls for the result of a pairing session from a new device.
    /// Returns Ok(None) if approval is still pending, or Ok(Some(result)) when approved.
    pub async fn get_pairing_result(
        &self,
        session_id: Uuid,
    ) -> Result<Option<PairingResultResponse>, Error> {
        let path = format!("/v1/pairing/{}/result", session_id);
        let url = format!("{}{}", self.base_url, path);

        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|_| Error::Offline)?;

        if resp.status().as_u16() == 202 {
            return Ok(None);
        }

        if !resp.status().is_success() {
            return Err(parse_error_response(resp).await);
        }

        let result = resp
            .json::<PairingResultResponse>()
            .await
            .map_err(|_| Error::Relay {
                code: "invalid_response".into(),
            })?;

        Ok(Some(result))
    }

    /// Pushes a batch of signed events from outbox to relay.
    pub async fn push_events(
        &self,
        secwet_id: Uuid,
        events: Vec<SignedEvent>,
        signing_key: &SigningKey,
    ) -> Result<PushEventsResponse, Error> {
        let path = format!("/v1/secwets/{}/events", secwet_id);
        let url = format!("{}{}", self.base_url, path);

        let req = PushEventsRequest { events };
        let body_bytes = serde_json::to_vec(&req).map_err(|_| Error::Storage)?;
        let headers = self.build_auth_headers("POST", &path, &body_bytes, signing_key)?;

        let resp = self
            .client
            .post(&url)
            .headers(headers)
            .header("Content-Type", "application/json")
            .body(body_bytes)
            .send()
            .await
            .map_err(|_| Error::Offline)?;

        if !resp.status().is_success() {
            return Err(parse_error_response(resp).await);
        }

        resp.json::<PushEventsResponse>()
            .await
            .map_err(|_| Error::Relay {
                code: "invalid_response".into(),
            })
    }

    /// Pulls events after a given server sequence cursor.
    pub async fn get_events(
        &self,
        secwet_id: Uuid,
        after: u64,
        limit: u32,
        signing_key: &SigningKey,
    ) -> Result<PullEventsResponse, Error> {
        let path = format!("/v1/secwets/{}/events?after={}&limit={}", secwet_id, after, limit);
        let url = format!("{}{}", self.base_url, path);

        let headers = self.build_auth_headers("GET", &path, b"", signing_key)?;

        let resp = self
            .client
            .get(&url)
            .headers(headers)
            .send()
            .await
            .map_err(|_| Error::Offline)?;

        if !resp.status().is_success() {
            return Err(parse_error_response(resp).await);
        }

        resp.json::<PullEventsResponse>()
            .await
            .map_err(|_| Error::Relay {
                code: "invalid_response".into(),
            })
    }

    /// Acknowledges received server sequence number to the relay.
    pub async fn ack_events(
        &self,
        secwet_id: Uuid,
        server_seq: u64,
        signing_key: &SigningKey,
    ) -> Result<(), Error> {
        let path = format!("/v1/secwets/{}/ack", secwet_id);
        let url = format!("{}{}", self.base_url, path);

        let req = AckEventsRequest { server_seq };
        let body_bytes = serde_json::to_vec(&req).map_err(|_| Error::Storage)?;
        let headers = self.build_auth_headers("POST", &path, &body_bytes, signing_key)?;

        let resp = self
            .client
            .post(&url)
            .headers(headers)
            .header("Content-Type", "application/json")
            .body(body_bytes)
            .send()
            .await
            .map_err(|_| Error::Offline)?;

        if !resp.status().is_success() {
            return Err(parse_error_response(resp).await);
        }

        Ok(())
    }

    /// Uploads an encrypted workspace snapshot.
    pub async fn upload_snapshot(
        &self,
        secwet_id: Uuid,
        req: &SnapshotUploadRequest,
        signing_key: &SigningKey,
    ) -> Result<(), Error> {
        let path = format!("/v1/secwets/{}/snapshot", secwet_id);
        let url = format!("{}{}", self.base_url, path);

        let body_bytes = serde_json::to_vec(req).map_err(|_| Error::Storage)?;
        let headers = self.build_auth_headers("PUT", &path, &body_bytes, signing_key)?;

        let resp = self
            .client
            .put(&url)
            .headers(headers)
            .header("Content-Type", "application/json")
            .body(body_bytes)
            .send()
            .await
            .map_err(|_| Error::Offline)?;

        if !resp.status().is_success() {
            return Err(parse_error_response(resp).await);
        }

        Ok(())
    }

    /// Downloads the newest encrypted workspace snapshot.
    pub async fn get_snapshot(
        &self,
        secwet_id: Uuid,
        signing_key: &SigningKey,
    ) -> Result<Option<SnapshotResponse>, Error> {
        let path = format!("/v1/secwets/{}/snapshot", secwet_id);
        let url = format!("{}{}", self.base_url, path);

        let headers = self.build_auth_headers("GET", &path, b"", signing_key)?;

        let resp = self
            .client
            .get(&url)
            .headers(headers)
            .send()
            .await
            .map_err(|_| Error::Offline)?;

        if resp.status().as_u16() == 404 {
            return Ok(None);
        }

        if !resp.status().is_success() {
            return Err(parse_error_response(resp).await);
        }

        let snap = resp.json::<SnapshotResponse>().await.map_err(|_| Error::Relay {
            code: "invalid_response".into(),
        })?;

        Ok(Some(snap))
    }

    /// Sends a signed request with an optional JSON body and decodes a JSON response.
    pub async fn signed_json<B: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        path: &str,
        body: Option<&B>,
        signing_key: &SigningKey,
    ) -> Result<R, Error> {
        let body_bytes = match body {
            Some(b) => serde_json::to_vec(b).map_err(|_| Error::Storage)?,
            None => Vec::new(),
        };
        let headers = self.build_auth_headers(method, path, &body_bytes, signing_key)?;
        let url = format!("{}{}", self.base_url, path);
        let m = reqwest::Method::from_bytes(method.as_bytes()).map_err(|_| Error::Storage)?;
        let mut req = self.client.request(m, &url).headers(headers);
        if body.is_some() {
            req = req.header("Content-Type", "application/json").body(body_bytes);
        }
        let resp = req.send().await.map_err(|_| Error::Offline)?;
        if !resp.status().is_success() {
            return Err(parse_error_response(resp).await);
        }
        resp.json::<R>().await.map_err(|_| Error::Relay {
            code: "invalid_response".into(),
        })
    }

    /// Sends an unauthenticated JSON request (invitation acceptance).
    pub async fn unsigned_json<B: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<R, Error> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .client
            .post(&url)
            .json(body)
            .send()
            .await
            .map_err(|_| Error::Offline)?;
        if !resp.status().is_success() {
            return Err(parse_error_response(resp).await);
        }
        resp.json::<R>().await.map_err(|_| Error::Relay {
            code: "invalid_response".into(),
        })
    }

    pub async fn list_devices(&self, secwet_id: Uuid, signing_key: &SigningKey) -> Result<secwet_proto::DeviceListResponse, Error> {
        let path = format!("/v1/secwets/{}/devices", secwet_id);
        self.signed_json::<(), _>("GET", &path, None, signing_key).await
    }

    pub async fn revoke_device(
        &self,
        secwet_id: Uuid,
        req: &secwet_proto::RevokeRequest,
        signing_key: &SigningKey,
    ) -> Result<secwet_proto::RevokeResponse, Error> {
        let path = format!(
            "/v1/secwets/{}/devices/{}/revoke",
            secwet_id, req.revocation.directive.target_device_id
        );
        self.signed_json("POST", &path, Some(req), signing_key).await
    }

    pub async fn rotate_keys(
        &self,
        secwet_id: Uuid,
        req: &secwet_proto::KeyRotationRequest,
        signing_key: &SigningKey,
    ) -> Result<secwet_proto::KeyRotationResponse, Error> {
        let path = format!("/v1/secwets/{}/keys", secwet_id);
        self.signed_json("POST", &path, Some(req), signing_key).await
    }

    pub async fn get_wrapped_keys(&self, secwet_id: Uuid, signing_key: &SigningKey) -> Result<secwet_proto::WrappedKeysResponse, Error> {
        let path = format!("/v1/secwets/{}/keys", secwet_id);
        self.signed_json::<(), _>("GET", &path, None, signing_key).await
    }

    pub async fn get_access(&self, secwet_id: Uuid, signing_key: &SigningKey) -> Result<secwet_proto::AccessResponse, Error> {
        let path = format!("/v1/secwets/{}/access", secwet_id);
        self.signed_json::<(), _>("GET", &path, None, signing_key).await
    }

    pub async fn list_members(&self, secwet_id: Uuid, signing_key: &SigningKey) -> Result<secwet_proto::MembersResponse, Error> {
        let path = format!("/v1/secwets/{}/members", secwet_id);
        self.signed_json::<(), _>("GET", &path, None, signing_key).await
    }

    pub async fn create_invitation(
        &self,
        secwet_id: Uuid,
        req: &secwet_proto::InviteCollaboratorRequest,
        signing_key: &SigningKey,
    ) -> Result<secwet_proto::InvitationDto, Error> {
        let path = format!("/v1/secwets/{}/invitations", secwet_id);
        self.signed_json("POST", &path, Some(req), signing_key).await
    }

    pub async fn delete_invitation(&self, secwet_id: Uuid, invitation_id: Uuid, signing_key: &SigningKey) -> Result<serde_json::Value, Error> {
        let path = format!("/v1/secwets/{}/invitations/{}", secwet_id, invitation_id);
        self.signed_json::<(), _>("DELETE", &path, None, signing_key).await
    }

    pub async fn activate_invitation(&self, secwet_id: Uuid, invitation_id: Uuid, signing_key: &SigningKey) -> Result<serde_json::Value, Error> {
        let path = format!("/v1/secwets/{}/invitations/{}/activate", secwet_id, invitation_id);
        self.signed_json("POST", &path, Some(&serde_json::json!({})), signing_key).await
    }

    pub async fn accept_invitation(
        &self,
        invitation_id: Uuid,
        req: &secwet_proto::AcceptInvitationRequest,
    ) -> Result<secwet_proto::AcceptInvitationResponse, Error> {
        let path = format!("/v1/invitations/{}/accept", invitation_id);
        self.unsigned_json(&path, req).await
    }

    pub async fn update_member_grants(
        &self,
        secwet_id: Uuid,
        member_id: Uuid,
        req: &secwet_proto::UpdateMemberGrantsRequest,
        signing_key: &SigningKey,
    ) -> Result<secwet_proto::MemberDto, Error> {
        let path = format!("/v1/secwets/{}/members/{}/grants", secwet_id, member_id);
        self.signed_json("PUT", &path, Some(req), signing_key).await
    }

    pub async fn remove_member(
        &self,
        secwet_id: Uuid,
        member_id: Uuid,
        req: &secwet_proto::RemoveMemberRequest,
        signing_key: &SigningKey,
    ) -> Result<serde_json::Value, Error> {
        let path = format!("/v1/secwets/{}/members/{}/remove", secwet_id, member_id);
        self.signed_json("POST", &path, Some(req), signing_key).await
    }

    pub async fn publish_branch_keys(
        &self,
        secwet_id: Uuid,
        req: &secwet_proto::PublishBranchKeysRequest,
        signing_key: &SigningKey,
    ) -> Result<serde_json::Value, Error> {
        let path = format!("/v1/secwets/{}/spaces/{}/keys", secwet_id, req.statement.space_id);
        self.signed_json("POST", &path, Some(req), signing_key).await
    }

    pub async fn post_certificates(
        &self,
        secwet_id: Uuid,
        req: &secwet_proto::DeviceCertificates,
        signing_key: &SigningKey,
    ) -> Result<serde_json::Value, Error> {
        let path = format!("/v1/secwets/{}/certificates", secwet_id);
        self.signed_json("POST", &path, Some(req), signing_key).await
    }

    pub async fn get_certificates(&self, secwet_id: Uuid, signing_key: &SigningKey) -> Result<secwet_proto::DeviceCertificates, Error> {
        let path = format!("/v1/secwets/{}/certificates", secwet_id);
        self.signed_json::<(), _>("GET", &path, None, signing_key).await
    }

    pub async fn get_branch_keys(&self, secwet_id: Uuid, signing_key: &SigningKey) -> Result<secwet_proto::BranchKeysResponse, Error> {
        let path = format!("/v1/secwets/{}/branch-keys", secwet_id);
        self.signed_json::<(), _>("GET", &path, None, signing_key).await
    }

    /// Constructs the 4 required cryptographic request authentication headers.
    fn build_auth_headers(
        &self,
        method: &str,
        path_and_query: &str,
        body: &[u8],
        signing_key: &SigningKey,
    ) -> Result<HeaderMap, Error> {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| Error::Crypto)?;

        let body_sha256: [u8; 32] = Sha256::digest(body).into();
        let canonical = canonical_request_bytes(
            method,
            path_and_query,
            now_ms,
            &nonce,
            &body_sha256,
        )
        .map_err(|_| Error::Crypto)?;

        let signature = sign_payload(signing_key, &canonical);

        let mut headers = HeaderMap::new();
        headers.insert(
            HEADER_DEVICE,
            HeaderValue::from_str(&self.device_id).map_err(|_| Error::Crypto)?,
        );
        headers.insert(
            HEADER_TIME,
            HeaderValue::from_str(&now_ms.to_string()).map_err(|_| Error::Crypto)?,
        );
        headers.insert(
            HEADER_NONCE,
            HeaderValue::from_str(&BASE64URL_NOPAD.encode(&nonce))
                .map_err(|_| Error::Crypto)?,
        );
        headers.insert(
            HEADER_SIGNATURE,
            HeaderValue::from_str(&BASE64URL_NOPAD.encode(&signature.to_bytes()))
                .map_err(|_| Error::Crypto)?,
        );

        Ok(headers)
    }
}

async fn parse_error_response(resp: reqwest::Response) -> Error {
    let status = resp.status();
    if status.as_u16() == 410 {
        return Error::Relay {
            code: "cursor_expired".into(),
        };
    }
    if let Ok(relay_err) = resp.json::<RelayError>().await {
        if relay_err.error.code == secwet_proto::RelayErrorCode::Revoked {
            if let Some(rev) = relay_err.revocation {
                return Error::RevocationNotice(Box::new(rev));
            }
            return Error::Revoked;
        }
        Error::Relay {
            code: relay_code_str(relay_err.error.code),
        }
    } else {
        Error::Relay {
            code: format!("status_{}", status.as_u16()),
        }
    }
}

/// The snake_case wire name of a relay error code (`epoch_conflict`, ...).
pub fn relay_code_str(code: secwet_proto::RelayErrorCode) -> String {
    serde_json::to_value(code)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "internal".to_string())
}
