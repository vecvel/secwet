//! Wire types for device revocation, master key rotation and
//! workspace collaboration with tree-wise RBAC.
//!
//! Pure data and pure permission logic: no I/O and no cryptography. Every
//! byte string that is signed is produced by a `signing_bytes` method here so
//! the signer (core) and the verifier (relay, core) can never disagree.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{signature_bytes, WrappedKey};

pub const REVOCATION_CONTEXT: &str = "secwet-revoke-v1";
pub const ROTATION_CONTEXT: &str = "secwet-rotate-v1";
pub const GRANTS_CONTEXT: &str = "secwet-grants-v1";
pub const INVITE_ACCEPT_CONTEXT: &str = "secwet-invite-accept-v1";
pub const BRANCH_PUBLISH_CONTEXT: &str = "secwet-branch-publish-v1";
pub const DEVICE_CERT_CONTEXT: &str = "secwet-device-cert-v1";

/// Invitations stay valid for seven days.
pub const INVITATION_TTL_MS: i64 = 7 * 24 * 60 * 60 * 1000;
/// Largest grant list a single member may hold.
pub const MAX_GRANTS_PER_MEMBER: usize = 256;
/// Re-sealing after a key rotation commits this many rows per transaction.
pub const RESEAL_BATCH_SIZE: usize = 100;

// ============================================================================
// Revocation
// ============================================================================

/// Statement an active device signs to revoke another device. The revoked
/// device verifies it before wiping, so a relay cannot forge a remote wipe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationDirective {
    pub secwet_id: Uuid,
    pub target_device_id: String,
    pub issuer_device_id: String,
    pub wipe: bool,
    pub issued_at: i64,
}

impl RevocationDirective {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, postcard::Error> {
        postcard::to_stdvec(&(REVOCATION_CONTEXT, self))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRevocation {
    pub directive: RevocationDirective,
    #[serde(with = "signature_bytes")]
    pub signature: [u8; 64],
}

/// Body of `POST /v1/secwets/{id}/devices/{device_id}/revoke`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokeRequest {
    pub wipe: bool,
    pub revocation: SignedRevocation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokeResponse {
    pub device_id: String,
    pub revoked_at: i64,
    pub wipe_requested: bool,
}

/// Device as registered on the relay (public keys only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayDeviceDto {
    pub id: String,
    pub sign_pub: [u8; 32],
    pub enc_pub: [u8; 32],
    /// `None` for the workspace owner's own devices, `Some` for a collaborator's device.
    pub member_id: Option<Uuid>,
    pub added_at: i64,
    pub revoked_at: Option<i64>,
    pub wipe_requested: bool,
    /// Highest `server_seq` stored when the device was revoked. Events it
    /// wrote before that point stay valid for devices that pull later.
    #[serde(default)]
    pub revoked_seq: Option<u64>,
}

/// Response of `GET /v1/secwets/{id}/devices`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceListResponse {
    pub current_epoch: u32,
    pub devices: Vec<RelayDeviceDto>,
}

// ============================================================================
// Device certificates
// ============================================================================

/// A device vouching for another device's keys and membership. Stored by the
/// relay outside event retention; a client accepts it only when the
/// certifier is a device it already trusts, so the relay can withhold
/// certificates but never forge one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCertificate {
    pub secwet_id: Uuid,
    pub device_id: String,
    pub sign_pub: [u8; 32],
    pub enc_pub: [u8; 32],
    pub member_id: Option<Uuid>,
    pub certifier_device_id: String,
    pub issued_at: i64,
}

impl DeviceCertificate {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, postcard::Error> {
        postcard::to_stdvec(&(DEVICE_CERT_CONTEXT, self))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedDeviceCertificate {
    pub certificate: DeviceCertificate,
    #[serde(with = "signature_bytes")]
    pub signature: [u8; 64],
}

/// Body of `POST /v1/secwets/{id}/certificates` and response of the GET.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCertificates {
    pub certificates: Vec<SignedDeviceCertificate>,
}

// ============================================================================
// Master key rotation
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceWrappedKey {
    pub device_id: String,
    pub wrapped: WrappedKey,
}

/// Signed statement naming the new epoch and the exact set of recipients.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRotationStatement {
    pub secwet_id: Uuid,
    pub epoch: u32,
    pub issuer_device_id: String,
    /// Sorted ascending, no duplicates.
    pub recipients: Vec<String>,
    /// `HKDF(K_m, salt = secwet_id, info = "secwet/v1/key-commit")`: binds the
    /// statement to the exact key, so a relay cannot pair a genuine statement
    /// with a key it chose.
    pub key_commitment: [u8; 32],
}

/// A rotation statement with its issuer's signature, as returned to devices
/// catching up so they can verify who opened each epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRotationStatement {
    pub statement: KeyRotationStatement,
    #[serde(with = "signature_bytes")]
    pub signature: [u8; 64],
}

impl KeyRotationStatement {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, postcard::Error> {
        postcard::to_stdvec(&(ROTATION_CONTEXT, self))
    }
}

/// Body of `POST /v1/secwets/{id}/keys`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRotationRequest {
    pub statement: KeyRotationStatement,
    #[serde(with = "signature_bytes")]
    pub signature: [u8; 64],
    pub wrapped: Vec<DeviceWrappedKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRotationResponse {
    pub epoch: u32,
}

/// Response of `GET /v1/secwets/{id}/keys`: the caller's wrapped keys for every epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedKeysResponse {
    pub current_epoch: u32,
    pub keys: Vec<super::WrappedEpochKey>,
    /// Signed statement for every epoch opened by a rotation (epoch 1 has none).
    #[serde(default)]
    pub statements: Vec<SignedRotationStatement>,
}

// ============================================================================
// Tree roles and nodes
// ============================================================================

/// Deterministic role held on a tree node. Ordered: `NoAccess < Viewer < Editor < Admin`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TreeRole {
    NoAccess = 0,
    Viewer = 1,
    Editor = 2,
    Admin = 3,
}

impl TreeRole {
    pub fn can_read(self) -> bool {
        self >= TreeRole::Viewer
    }
    pub fn can_write(self) -> bool {
        self >= TreeRole::Editor
    }
    pub fn can_manage(self) -> bool {
        self == TreeRole::Admin
    }
    pub const fn as_str(self) -> &'static str {
        match self {
            TreeRole::NoAccess => "no_access",
            TreeRole::Viewer => "viewer",
            TreeRole::Editor => "editor",
            TreeRole::Admin => "admin",
        }
    }
    pub fn parse(s: &str) -> Option<TreeRole> {
        match s.trim().to_ascii_lowercase().replace('-', "_").as_str() {
            "no_access" | "none" => Some(TreeRole::NoAccess),
            "viewer" | "read" | "reader" => Some(TreeRole::Viewer),
            "editor" | "writer" | "write" => Some(TreeRole::Editor),
            "admin" => Some(TreeRole::Admin),
            _ => None,
        }
    }
}

/// A node of the organizational tree a grant can target.
///
/// Workspace -> Space -> Group -> Item -> { General | Environment }.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TreeNode {
    Workspace,
    Space(Uuid),
    Group(Uuid),
    Item(Uuid),
    /// Item-wide content (`environment_id: null`) of the item with this id.
    General(Uuid),
    Environment(Uuid),
}

impl TreeNode {
    pub const fn kind_str(&self) -> &'static str {
        match self {
            TreeNode::Workspace => "workspace",
            TreeNode::Space(_) => "space",
            TreeNode::Group(_) => "group",
            TreeNode::Item(_) => "item",
            TreeNode::General(_) => "general",
            TreeNode::Environment(_) => "environment",
        }
    }

    pub fn id(&self) -> Option<Uuid> {
        match self {
            TreeNode::Workspace => None,
            TreeNode::Space(id)
            | TreeNode::Group(id)
            | TreeNode::Item(id)
            | TreeNode::General(id)
            | TreeNode::Environment(id) => Some(*id),
        }
    }

    /// Depth in the tree: Workspace 0, Space 1, Group 2, Item 3, General / Environment 4.
    pub const fn depth(&self) -> u8 {
        match self {
            TreeNode::Workspace => 0,
            TreeNode::Space(_) => 1,
            TreeNode::Group(_) => 2,
            TreeNode::Item(_) => 3,
            TreeNode::General(_) | TreeNode::Environment(_) => 4,
        }
    }

    pub fn from_parts(kind: &str, id: Option<Uuid>) -> Option<TreeNode> {
        match (kind, id) {
            ("workspace", _) => Some(TreeNode::Workspace),
            ("space", Some(id)) => Some(TreeNode::Space(id)),
            ("group", Some(id)) | ("label", Some(id)) => Some(TreeNode::Group(id)),
            ("item", Some(id)) => Some(TreeNode::Item(id)),
            ("general", Some(id)) => Some(TreeNode::General(id)),
            ("environment", Some(id)) | ("env", Some(id)) => Some(TreeNode::Environment(id)),
            _ => None,
        }
    }
}

/// One role assignment on one node. `space_id` names the space containing the
/// node (`None` only for `TreeNode::Workspace`) so the relay can route events
/// without knowing the tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MemberGrant {
    pub node: TreeNode,
    pub space_id: Option<Uuid>,
    pub role: TreeRole,
}

/// Resolves the role a member holds at the deepest node of `path`.
///
/// `path` lists the nodes from the root down (`Workspace` first). The most
/// specific explicit grant on the path wins, so a parent grant cascades to its
/// children unless a child carries its own grant (including `NoAccess`).
///
/// A non-workspace grant only counts inside the space it names, so a grant
/// labelled with one space cannot reach a node of another space.
pub fn effective_role(grants: &[MemberGrant], path: &[TreeNode]) -> TreeRole {
    let path_space = path.iter().find_map(|n| match n {
        TreeNode::Space(s) => Some(*s),
        _ => None,
    });
    let mut role = TreeRole::NoAccess;
    for node in path {
        let found = grants.iter().find(|g| {
            g.node == *node && (g.node == TreeNode::Workspace || (path_space.is_some() && g.space_id == path_space))
        });
        if let Some(g) = found {
            role = g.role;
        }
    }
    role
}

/// Spaces in which the member holds any grant at all. `None` means a
/// workspace-level grant covers every collaborative space.
pub fn granted_spaces(grants: &[MemberGrant]) -> Option<Vec<Uuid>> {
    if grants
        .iter()
        .any(|g| g.node == TreeNode::Workspace && g.role.can_read())
    {
        return None;
    }
    let mut out: Vec<Uuid> = grants
        .iter()
        .filter(|g| g.role.can_read())
        .filter_map(|g| g.space_id)
        .collect();
    out.sort();
    out.dedup();
    Some(out)
}

/// Validates the structural rules of a grant list.
pub fn validate_grants(grants: &[MemberGrant]) -> Result<(), &'static str> {
    if grants.is_empty() {
        return Err("at least one grant is required");
    }
    if grants.len() > MAX_GRANTS_PER_MEMBER {
        return Err("too many grants");
    }
    for (i, g) in grants.iter().enumerate() {
        match (g.node, g.space_id) {
            (TreeNode::Workspace, None) => {}
            (TreeNode::Workspace, Some(_)) => return Err("workspace grant must not name a space"),
            (TreeNode::Space(s), Some(sp)) if s != sp => return Err("space grant names another space"),
            (_, None) => return Err("grant must name its space"),
            _ => {}
        }
        if grants[..i].iter().any(|o| o.node == g.node) {
            return Err("duplicate grant for the same node");
        }
    }
    if !grants.iter().any(|g| g.role.can_read()) {
        return Err("grants give no access");
    }
    Ok(())
}

/// True when `new` gives strictly less access than `old` on any node, which
/// requires a forward-secret branch key rotation.
pub fn is_downgrade(old: &[MemberGrant], new: &[MemberGrant]) -> bool {
    old.iter().any(|o| {
        match new.iter().find(|n| n.node == o.node) {
            Some(n) => n.role < o.role,
            None => o.role > TreeRole::NoAccess,
        }
    }) || new
        .iter()
        .any(|n| n.role == TreeRole::NoAccess && !old.iter().any(|o| o.node == n.node))
}

/// Grant list for one member, signed by an admin device. `version` strictly
/// increases with every change so a stale set cannot be replayed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberGrantSet {
    pub secwet_id: Uuid,
    pub member_id: Uuid,
    pub version: u64,
    pub grants: Vec<MemberGrant>,
    pub issuer_device_id: String,
    pub issued_at: i64,
}

impl MemberGrantSet {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, postcard::Error> {
        postcard::to_stdvec(&(GRANTS_CONTEXT, self))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedGrantSet {
    pub set: MemberGrantSet,
    #[serde(with = "signature_bytes")]
    pub signature: [u8; 64],
}

// ============================================================================
// Scoped events
// ============================================================================

/// Which branch key protects an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeTarget {
    /// The name record of the last node of the path (space, group, item or environment).
    Name,
    /// Item-wide content of the item at the end of the path.
    General,
    /// Content of the environment at the end of the path.
    Content,
}

/// What a scoped event does; decides the role the author needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeOp {
    /// Create, rename or delete a container (space, group, item, environment).
    Container,
    /// Create or update a secret, file or note.
    Write,
    /// Delete a secret, file or note.
    Delete,
}

impl ScopeOp {
    pub fn required_role(self) -> TreeRole {
        match self {
            ScopeOp::Container | ScopeOp::Delete => TreeRole::Admin,
            ScopeOp::Write => TreeRole::Editor,
        }
    }
}

/// Clear routing metadata of an event in a collaborative space. It names
/// only identifiers, never names or values, and it is covered by the event
/// signature so the relay cannot move an event to another branch.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EventScope {
    pub space_id: Uuid,
    /// Descendants of the space down to the key node: `[group, item, environment]`, truncated.
    pub path: Vec<Uuid>,
    pub target: ScopeTarget,
    pub op: ScopeOp,
}

impl EventScope {
    /// Structural check: path length must match the target.
    pub fn is_well_formed(&self) -> bool {
        match self.target {
            ScopeTarget::Name => self.path.len() <= 3,
            ScopeTarget::General => self.path.len() == 2,
            ScopeTarget::Content => self.path.len() == 3,
        }
    }

    /// Tree nodes from the root down to the node this event touches.
    pub fn tree_nodes(&self) -> Vec<TreeNode> {
        let mut nodes = vec![TreeNode::Workspace, TreeNode::Space(self.space_id)];
        if let Some(g) = self.path.first() {
            nodes.push(TreeNode::Group(*g));
        }
        if let Some(i) = self.path.get(1) {
            nodes.push(TreeNode::Item(*i));
            if self.target == ScopeTarget::General {
                nodes.push(TreeNode::General(*i));
            }
        }
        if let Some(e) = self.path.get(2) {
            nodes.push(TreeNode::Environment(*e));
        }
        nodes
    }

    /// Whether a member holding `grants` may author this event.
    pub fn permits(&self, grants: &[MemberGrant]) -> bool {
        self.is_well_formed() && effective_role(grants, &self.tree_nodes()) >= self.op.required_role()
    }
}

// ============================================================================
// Branch keys
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BranchKeyKind {
    /// Node secret of the node at `path`: every key below it derives from it.
    Subtree,
    /// Name key of the node at `path` only (navigation without content).
    Name,
    /// General-content key of the item at `path` only.
    General,
}

/// One key inside a bundle. `path` starts with the space id.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BranchKeyEntry {
    pub path: Vec<Uuid>,
    pub kind: BranchKeyKind,
    pub key: [u8; 32],
}

impl Drop for BranchKeyEntry {
    fn drop(&mut self) {
        // No zeroize dependency here; volatile writes keep the wipe from
        // being optimized away.
        for b in self.key.iter_mut() {
            unsafe { std::ptr::write_volatile(b, 0) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

/// A device the publisher vouches for: the owner's devices that may sign
/// later bundles, grant sets and revocations. Lets a member store learn
/// admin keys through a channel the relay cannot alter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedDevice {
    pub device_id: String,
    pub sign_pub: [u8; 32],
    pub enc_pub: [u8; 32],
}

impl std::fmt::Debug for BranchKeyEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BranchKeyEntry")
            .field("path", &self.path)
            .field("kind", &self.kind)
            .field("key", &"[redacted]")
            .finish()
    }
}

/// Plaintext of a wrapped bundle: the minimal keys one device needs for one
/// space at one epoch. Only ever exists HPKE-wrapped outside a device.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BranchKeyBundle {
    pub secwet_id: Uuid,
    pub space_id: Uuid,
    pub epoch: u32,
    pub entries: Vec<BranchKeyEntry>,
    /// Owner devices the publisher vouches for (see `TrustedDevice`).
    pub admins: Vec<TrustedDevice>,
}

impl std::fmt::Debug for BranchKeyBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BranchKeyBundle")
            .field("space_id", &self.space_id)
            .field("epoch", &self.epoch)
            .field("entries", &self.entries.len())
            .finish()
    }
}

/// Wrapped bundle as stored and routed by the relay: an HPKE-wrapped bundle
/// key plus the bundle sealed under it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopedBranchKey {
    pub space_id: Uuid,
    pub epoch: u32,
    pub device_id: String,
    pub wrapped: WrappedKey,
    pub sealed_bundle: Vec<u8>,
    /// The signed publish this bundle came from, attached by the relay on
    /// delivery so the recipient can verify issuer and digest.
    #[serde(default)]
    pub statement: Option<SignedBranchStatement>,
}

impl ScopedBranchKey {
    /// Bytes whose SHA-256 is listed in the publish statement.
    pub fn digest_input(&self) -> Result<Vec<u8>, postcard::Error> {
        postcard::to_stdvec(&(
            "secwet-branch-digest-v1",
            self.space_id,
            self.epoch,
            &self.device_id,
            &self.wrapped,
            &self.sealed_bundle,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BranchKeyDigest {
    pub device_id: String,
    pub digest: [u8; 32],
}

/// Signed header of a publish so recipients know an admin produced it and
/// that their bundle is exactly the one the admin wrapped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BranchPublishStatement {
    pub secwet_id: Uuid,
    pub space_id: Uuid,
    pub epoch: u32,
    pub rotate: bool,
    pub issuer_device_id: String,
    /// One entry per recipient, sorted by device id: `SHA-256(digest_input)`.
    pub digests: Vec<BranchKeyDigest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedBranchStatement {
    pub statement: BranchPublishStatement,
    #[serde(with = "signature_bytes")]
    pub signature: [u8; 64],
}

impl BranchPublishStatement {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, postcard::Error> {
        postcard::to_stdvec(&(BRANCH_PUBLISH_CONTEXT, self))
    }
}

/// Body of `POST /v1/secwets/{id}/spaces/{space_id}/keys`.
///
/// `rotate = true` opens a new epoch (`current + 1`, or `1` when the space is
/// first shared) and fails with `epoch_conflict` otherwise; `rotate = false`
/// adds or replaces bundles at the current epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishBranchKeysRequest {
    pub statement: BranchPublishStatement,
    #[serde(with = "signature_bytes")]
    pub signature: [u8; 64],
    pub keys: Vec<ScopedBranchKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BranchScopeDto {
    pub space_id: Uuid,
    pub current_epoch: u32,
    /// Devices holding a bundle at the current epoch (owner callers only).
    #[serde(default)]
    pub recipients: Vec<String>,
}

/// Response of `GET /v1/secwets/{id}/branch-keys`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BranchKeysResponse {
    pub scopes: Vec<BranchScopeDto>,
    pub keys: Vec<ScopedBranchKey>,
}

// ============================================================================
// Members and invitations
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvitationStatus {
    /// Created, link not used yet.
    Pending,
    /// The invitee registered a device; keys not delivered yet.
    Accepted,
    /// Keys delivered; the member is collaborating.
    Active,
    /// Withdrawn by an admin or the member was removed.
    Revoked,
    Expired,
}

impl InvitationStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            InvitationStatus::Pending => "pending",
            InvitationStatus::Accepted => "accepted",
            InvitationStatus::Active => "active",
            InvitationStatus::Revoked => "revoked",
            InvitationStatus::Expired => "expired",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "accepted" => Some(Self::Accepted),
            "active" => Some(Self::Active),
            "revoked" => Some(Self::Revoked),
            "expired" => Some(Self::Expired),
            _ => None,
        }
    }
}

/// Body of `POST /v1/secwets/{id}/invitations`. The relay stores hashes only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteCollaboratorRequest {
    pub invitation_id: Uuid,
    pub member_id: Uuid,
    /// SHA-256 of the normalized email, salted with the workspace id.
    pub email_hash: [u8; 32],
    /// SHA-256 of the invite auth key derived from the link token.
    pub token_hash: [u8; 32],
    pub expires_at: i64,
    pub grants: SignedGrantSet,
}

/// What the invitee's new device proves when it accepts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteAcceptance {
    pub device_id: String,
    pub sign_pub: [u8; 32],
    pub enc_pub: [u8; 32],
    /// HKDF(token) MAC over both public keys. The relay never learns the
    /// token, so it cannot swap the keys without the inviter noticing.
    pub binding: [u8; 32],
    pub accepted_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvitationDto {
    pub invitation_id: Uuid,
    pub member_id: Uuid,
    pub email_hash: [u8; 32],
    pub status: InvitationStatus,
    pub created_by: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub acceptance: Option<InviteAcceptance>,
}

/// Body of the unauthenticated `POST /v1/invitations/{invitation_id}/accept`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptInvitationRequest {
    pub secwet_id: Uuid,
    pub email_hash: [u8; 32],
    /// Invite auth key; the relay compares `SHA-256(auth)` with the stored hash.
    pub auth: [u8; 32],
    pub sign_pub: [u8; 32],
    pub enc_pub: [u8; 32],
    pub binding: [u8; 32],
    /// Ed25519 signature by the new device over `acceptance_signing_bytes`.
    #[serde(with = "signature_bytes")]
    pub proof: [u8; 64],
}

impl std::fmt::Debug for AcceptInvitationRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcceptInvitationRequest")
            .field("secwet_id", &self.secwet_id)
            .field("auth", &"[redacted]")
            .finish()
    }
}

impl AcceptInvitationRequest {
    pub fn signing_bytes(
        invitation_id: &Uuid,
        secwet_id: &Uuid,
        sign_pub: &[u8; 32],
        enc_pub: &[u8; 32],
        binding: &[u8; 32],
    ) -> Result<Vec<u8>, postcard::Error> {
        postcard::to_stdvec(&(
            INVITE_ACCEPT_CONTEXT,
            invitation_id.as_bytes(),
            secwet_id.as_bytes(),
            sign_pub,
            enc_pub,
            binding,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptInvitationResponse {
    pub secwet_id: Uuid,
    pub member_id: Uuid,
    pub device_id: String,
    /// Newest `server_seq` at acceptance. A member starts its cursor here:
    /// it receives existing data as fresh seed events, not history.
    #[serde(default)]
    pub head_seq: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberStatus {
    Invited,
    Active,
    Removed,
}

impl MemberStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            MemberStatus::Invited => "invited",
            MemberStatus::Active => "active",
            MemberStatus::Removed => "removed",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "invited" => Some(Self::Invited),
            "active" => Some(Self::Active),
            "removed" => Some(Self::Removed),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberDto {
    pub member_id: Uuid,
    pub email_hash: [u8; 32],
    pub status: MemberStatus,
    pub grants: SignedGrantSet,
    pub devices: Vec<RelayDeviceDto>,
    pub created_at: i64,
    pub removed_at: Option<i64>,
}

/// Response of `GET /v1/secwets/{id}/members`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembersResponse {
    pub members: Vec<MemberDto>,
    pub invitations: Vec<InvitationDto>,
}

/// Body of `PUT /v1/secwets/{id}/members/{member_id}/grants`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateMemberGrantsRequest {
    pub grants: SignedGrantSet,
}

/// Body of `POST /v1/secwets/{id}/members/{member_id}/remove`: one signed
/// revocation per device of the member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoveMemberRequest {
    pub revocations: Vec<SignedRevocation>,
}

/// Response of `GET /v1/secwets/{id}/access` for the calling device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessResponse {
    /// `None` for the owner's devices (full access).
    pub member_id: Option<Uuid>,
    pub grants: Option<SignedGrantSet>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g(node: TreeNode, space: Option<Uuid>, role: TreeRole) -> MemberGrant {
        MemberGrant { node, space_id: space, role }
    }

    #[test]
    fn most_specific_grant_wins_and_cascades() {
        let s = Uuid::from_u128(1);
        let grp = Uuid::from_u128(2);
        let item = Uuid::from_u128(3);
        let dev = Uuid::from_u128(4);
        let prod = Uuid::from_u128(5);
        let grants = vec![
            g(TreeNode::Item(item), Some(s), TreeRole::Editor),
            g(TreeNode::Environment(prod), Some(s), TreeRole::NoAccess),
        ];
        let base = [TreeNode::Workspace, TreeNode::Space(s), TreeNode::Group(grp), TreeNode::Item(item)];
        let mut dev_path = base.to_vec();
        dev_path.push(TreeNode::Environment(dev));
        let mut prod_path = base.to_vec();
        prod_path.push(TreeNode::Environment(prod));
        let mut gen_path = base.to_vec();
        gen_path.push(TreeNode::General(item));
        assert_eq!(effective_role(&grants, &dev_path), TreeRole::Editor);
        assert_eq!(effective_role(&grants, &gen_path), TreeRole::Editor);
        assert_eq!(effective_role(&grants, &prod_path), TreeRole::NoAccess);
        assert_eq!(effective_role(&grants, &base[..3]), TreeRole::NoAccess);
    }

    #[test]
    fn grant_labelled_with_another_space_does_not_apply() {
        let s1 = Uuid::from_u128(1);
        let s2 = Uuid::from_u128(2);
        let g2 = Uuid::from_u128(3);
        // Admin of S1 tries to grant Admin on a group that lives in S2.
        let grants = vec![g(TreeNode::Group(g2), Some(s1), TreeRole::Admin)];
        let path = [TreeNode::Workspace, TreeNode::Space(s2), TreeNode::Group(g2)];
        assert_eq!(effective_role(&grants, &path), TreeRole::NoAccess);
        let honest = vec![g(TreeNode::Group(g2), Some(s2), TreeRole::Admin)];
        assert_eq!(effective_role(&honest, &path), TreeRole::Admin);
    }

    #[test]
    fn scope_permits_by_op() {
        let s = Uuid::from_u128(1);
        let scope = EventScope {
            space_id: s,
            path: vec![Uuid::from_u128(2), Uuid::from_u128(3), Uuid::from_u128(4)],
            target: ScopeTarget::Content,
            op: ScopeOp::Write,
        };
        let viewer = vec![g(TreeNode::Space(s), Some(s), TreeRole::Viewer)];
        let editor = vec![g(TreeNode::Space(s), Some(s), TreeRole::Editor)];
        assert!(!scope.permits(&viewer));
        assert!(scope.permits(&editor));
        let del = EventScope { op: ScopeOp::Delete, ..scope.clone() };
        assert!(!del.permits(&editor));
        let bad = EventScope { path: vec![], ..scope };
        assert!(!bad.permits(&editor));
    }

    #[test]
    fn downgrade_detection() {
        let s = Uuid::from_u128(1);
        let a = vec![g(TreeNode::Space(s), Some(s), TreeRole::Editor)];
        let b = vec![g(TreeNode::Space(s), Some(s), TreeRole::Viewer)];
        let c = vec![g(TreeNode::Space(s), Some(s), TreeRole::Admin)];
        assert!(is_downgrade(&a, &b));
        assert!(!is_downgrade(&a, &c));
        assert!(is_downgrade(&a, &[]));
    }

    #[test]
    fn grant_sets_roundtrip_through_postcard() {
        let s = Uuid::from_u128(9);
        let set = MemberGrantSet {
            secwet_id: s,
            member_id: s,
            version: 3,
            grants: vec![
                g(TreeNode::Workspace, None, TreeRole::Viewer),
                g(TreeNode::Environment(s), Some(s), TreeRole::NoAccess),
            ],
            issuer_device_id: "D".into(),
            issued_at: 1,
        };
        let bytes = postcard::to_stdvec(&set).unwrap();
        assert_eq!(postcard::from_bytes::<MemberGrantSet>(&bytes).unwrap(), set);
    }

    #[test]
    fn grant_validation() {
        let s = Uuid::from_u128(1);
        assert!(validate_grants(&[]).is_err());
        assert!(validate_grants(&[g(TreeNode::Group(s), None, TreeRole::Viewer)]).is_err());
        assert!(validate_grants(&[g(TreeNode::Workspace, None, TreeRole::Viewer)]).is_ok());
        assert!(validate_grants(&[g(TreeNode::Space(s), Some(s), TreeRole::NoAccess)]).is_err());
    }
}
