# M7 and M8 architecture: revocation, key rotation, collaboration

This is the implementation contract for F16 (M7) and F19 (M8) across `secwet-proto`, `secwet-core`, `secwet-relay`, `secwet-cli` and `apps/desktop`. Wire types live in `crates/secwet-proto/src/collab.rs`.

## 1. Trust model (unchanged from §3)

The relay is untrusted for confidentiality and integrity. Every decision that destroys data or grants access is backed by an Ed25519 signature from a device the client already knows, or by an HKDF MAC keyed with a secret the relay never sees.

## 2. M7: revocation

### 2.1 Directive

An active device builds `RevocationDirective { secwet_id, target_device_id, issuer_device_id, wipe, issued_at }`, signs `directive.signing_bytes()` and posts `RevokeRequest { wipe, revocation }` to `POST /v1/secwets/{id}/devices/{device_id}/revoke` (signed request).

Relay checks, in order:

1. Caller is active (auth middleware) and belongs to the workspace.
2. `device_id != caller` (`400 cannot_revoke_self`).
3. Target exists in this workspace (`404 not_found`) and is not revoked yet (`409 already_revoked`; replays fail cleanly).
4. Caller may revoke the target: owner devices (`member_id IS NULL`) may revoke any device; a member device may revoke only devices of the same member (`403 forbidden`).
5. Directive fields equal the path and caller, `issued_at` is within 60 s of server time, signature verifies with `verify_strict` against the caller's `sign_pub` (`401 bad_signature`).

It then sets `revoked_at = now()`, `wipe_requested = wipe`, stores the postcard `SignedRevocation` in `devices.revocation`, and broadcasts the device id on the revocation channel so an open WebSocket for that device receives `{"type":"revoked","server_seq":0}` and is closed.

### 2.2 Revoked device behaviour

The auth middleware verifies the signature of a revoked device's request first, then answers `403` with body `{ "error": { "code": "revoked", ... }, "revocation": SignedRevocation }`. Unsigned or badly signed requests from a revoked id get the plain `403 revoked` with no directive.

Core (`Secwet::handle_revocation_notice`) accepts the directive only when: `secwet_id` and `target_device_id` match this device, the issuer is a different device, and the signature verifies against the issuer's `sign_pub` from the local `devices` table (refreshed from `GET /devices` when the issuer is unknown, the same trust rule as §15.4 step 2).

- `wipe = true`: **crypto-shred**. Delete every keystore entry of the workspace (`device-sign`, `device-enc`, `vault-key/1..=N`, legacy `master-key/*`, `branch-bundle/*`), close and delete the workspace directory (`secwet.sqlite3`, `-wal`, `-shm`, cached files), zeroize in-memory keys, return `RevocationOutcome::Wiped`. The desktop app emits `secwet://wiped` and returns to onboarding.
- `wipe = false`: set `meta.revoked_state = 'sync_only'`, `meta.revoked_at`. The store is a **read-only archive**: every mutating API returns `Error::Revoked`; reading, revealing and export keep working; sync is disabled. Desktop shows the banner "This device was unlinked from Secwet. Sync is disabled."

## 3. M7: master key rotation

Owner devices only (member devices never hold `K_m`).

1. `GET /v1/secwets/{id}/devices` → active owner devices (`member_id IS NULL AND revoked_at IS NULL`). Local `devices` table is updated (revocations mirrored).
2. Generate `K_m` for epoch `N+1` from `OsRng`. Wrap with HPKE (`wrap_for_device`, info `KeyWrapInfo { purpose: "master-key", secwet_id, key_epoch: N+1, recipient_device_id }`) for every active owner device including this one. Revoked devices are never recipients.
3. Sign `KeyRotationStatement { secwet_id, epoch, issuer_device_id, recipients (sorted) }`, post `KeyRotationRequest` to `POST /v1/secwets/{id}/keys`.
4. Relay: caller must be an owner device (`403 forbidden`), `statement.epoch == current_epoch + 1` else `409 epoch_conflict`, recipients must equal exactly the set of active owner devices and match `wrapped` (`400 invalid_request`), signature valid. In one transaction: `UPDATE secwets SET current_epoch = $e WHERE id = $id AND current_epoch = $e - 1` (0 rows → `409 epoch_conflict`), insert `wrapped_keys`.
5. Core on success: store `vault-key/{N+1}` in the keystore, set `meta.current_key_epoch`, add the epoch to the in-memory keyring, then **re-seal** local rows (`records`, `labels`, `spaces`, device names) whose `key_epoch < N+1`, `RESEAL_BATCH_SIZE = 100` rows per transaction, then re-wrap recovery keys (F9: `recovery_wrapped_master_keys` gains the new epoch; requires the keystore, done in `rotate_master_key`). A fresh snapshot is uploaded under the new epoch.
6. On `409 epoch_conflict` the loser calls `GET /v1/secwets/{id}/keys`, unwraps the winner's epoch, adopts it (keystore, meta, keyring, re-seal) and does not retry.

Re-sealing is local on every device (each device seals its own store); it is not re-broadcast as upserts because equal-content upserts with fresh lamports would clobber concurrent edits under last-writer-wins. New writes and events use epoch `N+1` immediately, so a revoked device that never receives `N+1` cannot decrypt anything written after the rotation.

**Catch-up**: at the start of every sync and whenever an event names an unknown `key_epoch`, core calls `GET /keys` and adopts any newer epochs (`refresh_master_keys`). Offline devices therefore pick up rotations on reconnect.

Keyring: `Secwet` keeps `BTreeMap<epoch, (K_rec, K_evt)>`. Sealing always uses the current epoch. Opening tries the epoch named in the AAD first, then every other known epoch (AAD rebuilt for that epoch), newest first; `labels`, `spaces` and device names have no epoch column, so this fallback is what lets them be read while a re-seal is in progress. Re-sealing walks `records` by `key_epoch < current` and re-seals the small `labels`, `spaces` and `devices` tables in full (idempotent, so an interrupted re-seal resumes safely).

## 4. M8: tree, roles, cascade

Tree: `Workspace → Space → Group → Item → { General | Environment }`. `TreeNode` names a node; a `MemberGrant { node, space_id, role }` assigns `TreeRole ∈ { Admin, Editor, Viewer, NoAccess }`.

`effective_role(grants, path)` walks from `Workspace` down; the most specific explicit grant wins, so parent grants cascade unless a child carries its own grant (including `NoAccess`).

| Op | Needs |
|---|---|
| Read, reveal, copy, download | Viewer |
| Create or update secret, note, file | Editor |
| Delete secret, note, file | Admin |
| Create, rename, delete group / item / environment | Admin |
| Invite, change roles, remove, rotate branch keys | Admin on the space (or workspace) |

The workspace owner's devices are Admin everywhere. The Personal space (`is_default`) can never be shared.

## 5. M8: branch keys (zero-knowledge scoping)

Each shared space has a random 32-byte root `S_space` per branch epoch. Node secrets derive downwards with HKDF-SHA256 (salt = workspace id bytes):

```
S_child  = HKDF(S_parent, info = "secwet/v1/branch/node"    || child_id)
K_name   = HKDF(S_node,   info = "secwet/v1/branch/name")
K_general= HKDF(S_item,   info = "secwet/v1/branch/general")
K_content= HKDF(S_env,    info = "secwet/v1/branch/content")
```

Event key for a scoped event = the target key (`K_name` of the record's node, `K_general` of its item, or `K_content` of its environment). Holding `S_N` gives everything below `N`; a restricted member instead receives exactly the keys it may use.

**Bundle computation** (admin side, `compute_bundle_entries`), recursively from the space root for each member:

- If the member can read node `N` and no grant strictly below `N` is `NoAccess`, emit `Subtree(N)` and stop (covers future children too).
- Otherwise recurse into children; for an item also emit `General(item)` when General is readable; if anything below was emitted, emit `Name(N)` so navigation can show the container name.

Owner devices receive `Subtree(space)`.

**Wrapping**: per device, a random bundle key is HPKE-wrapped (`purpose: "branch-bundle"`, `key_epoch` = branch epoch) and the postcard `BranchKeyBundle` is sealed with XChaCha20-Poly1305 under it (`ScopedBranchKey { wrapped, sealed_bundle }`). The publish is signed (`BranchPublishStatement`).

**Rotation** (member removed or downgraded): a new `S_space` at epoch `e+1`, bundles recomputed for remaining devices only, `rotate = true` publish (`409 epoch_conflict` on races), then the admin re-emits the space's current records as scoped upserts under `e+1` with their stored lamports (idempotent for holders: equal `(lamport, origin)` never replaces). New writes use `e+1`; the removed member never receives `e+1`.

**At rest**: each device seals its local store with its own store key (owner devices: workspace `K_rec`; member devices: a member-local key that never leaves the device). Branch keys protect everything that leaves a device (events, routing on the relay). A member's store only ever contains records it could decrypt.

## 6. M8: scoped events

`EventEnvelope.scope: Option<EventScope { space_id, path, target, op }>` is clear routing metadata covered by the signature (`EventEnvelope::signing_bytes`). Unscoped events (workspace-private) are delivered to owner devices only and never accepted from member devices.

Relay on push from a member device: `scope` must be present and `scope.permits(member_grants)`; otherwise the event is consumed (its `device_seq` advances) but not stored and its id is returned in `PushEventsResponse.rejected`. Owner devices are unrestricted.

Relay on pull: owner devices get everything; member devices get only `scope_space ∈ granted_spaces(grants)` (all scoped events for a workspace-level grant). Member devices get `403 forbidden` on the workspace snapshot.

Clients re-check on apply: an event from a member device whose scope is not permitted by that member's signed grant set is dropped (`viewer_role_rejects_write_events`). Events the device cannot decrypt (no key for that branch) are skipped and the cursor advances.

## 7. M8: invitations

1. Admin: `invite_member(email, grants)` creates `invitation_id`, `member_id`, a 32-byte token `T`. `auth = HKDF(T, salt = invitation_id, info = "secwet/v1/invite-auth")`; relay stores `token_hash = SHA-256(auth)` and `email_hash = SHA-256("secwet-email-v1" || secwet_id || lowercase(trim(email)))`. The inviter keeps `T` and the email sealed in its local `collab_invitations` table. Link: `secwet://invite?v=1&w=<secwet_id>&i=<invitation_id>&t=<base64url T>&r=<relay url>`. The admin sends the link to the invitee (Secwet has no mail provider; the link is the delivery channel).
2. Invitee: `Secwet::accept_invitation(data_dir, link, email, device_name, keystore)` creates a member store (fresh device keys, member-local store key), computes `binding = HKDF(T, salt = invitation_id, info = "secwet/v1/invite-binding" || sign_pub || enc_pub)` and posts `AcceptInvitationRequest` to `POST /v1/invitations/{id}/accept` (unauthenticated, IP rate-limited). The relay checks expiry (`403 invalid_invitation`), status pending (`409 already_joined`), `SHA-256(auth)` and `email_hash` in constant time, the proof signature, then registers the device with `member_id` and marks the invitation accepted.
3. Inviter's next sync (`process_invitations`): for each accepted invitation it created, verify `binding` with its stored `T` (a relay that swapped keys fails here; the invitation is revoked), then publish bundles for every space the grants touch, and mark the invitation active.
4. Member device: `refresh_branch_keys` unwraps its bundles, stores them in the keystore (`branch-bundle/<space>/<epoch>`), pulls events and populates the authorized tree.

## 8. Relay schema (migration 0002)

```sql
ALTER TABLE devices ADD COLUMN member_id UUID, wipe_requested BOOLEAN NOT NULL DEFAULT false, revocation BYTEA;
ALTER TABLE events  ADD COLUMN scope_space UUID;
CREATE TABLE workspace_members (secwet_id UUID REFERENCES secwets ON DELETE CASCADE, member_id UUID, email_hash BYTEA NOT NULL,
  status TEXT NOT NULL, grants BYTEA NOT NULL, grants_version BIGINT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  removed_at TIMESTAMPTZ, PRIMARY KEY (secwet_id, member_id));
CREATE TABLE member_grants (secwet_id UUID, member_id UUID, node_kind TEXT, node_id UUID, space_id UUID, role TEXT, ...);
CREATE TABLE invitations (id UUID PRIMARY KEY, secwet_id UUID, member_id UUID, email_hash BYTEA, token_hash BYTEA, created_by TEXT,
  created_at TIMESTAMPTZ, expires_at TIMESTAMPTZ, status TEXT, acceptance BYTEA, accepted_device_id TEXT);
CREATE TABLE branch_scopes (secwet_id UUID, space_id UUID, current_epoch INT, PRIMARY KEY (secwet_id, space_id));
CREATE TABLE branch_keys (secwet_id UUID, space_id UUID, epoch INT, device_id TEXT, wrapped BYTEA, sealed_bundle BYTEA,
  PRIMARY KEY (secwet_id, space_id, epoch, device_id));
```

No column holds names, emails, values or keys in plaintext.

## 9. Relay endpoints

| Method and path | Caller | Errors |
|---|---|---|
| `GET /v1/secwets/{id}/devices` | device | |
| `POST /v1/secwets/{id}/devices/{device}/revoke` | active device | `cannot_revoke_self`, `already_revoked`, `forbidden`, `bad_signature`, `not_found` |
| `POST /v1/secwets/{id}/keys` | owner device | `epoch_conflict`, `forbidden`, `invalid_request`, `bad_signature` |
| `GET /v1/secwets/{id}/keys` | device | |
| `GET /v1/secwets/{id}/access` | device | |
| `GET /v1/secwets/{id}/members` | owner device or member admin | `forbidden` |
| `POST /v1/secwets/{id}/invitations` | admin | `exists`, `forbidden`, `invalid_request` |
| `DELETE /v1/secwets/{id}/invitations/{inv}` | admin | `not_found` |
| `POST /v1/invitations/{inv}/accept` | anyone (rate-limited) | `invalid_invitation`, `already_joined`, `expired`, `bad_signature` |
| `POST /v1/secwets/{id}/invitations/{inv}/activate` | inviter | |
| `PUT /v1/secwets/{id}/members/{member}/grants` | admin | `forbidden`, `epoch_conflict` (stale version) |
| `POST /v1/secwets/{id}/members/{member}/remove` | admin | `forbidden`, `not_found` |
| `POST /v1/secwets/{id}/spaces/{space}/keys` | admin of that space | `epoch_conflict`, `forbidden`, `bad_signature` |
| `GET /v1/secwets/{id}/branch-keys` | device | |

## 10. Desktop IPC (Tauri commands)

The logic behind these commands is in `crates/secwet-app` (`collab.rs`), shared with the mobile hosts; see `docs/app-layer.md`.

| Command | Args | Returns |
|---|---|---|
| `device_revoke` | `deviceId, wipe` | `RevokeResultDto { device_id, wipe_requested, rotation_recommended }` |
| `key_status` | | `KeyStatusDto { epoch, rotated_at, rotation_recommended, pending_reason }` |
| `key_rotate` | | `KeyRotationReport { previous_epoch, epoch, resealed, recipients, adopted_from_conflict }` |
| `link_status` | | `LinkStatusDto { state: "active" \| "unlinked", revoked_at }` |
| `members_list` | | `MemberView[]` |
| `member_invite` | `email, grants: GrantInput[]` | `InviteResultDto { invitation_id, member_id, link, expires_at }` |
| `member_set_grants` | `memberId, grants` | `MemberView` |
| `member_remove` | `memberId, wipe` | |
| `invitation_revoke` | `invitationId` | |
| `invitation_accept` | `link, email, deviceName` | `SecwetStatus` |
| `scope_nodes` | `spaceId` | `ScopeNodeView[]` |
| `my_access` | | `AccessView { is_owner, grants: GrantView[] }` |

Events: `secwet://wiped` (store crypto-shredded, go to onboarding), `secwet://unlinked` (sync-only revocation).

## 11. Hardening after review (supersedes earlier sections where they differ)

The security and systems reviews found that clients trusted the relay's device list and key deliveries. The rules below are now enforced; every item has a regression test (`crates/secwet-core/tests/m7_m8_core_tests.rs`, `crates/secwet-relay/tests/m7_m8_e2e.rs`, `crates/secwet-relay/tests/m7_m8_relay_tests.rs`).

**Device trust.** `devices.trust` is `self`, `certified` or `relay`. A device becomes `certified` only through:
- the pairing approver after comparing codes (`record_paired_device`);
- the inviter verifying an invite binding (`process_invitations`);
- an `EventBody::DeviceCertified` sealed with the current workspace event key from a non-member sender;
- a `SignedDeviceCertificate` from the relay's certificate store whose certifier is already trusted and not revoked (chains are followed);
- the inviter named in the invite link (`a`, `s`, `e`, and `m` when the inviter is a member admin);
- on member stores only, the `admins` list of a bundle whose issuer is a trusted owner device.

Relay-listed devices are stored as `relay`: their signatures can be checked, but they never receive keys, never issue wipes and never count as owners. Refreshing from the relay only mirrors revocations. Stores upgraded from earlier builds trust only themselves until the other devices re-certify.

**Key deliveries.** `KeyRotationStatement.key_commitment = HKDF(K_m, secwet_id, "secwet/v1/key-commit")`. A device adopts epoch `N+1` only from a statement signed by itself or a trusted, non-revoked owner device that names it and commits to the unwrapped key. Bundles arrive with the signed publish statement (`ScopedBranchKey.statement`) listing a SHA-256 digest per recipient. A root already held for a space and epoch is never replaced.

**Writes.** Records never change type. An existing record never moves between branches. Grants only count inside the space they name. Grant sets must name the member, come from a trusted owner device (or a member admin of every space they grant), and only ever move forward in version; removed stays removed. Member lamports are capped.

**Delivery.** Events that cannot be read or attributed yet are deferred (`collab_deferred`), retried after keys, certificates or grants arrive, and expire after 30 days. The cursor never rewinds. A write in a shared space whose key has not arrived is queued (`collab_pending_emit`), never sent unscoped. Seeds (`EventBody::Seed`) are insert-only with the original author as origin. Members start at the relay head on joining. Empty pulls advance and ack the head. Expiry for members is computed per visible space.

**Forward secrecy.** Branch rotations for revocations, removals and downgrades are queued durably (`collab_pending`) before the relay call and finished on the next sync. Revoking an owner device rotates every shared space the store administers. Revoking a member device rotates that member's spaces. A rotation conflict is adopted and then rotated past once more. The relay rejects stale epochs (owner devices: the whole batch, 409; member devices: the role check runs first and unpermitted events are consumed). Clients re-encrypt their outbox when an epoch changes.

**Wipe robustness.** Handling a revocation notice is idempotent. Keystore entries a wipe could not delete are recorded by name in `.secwet-pending-wipe-<id>` and retried at startup (`Secwet::finish_pending_wipes`).

**Known limits (documented, not hidden).**
- A device revoked during epoch `N` still holds epoch `N` until a rotation.
- Member stores accept other members' writes on the relay's role enforcement (they do not hold other members' signed grants).
- A rotation statement whose issuer is revoked before a lagging device catches up is not adopted. That device must be paired again.
- The relay sees routing metadata: space, group, item and environment ids, plus event timing.
