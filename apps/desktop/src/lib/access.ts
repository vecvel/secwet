/**
 * apps/desktop/src/lib/access.ts
 *
 * Pure role and permission helpers for member mode (docs/m7-m8-architecture.md §4).
 * No React, no IPC: every function here takes plain data so it can be unit tested.
 */
import type {
  AccessView,
  GrantInput,
  GroupView,
  ItemView,
  LinkStatusDto,
  ScopeNodeView,
  SpaceView,
  TreeNodeKind,
  TreeRole,
} from "./api";

/** Where an action happens, from the space down. Leave deeper levels unset for container actions. */
export interface NodePath {
  spaceId?: string | null;
  groupId?: string | null;
  itemId?: string | null;
  /** Set for content inside an environment. */
  environmentId?: string | null;
  /** True for item-wide content (the "General" scope, environment_id null). */
  general?: boolean;
}

export interface Permissions {
  role: TreeRole;
  readOnly: boolean;
  /** Read, reveal, copy, download. */
  canView: boolean;
  /** Create or update secrets, notes and files. */
  canWrite: boolean;
  /** Delete secrets, notes and files. */
  canDelete: boolean;
  /** Create, rename and delete groups, items and environments. */
  canManage: boolean;
  /** Invite people and change their access. */
  canShare: boolean;
}

export const ROLE_ORDER: TreeRole[] = ["admin", "editor", "viewer", "no_access"];

export const ROLE_LABELS: Record<TreeRole, string> = {
  admin: "Admin",
  editor: "Editor",
  viewer: "Viewer",
  no_access: "No access",
};

export const ROLE_DESCRIPTIONS: Record<TreeRole, string> = {
  admin: "Full control and can invite",
  editor: "Add and edit secrets, notes, files. Can't delete.",
  viewer: "Read, reveal, copy, download",
  no_access: "Hidden",
};

export function roleRank(role: TreeRole): number {
  switch (role) {
    case "admin":
      return 3;
    case "editor":
      return 2;
    case "viewer":
      return 1;
    default:
      return 0;
  }
}

export function isReadOnly(link: LinkStatusDto | null | undefined): boolean {
  return link?.state === "unlinked";
}

function sameNode(g: GrantInput, kind: TreeNodeKind, id: string | null): boolean {
  if (g.kind !== kind) return false;
  if (kind === "workspace") return true;
  return (g.id ?? null) === id;
}

/** Tree nodes from the workspace down to the deepest node the path names. */
export function pathNodes(path: NodePath): { kind: TreeNodeKind; id: string | null }[] {
  const nodes: { kind: TreeNodeKind; id: string | null }[] = [{ kind: "workspace", id: null }];
  if (path.spaceId) nodes.push({ kind: "space", id: path.spaceId });
  if (path.groupId) nodes.push({ kind: "group", id: path.groupId });
  if (path.itemId) {
    nodes.push({ kind: "item", id: path.itemId });
    if (path.environmentId) nodes.push({ kind: "environment", id: path.environmentId });
    else if (path.general) nodes.push({ kind: "general", id: path.itemId });
  }
  return nodes;
}

/**
 * Role at the deepest node of `path`. Mirrors `secwet_proto::collab::effective_role`:
 * the most specific explicit grant on the path wins. Owners (and a missing access view,
 * which means the backend predates member mode) are Admin everywhere.
 */
export function effectiveRole(access: AccessView | null | undefined, path: NodePath): TreeRole {
  if (!access || access.is_owner) return "admin";
  return roleFromGrants(access.grants, path);
}

export function roleFromGrants(grants: GrantInput[], path: NodePath): TreeRole {
  let role: TreeRole = "no_access";
  for (const node of pathNodes(path)) {
    const g = grants.find((x) => sameNode(x, node.kind, node.id));
    if (g) role = g.role;
  }
  return role;
}

export function permissionsFromRole(role: TreeRole, readOnly: boolean): Permissions {
  const rank = roleRank(role);
  return {
    role,
    readOnly,
    canView: rank >= 1,
    canWrite: !readOnly && rank >= 2,
    canDelete: !readOnly && rank >= 3,
    canManage: !readOnly && rank >= 3,
    canShare: !readOnly && rank >= 3,
  };
}

export function permissionsFor(
  access: AccessView | null | undefined,
  readOnly: boolean,
  path: NodePath
): Permissions {
  return permissionsFromRole(effectiveRole(access, path), readOnly);
}

/** Owners and anyone holding Admin on some node can open the Members section. */
export function canManageMembers(access: AccessView | null | undefined): boolean {
  if (!access || access.is_owner) return true;
  return access.grants.some((g) => g.role === "admin");
}

/** Creating spaces needs Admin at the workspace level (the owner, in practice). */
export function canCreateSpace(access: AccessView | null | undefined, readOnly: boolean): boolean {
  return !readOnly && effectiveRole(access, {}) === "admin";
}

/** Pairing adds an owner device; the relay refuses it from a member's device. */
export function canPairDevices(access: AccessView | null | undefined, readOnly: boolean): boolean {
  return !readOnly && (!access || access.is_owner);
}

/** Rotating the master key is for owner devices only; member devices never hold it. */
export function canRotateMasterKey(access: AccessView | null | undefined, readOnly: boolean): boolean {
  return !readOnly && (!access || access.is_owner);
}

/** The Personal space is never shared. */
export function isShareableSpace(space: Pick<SpaceView, "is_default"> | null | undefined): boolean {
  return Boolean(space) && !space!.is_default;
}

/** Resolves the space and group of an item from the cached tree. */
export function pathForItem(
  itemId: string,
  items: Pick<ItemView, "id" | "group_id" | "label_id">[],
  groups: Pick<GroupView, "id" | "space_id">[]
): NodePath {
  const item = items.find((i) => i.id === itemId);
  const groupId = item ? item.group_id ?? item.label_id : null;
  const group = groups.find((g) => g.id === groupId);
  return { spaceId: group?.space_id ?? null, groupId: groupId ?? null, itemId };
}

// ----------------------------------------------------------------------------
// Share dialog helpers
// ----------------------------------------------------------------------------

/** Explicit role per scope node; a missing key means "inherit from the parent". */
export type GrantDraft = Record<string, TreeRole>;

export function nodeKey(node: { kind: TreeNodeKind; id?: string | null }): string {
  return `${node.kind}:${node.id ?? ""}`;
}

/** Path of a scope node from the space down, built from the parent links. */
export function scopeNodePath(nodes: ScopeNodeView[], node: ScopeNodeView): NodePath {
  const byId = new Map<string, ScopeNodeView>();
  for (const n of nodes) {
    // General shares its id with the item, so index containers only.
    if (n.kind === "space" || n.kind === "group" || n.kind === "item") byId.set(n.id, n);
  }
  const path: NodePath = {};
  let cur: ScopeNodeView | undefined = node;
  while (cur) {
    if (cur.kind === "space") path.spaceId = cur.id;
    if (cur.kind === "group") path.groupId = cur.id;
    if (cur.kind === "item") path.itemId = cur.id;
    if (cur.kind === "environment") path.environmentId = cur.id;
    if (cur.kind === "general") path.general = true;
    cur = cur.parent_id ? byId.get(cur.parent_id) : undefined;
  }
  return path;
}

export function draftToGrants(nodes: ScopeNodeView[], draft: GrantDraft): GrantInput[] {
  return nodes
    .filter((n) => draft[nodeKey(n)] !== undefined)
    .map((n) => ({ kind: n.kind, id: n.id, role: draft[nodeKey(n)] }));
}

export function grantsToDraft(nodes: ScopeNodeView[], grants: GrantInput[]): GrantDraft {
  const draft: GrantDraft = {};
  for (const n of nodes) {
    const g = grants.find((x) => sameNode(x, n.kind, n.id));
    if (g) draft[nodeKey(n)] = g.role;
  }
  return draft;
}

/**
 * Role a node gets from its ancestors when it has no explicit grant of its own.
 * `baseGrants` are grants outside this space's tree that still apply, such as a
 * workspace-level grant the member already holds.
 */
export function inheritedRole(
  nodes: ScopeNodeView[],
  draft: GrantDraft,
  node: ScopeNodeView,
  baseGrants: GrantInput[] = []
): TreeRole {
  const parentPath = scopeNodePath(nodes, node);
  // Drop the node itself so only ancestors count.
  if (node.kind === "space") parentPath.spaceId = null;
  if (node.kind === "group") parentPath.groupId = null;
  if (node.kind === "item") parentPath.itemId = null;
  if (node.kind === "environment") parentPath.environmentId = null;
  if (node.kind === "general") parentPath.general = false;
  return roleFromGrants([...baseGrants, ...draftToGrants(nodes, draft)], parentPath);
}

/** At least one node in the space ends up readable, counting `baseGrants` (for example a workspace grant). */
export function hasReadableGrant(nodes: ScopeNodeView[], draft: GrantDraft, baseGrants: GrantInput[] = []): boolean {
  const grants = [...baseGrants, ...draftToGrants(nodes, draft)];
  return nodes.some((n) => roleRank(roleFromGrants(grants, scopeNodePath(nodes, n))) >= 1);
}

/** Grants that target nodes outside `nodes` (other spaces, the workspace) are kept as they are. */
export function grantsOutside(nodes: ScopeNodeView[], grants: GrantInput[]): GrantInput[] {
  const keys = new Set(nodes.map(nodeKey));
  return grants.filter((g) => !keys.has(nodeKey(g)));
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function isValidEmail(email: string): boolean {
  return EMAIL_RE.test(email.trim());
}

/** "Editor on Work, Viewer on Work / Backend". */
export function summarizeGrants(grants: { role: TreeRole; label: string }[]): string {
  if (grants.length === 0) return "No access yet";
  return grants.map((g) => `${ROLE_LABELS[g.role]} on ${g.label}`).join(", ");
}

/** Best guess of the space a grant lives in, for opening the access editor. */
export function spaceOfGrant(
  grant: GrantInput & { space_id?: string | null },
  groups: Pick<GroupView, "id" | "space_id">[],
  items: Pick<ItemView, "id" | "group_id" | "label_id">[]
): string | null {
  if (grant.space_id) return grant.space_id;
  if (grant.kind === "space") return grant.id ?? null;
  if (grant.kind === "group") return groups.find((g) => g.id === grant.id)?.space_id ?? null;
  if (grant.kind === "item" || grant.kind === "general") {
    return grant.id ? pathForItem(grant.id, items, groups).spaceId ?? null : null;
  }
  return null;
}
