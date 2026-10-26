/**
 * apps/desktop/src/lib/api.ts
 *
 * Typed Tauri 2 IPC client and seamless browser mock fallback.
 * Authoritative: docs/IMPLEMENTATION.md §9.1, §9.2, and secwet-proto.
 */
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { type SecretKind } from "../data/mock";

// ============================================================================
// 1. Data Types Matching Section 9.1 & secwet-proto
// ============================================================================

export type { SecretKind };

export interface GroupView {
  id: string;
  name: string;
  position: number;
  icon?: string | null;
  items_count: number;
}
export type LabelView = GroupView;

export interface ItemView {
  id: string;
  label_id: string;
  group_id?: string;
  name: string;
  description?: string | null;
  position: number;
  environments_count: number;
  secrets_count: number;
  assets_count: number;
  files_count: number;
  notes_count: number;
}

export interface EnvironmentView {
  id: string;
  project_id: string;
  item_id?: string;
  name: string;
  position: number;
  secret_count: number;
}

export interface ProjectView {
  id: string;
  name: string;
  environments: EnvironmentView[];
}

export interface SecretMeta {
  id: string;
  project_id: string;
  environment_id?: string | null;
  name: string;
  kind: SecretKind;
  note?: string;
  updated_at: number;
  value_tail: string;
  // Compatibility aliases
  item_id?: string;
  projectId?: string;
  environmentId?: string | null;
  updatedAt?: number;
}

export interface SecretDraft {
  item_id?: string;
  project_id?: string;
  environment_id?: string | null;
  name: string;
  kind: SecretKind;
  value: string;
  note?: string | null;
  // Compatibility aliases
  projectId?: string;
  environmentId?: string | null;
}

export interface AssetMetaView {
  id: string;
  item_id: string;
  environment_id?: string | null;
  name: string;
  size_bytes: number;
  mime_type: string;
  sha256: string;
  updated_at: number;
}

export type FileMetaView = AssetMetaView;

export interface AssetDownloadResult {
  meta: AssetMetaView;
  bytes: number[];
}

export type FileDownloadResult = AssetDownloadResult;

export interface NoteMetaView {
  id: string;
  item_id: string;
  environment_id?: string | null;
  title: string;
  snippet: string;
  updated_at: number;
  position: number;
}

export interface NoteView {
  id: string;
  item_id: string;
  environment_id?: string | null;
  title: string;
  content: string;
  updated_at: number;
  position: number;
}

export interface NoteDraft {
  item_id: string;
  environment_id?: string | null;
  title: string;
  content: string;
}

export interface NoteUpdateDraft {
  title?: string | null;
  content?: string | null;
}

export interface DashboardConfig {
  home_label: string;
  visible_kpis: string[];
  widgets: string[];
}

export type VaultStatus =
  | { status: "uninitialized" }
  | { status: "locked"; vault_id?: string }
  | { status: "unlocked"; vault_id?: string }
  | "Uninitialized"
  | { Locked: { vault_id: string } }
  | { Unlocked: { vault_id: string } };

export interface RecentSecret {
  id: string;
  name: string;
  project_id: string;
  project_name: string;
  environment_id: string;
  environment_name: string;
  updated_at: number;
  item_id?: string;
  item_name?: string;
}

export interface ChecklistState {
  vault_created: boolean;
  recovery_key_created: boolean;
  cli_connected: boolean;
  add_device_done: boolean;
  pending_rotation?: string;
}

export interface Overview {
  labels_count: number;
  groups_count?: number;
  items_count: number;
  projects_count: number;
  environments_count: number;
  secrets_count: number;
  assets_count: number;
  files_count: number;
  notes_count: number;
  active_devices_count: number;
  projects: ProjectView[];
  recent: RecentSecret[];
  checklist: ChecklistState;
}

export interface Settings {
  theme: "system" | "light" | "dark";
  lock_timeout_minutes: number;
  lock_minutes: number;
  device_name: string;
  home_label?: string;
}

export interface SettingsPatch {
  theme?: string;
  lock_timeout_minutes?: number;
  lock_minutes?: number;
  device_name?: string;
  home_label?: string;
}

export interface DeviceView {
  id: string;
  name: string;
  platform: string;
  fingerprint: string;
  added_at: number;
  last_sync_at?: number;
  revoked_at?: number;
  current?: boolean;
}

export interface UiError {
  code: string;
  field?: string;
  message: string;
}

export interface VaultChangedEvent {
  scope: string; // "labels" | "items" | "environments" | "secrets" | "files" | "notes" | "dashboard" | "settings" | "all"
}

export interface SyncStatusEvent {
  state: "idle" | "syncing" | "offline" | "paused";
  detail?: string;
}

export interface SyncReport {
  pushed: number;
  pulled: number;
}

// ============================================================================
// 2. Helpers for VaultStatus and Errors
// ============================================================================

export function isUnlocked(status: VaultStatus | null | undefined): boolean {
  if (!status) return false;
  if (typeof status === "object") {
    if ("status" in status && status.status === "unlocked") return true;
    if ("Unlocked" in status) return true;
  }
  return false;
}

export function isLocked(status: VaultStatus | null | undefined): boolean {
  if (!status) return false;
  if (typeof status === "object") {
    if ("status" in status && status.status === "locked") return true;
    if ("Locked" in status) return true;
  }
  return false;
}

export function isUninitialized(status: VaultStatus | null | undefined): boolean {
  if (!status) return false;
  if (typeof status === "string") return status === "Uninitialized";
  if (typeof status === "object" && "status" in status && status.status === "uninitialized") return true;
  return false;
}

export function getVaultId(status: VaultStatus | null | undefined): string | undefined {
  if (!status || typeof status !== "object") return undefined;
  if ("vault_id" in status && typeof status.vault_id === "string") return status.vault_id;
  if ("Unlocked" in status) return status.Unlocked.vault_id;
  if ("Locked" in status) return status.Locked.vault_id;
  return undefined;
}

/**
 * Maps a UiError to an end-user message following Section 9.2 item 5 & Section 10 rules.
 */
export function formatUiError(err: unknown, defaultMessage = "Something went wrong. Try again."): string {
  if (!err) return defaultMessage;
  if (typeof err === "string") return err;
  const uiErr = err as Partial<UiError>;

  if (import.meta.env.DEV && uiErr.code) {
    console.error("[Secwet Error Code]", uiErr.code);
  }

  const code = uiErr.code?.toLowerCase();
  switch (code) {
    case "duplicate":
      return uiErr.message || "An item with this name already exists.";
    case "lastenvironment":
    case "last_environment":
      return "Cannot delete the last environment.";
    case "locked":
    case "vault_locked":
      return "Secwet is locked. Unlock it to continue.";
    case "crypto":
    case "crypto_error":
      return "This item could not be decrypted.";
    case "invalid":
      return uiErr.message || "Please check your inputs.";
    case "already_initialized":
      return "Secwet is already initialized on this device.";
    case "not_found":
      return "Item not found.";
    case "keystore_error":
      return "Secure storage error.";
    default:
      return uiErr.message || defaultMessage;
  }
}

// ============================================================================
// 3. Runtime Detection & Fallback Mock Implementation
// ============================================================================

export const isTauri = (): boolean =>
  typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

/** In-memory mock store for web browser preview (`pnpm desktop:dev`). */
export class BrowserMockBackend {
  private status: VaultStatus = { status: "unlocked", vault_id: "00000000-0000-0000-0000-000000000001" };
  private labels: LabelView[];
  private items: ItemView[];
  private environments: EnvironmentView[];
  private secrets: Array<{
    id: string;
    item_id: string;
    environment_id?: string | null;
    name: string;
    kind: SecretKind;
    value: string;
    note?: string | null;
    updated_at: number;
  }>;
  private files: Array<{
    id: string;
    item_id: string;
    environment_id?: string | null;
    name: string;
    size_bytes: number;
    mime_type: string;
    sha256: string;
    updated_at: number;
    bytes: number[];
  }>;
  private notes: Array<{
    id: string;
    item_id: string;
    environment_id?: string | null;
    title: string;
    content: string;
    updated_at: number;
    position: number;
  }>;
  private dashboardConfig: DashboardConfig = {
    home_label: "Overview",
    visible_kpis: ["items", "secrets", "files", "notes", "devices"],
    widgets: ["recent_secrets", "recent_notes", "quick_actions", "checklist"],
  };
  private settings: Settings = {
    theme: "system",
    lock_timeout_minutes: 15,
    lock_minutes: 15,
    device_name: "Desktop",
    home_label: "Overview",
  };
  private devices: DeviceView[] = [
    {
      id: "dev-local-1",
      name: "Desktop",
      platform: "macOS",
      fingerprint: "482913",
      added_at: Date.now() - 86400000 * 3,
      current: true,
    },
  ];
  private cliConnected = false;
  private recoveryCreated = false;
  private listeners = new Map<string, Set<(payload: any) => void>>();

  constructor() {
    this.labels = [
      { id: "lbl-proj", name: "Projects", position: 0, icon: "folder", items_count: 2 },
      { id: "lbl-pers", name: "Personal", position: 1, icon: "key", items_count: 1 },
      { id: "lbl-work", name: "Work", position: 2, icon: "devices", items_count: 0 },
    ];

    this.items = [
      {
        id: "item-payments",
        label_id: "lbl-proj",
        name: "Payments API",
        description: "Stripe and billing microservices",
        position: 0,
        environments_count: 2,
        secrets_count: 2,
        assets_count: 1,
        files_count: 1,
        notes_count: 1,
      },
      {
        id: "item-frontend",
        label_id: "lbl-proj",
        name: "Frontend App",
        description: "Desktop and mobile client bundles",
        position: 1,
        environments_count: 0, // 0 environments to test zero-env behavior!
        secrets_count: 2,
        assets_count: 1,
        files_count: 1,
        notes_count: 1,
      },
      {
        id: "item-creds",
        label_id: "lbl-pers",
        name: "Master Credentials",
        description: "Personal keys and seeds",
        position: 0,
        environments_count: 0,
        secrets_count: 1,
        assets_count: 0,
        files_count: 0,
        notes_count: 0,
      },
    ];

    this.environments = [
      { id: "env-prod", project_id: "item-payments", item_id: "item-payments", name: "Production", position: 0, secret_count: 2 },
      { id: "env-stag", project_id: "item-payments", item_id: "item-payments", name: "Staging", position: 1, secret_count: 0 },
    ];

    this.secrets = [
      {
        id: "sec-stripe-live",
        item_id: "item-payments",
        environment_id: "env-prod",
        name: "STRIPE_SECRET_KEY",
        kind: "api_key",
        value: "mock_sec_stripe_test_key_12345",
        note: "Rotated quarterly via dashboard",
        updated_at: Date.now() - 3600000,
      },
      {
        id: "sec-paypal",
        item_id: "item-payments",
        environment_id: "env-prod",
        name: "PAYPAL_CLIENT_SECRET",
        kind: "password",
        value: "EILiveSecret9876543210PayPal",
        note: "Webhook signature verification",
        updated_at: Date.now() - 7200000,
      },
      {
        id: "sec-endpoint",
        item_id: "item-frontend",
        environment_id: null,
        name: "VITE_API_ENDPOINT",
        kind: "env_var",
        value: "https://api.secwet.dev/v1",
        note: "Item-level base URL",
        updated_at: Date.now() - 1800000,
      },
      {
        id: "sec-sentry",
        item_id: "item-frontend",
        environment_id: null,
        name: "SENTRY_AUTH_TOKEN",
        kind: "access_token",
        value: "mock_sentry_token_123456",
        note: "Release source map upload",
        updated_at: Date.now() - 900000,
      },
      {
        id: "sec-gh",
        item_id: "item-creds",
        environment_id: null,
        name: "GITHUB_PAT",
        kind: "access_token",
        value: "mock_github_pat_token_abc123",
        note: "Repo and workflow permissions",
        updated_at: Date.now() - 14400000,
      },
    ];

    const sampleMd = "# Payments API Specification\n\nAll endpoints require Bearer auth.\n\n- POST /charges\n- GET /invoices\n- POST /webhooks\n";
    const sampleMdBytes = Array.from(new TextEncoder().encode(sampleMd));

    const sampleSvg = `<svg viewBox="0 0 24 24" fill="none" stroke="#3D6A4C" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>`;
    const sampleSvgBytes = Array.from(new TextEncoder().encode(sampleSvg));

    this.files = [
      {
        id: "file-spec-1",
        item_id: "item-payments",
        environment_id: "env-prod",
        name: "api-spec.md",
        size_bytes: sampleMdBytes.length,
        mime_type: "text/markdown",
        sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        updated_at: Date.now() - 3600000,
        bytes: sampleMdBytes,
      },
      {
        id: "file-logo-2",
        item_id: "item-frontend",
        environment_id: null,
        name: "app-mark.svg",
        size_bytes: sampleSvgBytes.length,
        mime_type: "image/svg+xml",
        sha256: "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
        updated_at: Date.now() - 1800000,
        bytes: sampleSvgBytes,
      },
    ];

    this.notes = [
      {
        id: "note-payments-guidelines",
        item_id: "item-payments",
        environment_id: "env-prod",
        title: "Deployment Guidelines",
        content: "<h2>Deployment Process</h2><p>Always verify database migrations in staging before releasing to production.</p><ul><li>Run migrations</li><li>Verify webhooks</li><li>Rotate secrets if compromised</li></ul>",
        updated_at: Date.now() - 3600000,
        position: 0,
      },
      {
        id: "note-frontend-release",
        item_id: "item-frontend",
        environment_id: null,
        title: "Release Checklist",
        content: "<h3>Client Release Steps</h3><ol><li>Run typecheck and unit tests</li><li>Audit bundle size &lt; 5MB</li><li>Publish desktop package</li></ol>",
        updated_at: Date.now() - 1800000,
        position: 0,
      },
    ];
  }

  private emit(event: string, payload?: any) {
    const handlers = this.listeners.get(event);
    if (handlers) {
      handlers.forEach((h) => {
        try {
          h(payload);
        } catch (e) {
          console.error("Mock event handler error:", e);
        }
      });
    }
  }

  public listen(event: string, handler: (payload: any) => void): UnlistenFn {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    this.listeners.get(event)!.add(handler);
    return () => {
      this.listeners.get(event)?.delete(handler);
    };
  }

  private updateCounts() {
    for (const item of this.items) {
      item.environments_count = this.environments.filter((e) => e.project_id === item.id).length;
      item.secrets_count = this.secrets.filter((s) => s.item_id === item.id).length;
      item.assets_count = this.files.filter((f) => f.item_id === item.id).length;
      item.files_count = item.assets_count;
      item.notes_count = this.notes.filter((n) => n.item_id === item.id).length;
    }
    for (const label of this.labels) {
      label.items_count = this.items.filter((i) => i.label_id === label.id).length;
    }
    for (const env of this.environments) {
      env.secret_count = this.secrets.filter((s) => s.environment_id === env.id).length;
    }
  }

  // 1. Lifecycle
  async vaultStatus(): Promise<VaultStatus> {
    return this.status;
  }

  async vaultCreate(deviceName?: string): Promise<VaultStatus> {
    this.status = { status: "unlocked", vault_id: crypto.randomUUID() };
    if (deviceName) this.settings.device_name = deviceName;
    this.emit("vault://changed", { scope: "all" });
    return this.status;
  }

  async vaultUnlock(): Promise<void> {
    this.status = { status: "unlocked", vault_id: "00000000-0000-0000-0000-000000000001" };
    this.emit("vault://changed", { scope: "all" });
  }

  async vaultLock(): Promise<void> {
    this.status = { status: "locked", vault_id: "00000000-0000-0000-0000-000000000001" };
    this.emit("vault://locked");
  }

  // 2. Groups & Labels
  async groupsList(): Promise<GroupView[]> {
    this.updateCounts();
    return JSON.parse(JSON.stringify(this.labels.sort((a, b) => a.position - b.position)));
  }

  async groupCreate(name: string, icon?: string | null): Promise<GroupView> {
    const trimmed = name.trim();
    if (this.labels.some((l) => l.name.toLowerCase() === trimmed.toLowerCase())) {
      throw { code: "duplicate", message: `A group called "${trimmed}" already exists.` };
    }
    const newGroup: GroupView = {
      id: crypto.randomUUID(),
      name: trimmed,
      position: this.labels.length,
      icon: icon || null,
      items_count: 0,
    };
    this.labels.push(newGroup);
    this.emit("vault://changed", { scope: "groups" });
    this.emit("vault://changed", { scope: "labels" });
    return newGroup;
  }

  async groupRename(id: string, name: string, icon?: string | null): Promise<void> {
    const l = this.labels.find((x) => x.id === id);
    if (!l) throw { code: "not_found", message: "Group not found" };
    l.name = name.trim();
    if (icon !== undefined) l.icon = icon;
    this.emit("vault://changed", { scope: "groups" });
    this.emit("vault://changed", { scope: "labels" });
  }

  async groupDelete(id: string): Promise<void> {
    this.labels = this.labels.filter((l) => l.id !== id);
    const itemIds = this.items.filter((i) => i.label_id === id).map((i) => i.id);
    this.items = this.items.filter((i) => i.label_id !== id);
    this.environments = this.environments.filter((e) => !itemIds.includes(e.project_id));
    this.secrets = this.secrets.filter((s) => !itemIds.includes(s.item_id));
    this.files = this.files.filter((f) => !itemIds.includes(f.item_id));
    this.notes = this.notes.filter((n) => !itemIds.includes(n.item_id));
    this.updateCounts();
    this.emit("vault://changed", { scope: "groups" });
    this.emit("vault://changed", { scope: "labels" });
  }

  async groupReorder(ids: string[]): Promise<void> {
    ids.forEach((id, pos) => {
      const l = this.labels.find((x) => x.id === id);
      if (l) l.position = pos;
    });
    this.emit("vault://changed", { scope: "groups" });
    this.emit("vault://changed", { scope: "labels" });
  }

  async labelsList(): Promise<LabelView[]> {
    return this.groupsList();
  }

  async labelCreate(name: string, icon?: string | null): Promise<LabelView> {
    return this.groupCreate(name, icon);
  }

  async labelRename(id: string, name: string, icon?: string | null): Promise<void> {
    return this.groupRename(id, name, icon);
  }

  async labelDelete(id: string): Promise<void> {
    return this.groupDelete(id);
  }

  async labelReorder(ids: string[]): Promise<void> {
    return this.groupReorder(ids);
  }

  // 3. Items
  async itemsList(labelId?: string | null): Promise<ItemView[]> {
    this.updateCounts();
    let res = this.items;
    if (labelId) {
      res = res.filter((i) => i.label_id === labelId);
    }
    return JSON.parse(JSON.stringify(res.sort((a, b) => a.position - b.position)));
  }

  async itemCreate(labelId: string, name: string, description?: string | null): Promise<ItemView> {
    const trimmed = name.trim();
    if (this.items.some((i) => i.label_id === labelId && i.name.toLowerCase() === trimmed.toLowerCase())) {
      throw { code: "duplicate", message: `An item called "${trimmed}" already exists under this label.` };
    }
    const newItem: ItemView = {
      id: crypto.randomUUID(),
      label_id: labelId,
      name: trimmed,
      description: description?.trim() || null,
      position: this.items.filter((i) => i.label_id === labelId).length,
      environments_count: 0,
      secrets_count: 0,
      assets_count: 0,
      files_count: 0,
      notes_count: 0,
    };
    this.items.push(newItem);
    this.updateCounts();
    this.emit("vault://changed", { scope: "items" });
    return newItem;
  }

  async itemRename(id: string, name: string, description?: string | null): Promise<void> {
    const it = this.items.find((x) => x.id === id);
    if (!it) throw { code: "not_found", message: "Item not found" };
    it.name = name.trim();
    if (description !== undefined) it.description = description?.trim() || null;
    this.emit("vault://changed", { scope: "items" });
  }

  async itemDelete(id: string): Promise<void> {
    this.items = this.items.filter((i) => i.id !== id);
    this.environments = this.environments.filter((e) => e.project_id !== id);
    this.secrets = this.secrets.filter((s) => s.item_id !== id);
    this.files = this.files.filter((f) => f.item_id !== id);
    this.notes = this.notes.filter((n) => n.item_id !== id);
    this.updateCounts();
    this.emit("vault://changed", { scope: "items" });
  }

  // 4. Environments
  async environmentsList(itemId: string): Promise<EnvironmentView[]> {
    return JSON.parse(
      JSON.stringify(
        this.environments
          .filter((e) => e.project_id === itemId || e.item_id === itemId)
          .sort((a, b) => a.position - b.position)
      )
    );
  }

  async environmentAdd(itemId: string, name: string): Promise<EnvironmentView> {
    const trimmed = name.trim();
    const envs = this.environments.filter((e) => e.project_id === itemId || e.item_id === itemId);
    if (envs.some((e) => e.name.toLowerCase() === trimmed.toLowerCase())) {
      throw { code: "duplicate", message: `An environment called "${trimmed}" already exists.` };
    }
    const newEnv: EnvironmentView = {
      id: crypto.randomUUID(),
      project_id: itemId,
      item_id: itemId,
      name: trimmed,
      position: envs.length,
      secret_count: 0,
    };
    this.environments.push(newEnv);
    this.updateCounts();
    this.emit("vault://changed", { scope: "environments" });
    return newEnv;
  }

  async environmentRename(id: string, name: string): Promise<void> {
    const env = this.environments.find((e) => e.id === id);
    if (!env) throw { code: "not_found", message: "Environment not found" };
    env.name = name.trim();
    this.emit("vault://changed", { scope: "environments" });
  }

  async environmentDelete(id: string, preserveContent?: boolean | null): Promise<void> {
    const env = this.environments.find((e) => e.id === id);
    if (!env) throw { code: "not_found", message: "Environment not found" };

    if (preserveContent) {
      // Move content to item level
      for (const s of this.secrets) {
        if (s.environment_id === id) s.environment_id = null;
      }
      for (const f of this.files) {
        if (f.environment_id === id) f.environment_id = null;
      }
      for (const n of this.notes) {
        if (n.environment_id === id) n.environment_id = null;
      }
    } else {
      this.secrets = this.secrets.filter((s) => s.environment_id !== id);
      this.files = this.files.filter((f) => f.environment_id !== id);
      this.notes = this.notes.filter((n) => n.environment_id !== id);
    }

    this.environments = this.environments.filter((e) => e.id !== id);
    this.updateCounts();
    this.emit("vault://changed", { scope: "environments" });
  }

  // 5. Secrets
  async secretsList(itemId?: string | null, environmentId?: string | null): Promise<SecretMeta[]> {
    return this.secrets
      .filter((s) => {
        if (itemId && s.item_id !== itemId) return false;
        if (environmentId !== undefined && environmentId !== null && s.environment_id !== environmentId) return false;
        return true;
      })
      .map((s) => ({
        id: s.id,
        project_id: s.item_id,
        item_id: s.item_id,
        environment_id: s.environment_id ?? null,
        name: s.name,
        kind: s.kind,
        note: s.note ?? undefined,
        updated_at: s.updated_at,
        value_tail: s.value.replace(/\s+/g, "").slice(-4),
        projectId: s.item_id,
        environmentId: s.environment_id ?? undefined,
        updatedAt: s.updated_at,
      }));
  }

  async secretReveal(id: string): Promise<string> {
    const s = this.secrets.find((x) => x.id === id);
    if (!s) throw { code: "not_found", message: "Secret not found" };
    return s.value;
  }

  async secretCopy(id: string): Promise<void> {
    const s = this.secrets.find((x) => x.id === id);
    if (!s) throw { code: "not_found", message: "Secret not found" };
    if (typeof navigator !== "undefined" && navigator.clipboard) {
      await navigator.clipboard.writeText(s.value);
    }
  }

  async secretCreate(draft: SecretDraft): Promise<SecretMeta> {
    const targetItemId = draft.item_id ?? draft.project_id ?? draft.projectId ?? "";
    const envId = draft.environment_id ?? draft.environmentId ?? null;
    const newId = crypto.randomUUID();
    const item = {
      id: newId,
      item_id: targetItemId,
      environment_id: envId,
      name: draft.name.trim(),
      kind: draft.kind,
      value: draft.value,
      note: draft.note?.trim() || null,
      updated_at: Date.now(),
    };
    this.secrets.push(item);
    this.updateCounts();
    this.emit("vault://changed", { scope: "secrets" });
    return {
      id: item.id,
      project_id: item.item_id,
      item_id: item.item_id,
      environment_id: item.environment_id,
      name: item.name,
      kind: item.kind,
      note: item.note ?? undefined,
      updated_at: item.updated_at,
      value_tail: item.value.replace(/\s+/g, "").slice(-4),
      projectId: item.item_id,
      environmentId: item.environment_id ?? undefined,
      updatedAt: item.updated_at,
    };
  }

  async secretUpdate(id: string, draft: SecretDraft): Promise<SecretMeta> {
    const idx = this.secrets.findIndex((s) => s.id === id);
    if (idx === -1) throw { code: "not_found", message: "Secret not found" };
    const prev = this.secrets[idx];
    const targetItemId = draft.item_id ?? draft.project_id ?? draft.projectId ?? prev.item_id;
    const envId = draft.environment_id !== undefined ? draft.environment_id : prev.environment_id;
    this.secrets[idx] = {
      ...prev,
      item_id: targetItemId,
      environment_id: envId,
      name: draft.name.trim(),
      kind: draft.kind,
      value: draft.value,
      note: draft.note?.trim() || null,
      updated_at: Date.now(),
    };
    this.updateCounts();
    this.emit("vault://changed", { scope: "secrets" });
    return {
      id,
      project_id: targetItemId,
      item_id: targetItemId,
      environment_id: envId,
      name: draft.name.trim(),
      kind: draft.kind,
      note: draft.note?.trim() || undefined,
      updated_at: Date.now(),
      value_tail: draft.value.replace(/\s+/g, "").slice(-4),
      projectId: targetItemId,
      environmentId: envId ?? undefined,
      updatedAt: Date.now(),
    };
  }

  async secretDelete(id: string): Promise<void> {
    this.secrets = this.secrets.filter((x) => x.id !== id);
    this.updateCounts();
    this.emit("vault://changed", { scope: "secrets" });
  }

  async secretCopyToEnvironment(id: string, targetEnvironmentId?: string | null): Promise<SecretMeta> {
    const orig = this.secrets.find((s) => s.id === id);
    if (!orig) throw { code: "not_found", message: "Secret not found" };
    const newId = crypto.randomUUID();
    const copyItem = {
      ...orig,
      id: newId,
      environment_id: targetEnvironmentId || null,
      updated_at: Date.now(),
    };
    this.secrets.push(copyItem);
    this.updateCounts();
    this.emit("vault://changed", { scope: "secrets" });
    return {
      id: newId,
      project_id: copyItem.item_id,
      item_id: copyItem.item_id,
      environment_id: copyItem.environment_id,
      name: copyItem.name,
      kind: copyItem.kind,
      note: copyItem.note ?? undefined,
      updated_at: copyItem.updated_at,
      value_tail: copyItem.value.replace(/\s+/g, "").slice(-4),
      projectId: copyItem.item_id,
      environmentId: copyItem.environment_id ?? undefined,
      updatedAt: copyItem.updated_at,
    };
  }

  // 6. Assets & Files
  async assetsList(itemId: string, environmentId?: string | null): Promise<AssetMetaView[]> {
    return this.files
      .filter((f) => {
        if (f.item_id !== itemId) return false;
        if (environmentId !== undefined && environmentId !== null && f.environment_id !== environmentId) return false;
        return true;
      })
      .map((f) => ({
        id: f.id,
        item_id: f.item_id,
        environment_id: f.environment_id ?? null,
        name: f.name,
        size_bytes: f.size_bytes,
        mime_type: f.mime_type,
        sha256: f.sha256,
        updated_at: f.updated_at,
      }));
  }

  async filesList(itemId: string, environmentId?: string | null): Promise<FileMetaView[]> {
    return this.assetsList(itemId, environmentId);
  }

  async assetUpload(
    itemId: string,
    environmentId: string | undefined | null,
    name: string,
    mime: string | undefined | null,
    bytes: number[] | Uint8Array
  ): Promise<AssetMetaView> {
    const byteArray = Array.from(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes));
    if (byteArray.length > 50 * 1024 * 1024) {
      throw { code: "invalid", message: "Asset exceeds 50 MiB limit." };
    }
    const newFile = {
      id: crypto.randomUUID(),
      item_id: itemId,
      environment_id: environmentId || null,
      name: name.trim(),
      size_bytes: byteArray.length,
      mime_type: mime || "application/octet-stream",
      sha256: "mock-sha256-" + Date.now(),
      updated_at: Date.now(),
      bytes: byteArray,
    };
    this.files.push(newFile);
    this.updateCounts();
    this.emit("vault://changed", { scope: "assets" });
    this.emit("vault://changed", { scope: "files" });
    return {
      id: newFile.id,
      item_id: newFile.item_id,
      environment_id: newFile.environment_id,
      name: newFile.name,
      size_bytes: newFile.size_bytes,
      mime_type: newFile.mime_type,
      sha256: newFile.sha256,
      updated_at: newFile.updated_at,
    };
  }

  async fileUpload(
    itemId: string,
    environmentId: string | undefined | null,
    name: string,
    mime: string | undefined | null,
    bytes: number[] | Uint8Array
  ): Promise<FileMetaView> {
    return this.assetUpload(itemId, environmentId, name, mime, bytes);
  }

  async assetDownload(id: string): Promise<AssetDownloadResult> {
    const f = this.files.find((x) => x.id === id);
    if (!f) throw { code: "not_found", message: "Asset not found" };
    return {
      meta: {
        id: f.id,
        item_id: f.item_id,
        environment_id: f.environment_id ?? null,
        name: f.name,
        size_bytes: f.size_bytes,
        mime_type: f.mime_type,
        sha256: f.sha256,
        updated_at: f.updated_at,
      },
      bytes: f.bytes,
    };
  }

  async fileDownload(id: string): Promise<FileDownloadResult> {
    return this.assetDownload(id);
  }

  async assetRename(id: string, name: string): Promise<AssetMetaView> {
    const f = this.files.find((x) => x.id === id);
    if (!f) throw { code: "not_found", message: "Asset not found" };
    f.name = name.trim();
    f.updated_at = Date.now();
    this.emit("vault://changed", { scope: "assets" });
    this.emit("vault://changed", { scope: "files" });
    return {
      id: f.id,
      item_id: f.item_id,
      environment_id: f.environment_id ?? null,
      name: f.name,
      size_bytes: f.size_bytes,
      mime_type: f.mime_type,
      sha256: f.sha256,
      updated_at: f.updated_at,
    };
  }

  async fileRename(id: string, name: string): Promise<FileMetaView> {
    return this.assetRename(id, name);
  }

  async assetDelete(id: string): Promise<void> {
    this.files = this.files.filter((x) => x.id !== id);
    this.updateCounts();
    this.emit("vault://changed", { scope: "assets" });
    this.emit("vault://changed", { scope: "files" });
  }

  async fileDelete(id: string): Promise<void> {
    return this.assetDelete(id);
  }

  // 7. Notes
  async notesList(itemId: string, environmentId?: string | null): Promise<NoteMetaView[]> {
    return this.notes
      .filter((n) => {
        if (n.item_id !== itemId) return false;
        if (environmentId !== undefined && environmentId !== null && n.environment_id !== environmentId) return false;
        return true;
      })
      .map((n) => ({
        id: n.id,
        item_id: n.item_id,
        environment_id: n.environment_id ?? null,
        title: n.title,
        snippet: n.content.replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim().slice(0, 100),
        updated_at: n.updated_at,
        position: n.position,
      }));
  }

  async noteGet(id: string): Promise<NoteView> {
    const n = this.notes.find((x) => x.id === id);
    if (!n) throw { code: "not_found", message: "Note not found" };
    return { ...n, environment_id: n.environment_id ?? null };
  }

  async noteCreate(draft: NoteDraft): Promise<NoteView> {
    const trimmedTitle = draft.title.trim();
    if (!trimmedTitle) {
      throw { code: "invalid", message: "Enter a title for this note." };
    }
    const newNote = {
      id: crypto.randomUUID(),
      item_id: draft.item_id,
      environment_id: draft.environment_id || null,
      title: trimmedTitle,
      content: draft.content,
      updated_at: Date.now(),
      position: this.notes.filter((n) => n.item_id === draft.item_id).length,
    };
    this.notes.push(newNote);
    this.updateCounts();
    this.emit("vault://changed", { scope: "notes" });
    return newNote;
  }

  async noteUpdate(id: string, draft: NoteUpdateDraft): Promise<NoteView> {
    const n = this.notes.find((x) => x.id === id);
    if (!n) throw { code: "not_found", message: "Note not found" };
    if (draft.title !== undefined && draft.title !== null) {
      const trimmed = draft.title.trim();
      if (!trimmed) throw { code: "invalid", message: "Enter a title for this note." };
      n.title = trimmed;
    }
    if (draft.content !== undefined && draft.content !== null) {
      n.content = draft.content;
    }
    n.updated_at = Date.now();
    this.emit("vault://changed", { scope: "notes" });
    return { ...n, environment_id: n.environment_id ?? null };
  }

  async noteDelete(id: string): Promise<void> {
    this.notes = this.notes.filter((x) => x.id !== id);
    this.updateCounts();
    this.emit("vault://changed", { scope: "notes" });
  }

  async noteCopyPlain(id: string): Promise<void> {
    const n = this.notes.find((x) => x.id === id);
    if (!n) throw { code: "not_found", message: "Note not found" };
    const plain = n.content.replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim();
    if (typeof navigator !== "undefined" && navigator.clipboard) {
      await navigator.clipboard.writeText(plain);
    }
  }

  async clipboardCopyText(text: string): Promise<void> {
    if (typeof navigator !== "undefined" && navigator.clipboard) {
      await navigator.clipboard.writeText(text);
    }
  }

  // 8. Overview & Dashboard
  async overview(): Promise<Overview> {
    this.updateCounts();
    const recent: RecentSecret[] = [...this.secrets]
      .sort((a, b) => b.updated_at - a.updated_at)
      .slice(0, 5)
      .map((s) => {
        const item = this.items.find((i) => i.id === s.item_id);
        const env = this.environments.find((e) => e.id === s.environment_id);
        return {
          id: s.id,
          name: s.name,
          project_id: s.item_id,
          project_name: item?.name || "Item",
          environment_id: s.environment_id || "",
          environment_name: env?.name || "General",
          updated_at: s.updated_at,
          item_id: s.item_id,
          item_name: item?.name || "Item",
        };
      });

    return {
      labels_count: this.labels.length,
      groups_count: this.labels.length,
      items_count: this.items.length,
      projects_count: this.items.length,
      environments_count: this.environments.length,
      secrets_count: this.secrets.length,
      assets_count: this.files.length,
      files_count: this.files.length,
      notes_count: this.notes.length,
      active_devices_count: this.devices.length,
      projects: this.items.map((it) => ({
        id: it.id,
        name: it.name,
        environments: this.environments.filter((e) => e.project_id === it.id),
      })),
      recent,
      checklist: {
        vault_created: true,
        recovery_key_created: this.recoveryCreated,
        cli_connected: this.cliConnected,
        add_device_done: this.devices.length > 1,
      },
    };
  }

  async dashboardGet(): Promise<DashboardConfig> {
    return { ...this.dashboardConfig };
  }

  async dashboardSet(config: DashboardConfig): Promise<void> {
    this.dashboardConfig = { ...config };
    if (config.home_label) {
      this.settings.home_label = config.home_label;
    }
    this.emit("vault://changed", { scope: "dashboard" });
  }

  // 9. Settings
  async systemDeviceName(): Promise<string> {
    return this.settings.device_name || "Desktop";
  }

  async biometricStatus(): Promise<{ available: boolean; biometry_type: string }> {
    return { available: true, biometry_type: "touch_id" };
  }

  async biometricAuthenticate(_reason?: string): Promise<boolean> {
    return true;
  }

  async settingsGet(): Promise<Settings> {
    return { ...this.settings };
  }

  async settingsSet(next: SettingsPatch): Promise<Settings> {
    const lockMin = next.lock_minutes ?? next.lock_timeout_minutes ?? this.settings.lock_minutes;
    this.settings = {
      ...this.settings,
      ...next,
      lock_minutes: lockMin,
      lock_timeout_minutes: lockMin,
      theme: (next.theme as any) || this.settings.theme,
      device_name: next.device_name || this.settings.device_name,
      home_label: next.home_label || this.settings.home_label || "Overview",
    };
    if (next.home_label) {
      this.dashboardConfig.home_label = next.home_label;
    }
    this.emit("vault://changed", { scope: "settings" });
    return { ...this.settings };
  }

  // 10. Backward Compatibility (Projects)
  async projectsList(): Promise<ProjectView[]> {
    return this.items.map((it) => ({
      id: it.id,
      name: it.name,
      environments: this.environments.filter((e) => e.project_id === it.id),
    }));
  }

  async projectCreate(name: string, environments: string[]): Promise<ProjectView> {
    const defaultLabel = this.labels[0] || (await this.labelCreate("Projects", "folder"));
    const item = await this.itemCreate(defaultLabel.id, name);
    const createdEnvs: EnvironmentView[] = [];
    for (const e of environments) {
      createdEnvs.push(await this.environmentAdd(item.id, e));
    }
    return {
      id: item.id,
      name: item.name,
      environments: createdEnvs,
    };
  }

  async projectRename(id: string, name: string): Promise<void> {
    await this.itemRename(id, name);
  }

  async projectDelete(id: string): Promise<void> {
    await this.itemDelete(id);
  }

  // Additional mock helpers
  async devicesList(): Promise<DeviceView[]> {
    return JSON.parse(JSON.stringify(this.devices));
  }

  async deviceRevoke(deviceId: string): Promise<void> {
    const dev = this.devices.find((d) => d.id === deviceId);
    if (dev) {
      dev.revoked_at = Date.now();
      this.emit("vault://changed", { scope: "devices" });
    }
  }

  async recoveryCreate(): Promise<string> {
    this.recoveryCreated = true;
    this.emit("vault://changed", { scope: "settings" });
    return "MOCK-RECV-KEY-1234-5678-ABCD";
  }

  async recoveryStatus(): Promise<{ created: boolean; createdAt?: number }> {
    return { created: this.recoveryCreated, createdAt: this.recoveryCreated ? Date.now() - 3600000 : undefined };
  }

  async exportVault(_recoveryKey: string): Promise<string> {
    return "/mock/path/to/vault.secwet";
  }

  async vaultRotateKey(): Promise<number> {
    return 2;
  }

  async syncNow(): Promise<SyncReport> {
    return { pushed: 0, pulled: 0 };
  }
}

export const mockBackend = new BrowserMockBackend();

function normalizeDraft(draft: SecretDraft) {
  const targetId = draft.item_id ?? draft.project_id ?? draft.projectId ?? "";
  const rawEnv = draft.environment_id ?? draft.environmentId;
  const envId = (rawEnv && typeof rawEnv === "string" && rawEnv.trim() !== "") ? rawEnv.trim() : null;
  return {
    item_id: targetId,
    project_id: targetId,
    environment_id: envId,
    name: draft.name.trim(),
    kind: draft.kind,
    value: draft.value,
    note: draft.note?.trim() || null,
  };
}

function normalizeSettings(s: any): Settings {
  const lockMinutes = s.lock_timeout_minutes ?? s.lock_minutes ?? 15;
  return {
    theme: s.theme || "system",
    lock_timeout_minutes: lockMinutes,
    lock_minutes: lockMinutes,
    device_name: s.device_name || "desktop",
    home_label: s.home_label || "Overview",
  };
}

function normalizeSecretMeta(s: any): SecretMeta {
  const targetId = s.item_id ?? s.project_id ?? s.projectId;
  const envId = s.environment_id ?? s.environmentId ?? null;
  return {
    id: s.id,
    project_id: targetId,
    environment_id: envId,
    name: s.name,
    kind: s.kind,
    note: s.note ?? undefined,
    updated_at: s.updated_at ?? s.updatedAt ?? Date.now(),
    value_tail: s.value_tail || "",
    item_id: targetId,
    projectId: targetId,
    environmentId: envId,
    updatedAt: s.updated_at ?? s.updatedAt ?? Date.now(),
  };
}

// ============================================================================
// 4. Exported Typed API Functions (All 45 Tauri Commands + Events)
// ============================================================================

export const api = {
  // 1. Lifecycle (4)
  vaultStatus: async (): Promise<VaultStatus> => {
    if (isTauri()) {
      return invoke<VaultStatus>("vault_status");
    }
    return mockBackend.vaultStatus();
  },

  vaultCreate: async (deviceName?: string): Promise<VaultStatus> => {
    if (isTauri()) {
      return invoke<VaultStatus>("vault_create", { deviceName, device_name: deviceName });
    }
    return mockBackend.vaultCreate(deviceName);
  },

  vaultUnlock: async (): Promise<void> => {
    if (isTauri()) {
      return invoke<void>("vault_unlock");
    }
    return mockBackend.vaultUnlock();
  },

  vaultLock: async (): Promise<void> => {
    if (isTauri()) {
      return invoke<void>("vault_lock");
    }
    return mockBackend.vaultLock();
  },

  // 2. Groups (5)
  groupsList: async (): Promise<GroupView[]> => {
    if (isTauri()) {
      return invoke<GroupView[]>("groups_list");
    }
    return mockBackend.groupsList();
  },

  groupCreate: async (name: string, icon?: string | null): Promise<GroupView> => {
    if (isTauri()) {
      return invoke<GroupView>("group_create", { name: name.trim(), icon: icon || null });
    }
    return mockBackend.groupCreate(name, icon);
  },

  groupRename: async (id: string, name: string, icon?: string | null): Promise<void> => {
    if (isTauri()) {
      return invoke<void>("group_rename", { id, name: name.trim(), icon: icon || null });
    }
    return mockBackend.groupRename(id, name, icon);
  },

  groupDelete: async (id: string): Promise<void> => {
    if (isTauri()) {
      return invoke<void>("group_delete", { id });
    }
    return mockBackend.groupDelete(id);
  },

  groupReorder: async (ids: string[]): Promise<void> => {
    if (isTauri()) {
      return invoke<void>("group_reorder", { ids });
    }
    return mockBackend.groupReorder(ids);
  },

  // Legacy Labels (5) - forwarding to group methods
  labelsList: async (): Promise<LabelView[]> => {
    return api.groupsList();
  },

  labelCreate: async (name: string, icon?: string | null): Promise<LabelView> => {
    return api.groupCreate(name, icon);
  },

  labelRename: async (id: string, name: string, icon?: string | null): Promise<void> => {
    return api.groupRename(id, name, icon);
  },

  labelDelete: async (id: string): Promise<void> => {
    return api.groupDelete(id);
  },

  labelReorder: async (ids: string[]): Promise<void> => {
    return api.groupReorder(ids);
  },

  // 3. Items (4)
  itemsList: async (labelId?: string | null): Promise<ItemView[]> => {
    if (isTauri()) {
      return invoke<ItemView[]>("items_list", { labelId: labelId || null, label_id: labelId || null });
    }
    return mockBackend.itemsList(labelId);
  },

  itemCreate: async (labelId: string, name: string, description?: string | null): Promise<ItemView> => {
    if (isTauri()) {
      return invoke<ItemView>("item_create", {
        labelId,
        label_id: labelId,
        name: name.trim(),
        description: description?.trim() || null,
      });
    }
    return mockBackend.itemCreate(labelId, name, description);
  },

  itemRename: async (id: string, name: string, description?: string | null): Promise<void> => {
    if (isTauri()) {
      return invoke<void>("item_rename", {
        id,
        name: name.trim(),
        description: description?.trim() || null,
      });
    }
    return mockBackend.itemRename(id, name, description);
  },

  itemDelete: async (id: string): Promise<void> => {
    if (isTauri()) {
      return invoke<void>("item_delete", { id });
    }
    return mockBackend.itemDelete(id);
  },

  // 4. Environments (4)
  environmentsList: async (itemId: string): Promise<EnvironmentView[]> => {
    if (isTauri()) {
      return invoke<EnvironmentView[]>("environments_list", { itemId, item_id: itemId });
    }
    return mockBackend.environmentsList(itemId);
  },

  environmentAdd: async (itemId: string, name: string): Promise<EnvironmentView> => {
    if (isTauri()) {
      return invoke<EnvironmentView>("environment_add", { itemId, item_id: itemId, name: name.trim() });
    }
    return mockBackend.environmentAdd(itemId, name);
  },

  environmentRename: async (id: string, name: string): Promise<void> => {
    if (isTauri()) {
      return invoke<void>("environment_rename", { id, name: name.trim() });
    }
    return mockBackend.environmentRename(id, name);
  },

  environmentDelete: async (id: string, preserveContent?: boolean | null): Promise<void> => {
    if (isTauri()) {
      return invoke<void>("environment_delete", {
        id,
        preserveContent: preserveContent ?? null,
        preserve_content: preserveContent ?? null,
      });
    }
    return mockBackend.environmentDelete(id, preserveContent);
  },

  // 5. Secrets (7)
  secretsList: async (itemId?: string | null, environmentId?: string | null): Promise<SecretMeta[]> => {
    if (isTauri()) {
      const res = await invoke<any[]>("secrets_list", {
        itemId: itemId || null,
        item_id: itemId || null,
        environmentId: environmentId || null,
        environment_id: environmentId || null,
      });
      return res.map(normalizeSecretMeta);
    }
    return mockBackend.secretsList(itemId, environmentId);
  },

  secretReveal: async (id: string): Promise<string> => {
    if (isTauri()) {
      return invoke<string>("secret_reveal", { id });
    }
    return mockBackend.secretReveal(id);
  },

  secretCopy: async (id: string): Promise<void> => {
    if (isTauri()) {
      return invoke<void>("secret_copy", { id });
    }
    return mockBackend.secretCopy(id);
  },

  secretCreate: async (draft: SecretDraft): Promise<SecretMeta> => {
    if (isTauri()) {
      const res = await invoke<any>("secret_create", { draft: normalizeDraft(draft) });
      return normalizeSecretMeta(res);
    }
    return mockBackend.secretCreate(draft);
  },

  secretUpdate: async (id: string, draft: SecretDraft): Promise<SecretMeta> => {
    if (isTauri()) {
      const res = await invoke<any>("secret_update", { id, draft: normalizeDraft(draft) });
      return normalizeSecretMeta(res);
    }
    return mockBackend.secretUpdate(id, draft);
  },

  secretDelete: async (id: string): Promise<void> => {
    if (isTauri()) {
      return invoke<void>("secret_delete", { id });
    }
    return mockBackend.secretDelete(id);
  },

  secretCopyToEnvironment: async (id: string, targetEnvironmentId?: string | null): Promise<SecretMeta> => {
    if (isTauri()) {
      const res = await invoke<any>("secret_copy_to_environment", {
        id,
        targetEnvironmentId: targetEnvironmentId || null,
        target_environment_id: targetEnvironmentId || null,
      });
      return normalizeSecretMeta(res);
    }
    return mockBackend.secretCopyToEnvironment(id, targetEnvironmentId);
  },

  // 6. Assets & Files
  assetsList: async (itemId: string, environmentId?: string | null): Promise<AssetMetaView[]> => {
    if (isTauri()) {
      return invoke<AssetMetaView[]>("assets_list", {
        itemId,
        item_id: itemId,
        environmentId: environmentId || null,
        environment_id: environmentId || null,
      });
    }
    return mockBackend.assetsList(itemId, environmentId);
  },

  filesList: async (itemId: string, environmentId?: string | null): Promise<FileMetaView[]> => {
    return api.assetsList(itemId, environmentId);
  },

  assetUpload: async (
    itemId: string,
    environmentId: string | undefined | null,
    name: string,
    mime: string | undefined | null,
    bytes: number[] | Uint8Array
  ): Promise<AssetMetaView> => {
    const byteArray = Array.from(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes));
    if (isTauri()) {
      return invoke<AssetMetaView>("asset_upload", {
        itemId,
        item_id: itemId,
        environmentId: environmentId || null,
        environment_id: environmentId || null,
        name: name.trim(),
        mime: mime || null,
        bytes: byteArray,
      });
    }
    return mockBackend.assetUpload(itemId, environmentId, name, mime, byteArray);
  },

  fileUpload: async (
    itemId: string,
    environmentId: string | undefined | null,
    name: string,
    mime: string | undefined | null,
    bytes: number[] | Uint8Array
  ): Promise<FileMetaView> => {
    return api.assetUpload(itemId, environmentId, name, mime, bytes);
  },

  assetDownload: async (id: string): Promise<AssetDownloadResult> => {
    if (isTauri()) {
      return invoke<AssetDownloadResult>("asset_download", { id });
    }
    return mockBackend.assetDownload(id);
  },

  fileDownload: async (id: string): Promise<FileDownloadResult> => {
    return api.assetDownload(id);
  },

  assetRename: async (id: string, name: string): Promise<AssetMetaView> => {
    if (isTauri()) {
      return invoke<AssetMetaView>("asset_rename", { id, name: name.trim() });
    }
    return mockBackend.assetRename(id, name);
  },

  fileRename: async (id: string, name: string): Promise<FileMetaView> => {
    return api.assetRename(id, name);
  },

  assetDelete: async (id: string): Promise<void> => {
    if (isTauri()) {
      return invoke<void>("asset_delete", { id });
    }
    return mockBackend.assetDelete(id);
  },

  fileDelete: async (id: string): Promise<void> => {
    return api.assetDelete(id);
  },

  // 7. Notes (7)
  notesList: async (itemId: string, environmentId?: string | null): Promise<NoteMetaView[]> => {
    if (isTauri()) {
      return invoke<NoteMetaView[]>("notes_list", {
        itemId,
        item_id: itemId,
        environmentId: environmentId || null,
        environment_id: environmentId || null,
      });
    }
    return mockBackend.notesList(itemId, environmentId);
  },

  noteGet: async (id: string): Promise<NoteView> => {
    if (isTauri()) {
      return invoke<NoteView>("note_get", { id });
    }
    return mockBackend.noteGet(id);
  },

  noteCreate: async (draft: NoteDraft): Promise<NoteView> => {
    if (isTauri()) {
      return invoke<NoteView>("note_create", {
        draft: {
          itemId: draft.item_id,
          item_id: draft.item_id,
          environmentId: draft.environment_id || null,
          environment_id: draft.environment_id || null,
          title: draft.title.trim(),
          content: draft.content,
        },
      });
    }
    return mockBackend.noteCreate(draft);
  },

  noteUpdate: async (id: string, draft: NoteUpdateDraft): Promise<NoteView> => {
    if (isTauri()) {
      return invoke<NoteView>("note_update", {
        id,
        draft: {
          title: draft.title !== undefined ? draft.title?.trim() || null : null,
          content: draft.content !== undefined ? draft.content : null,
        },
      });
    }
    return mockBackend.noteUpdate(id, draft);
  },

  noteDelete: async (id: string): Promise<void> => {
    if (isTauri()) {
      return invoke<void>("note_delete", { id });
    }
    return mockBackend.noteDelete(id);
  },

  noteCopyPlain: async (id: string): Promise<void> => {
    if (isTauri()) {
      return invoke<void>("note_copy_plain", { id });
    }
    return mockBackend.noteCopyPlain(id);
  },

  clipboardCopyText: async (text: string): Promise<void> => {
    if (isTauri()) {
      return invoke<void>("clipboard_copy_text", { text });
    }
    return mockBackend.clipboardCopyText(text);
  },

  // 8. Overview & Dashboard (3)
  overview: async (): Promise<Overview> => {
    if (isTauri()) {
      return invoke<Overview>("overview");
    }
    return mockBackend.overview();
  },

  dashboardGet: async (): Promise<DashboardConfig> => {
    if (isTauri()) {
      return invoke<DashboardConfig>("dashboard_get");
    }
    return mockBackend.dashboardGet();
  },

  dashboardSet: async (config: DashboardConfig): Promise<void> => {
    if (isTauri()) {
      return invoke<void>("dashboard_set", { config });
    }
    return mockBackend.dashboardSet(config);
  },

  // 9. Settings (2)
  settingsGet: async (): Promise<Settings> => {
    if (isTauri()) {
      const s = await invoke<any>("settings_get");
      return normalizeSettings(s);
    }
    return mockBackend.settingsGet();
  },

  settingsSet: async (settings: SettingsPatch): Promise<Settings> => {
    const lockMinutes = settings.lock_minutes ?? settings.lock_timeout_minutes;
    const patch = {
      theme: settings.theme,
      lock_minutes: lockMinutes,
      lock_timeout_minutes: lockMinutes,
      device_name: settings.device_name,
    };
    if (isTauri()) {
      const s = await invoke<any>("settings_set", { settings: patch });
      return normalizeSettings(s);
    }
    return mockBackend.settingsSet(settings);
  },

  systemDeviceName: async (): Promise<string> => {
    if (isTauri()) {
      return invoke<string>("system_device_name").catch(() => "Desktop");
    }
    return mockBackend.systemDeviceName();
  },

  biometricStatus: async (): Promise<{ available: boolean; biometry_type: string }> => {
    if (isTauri()) {
      return invoke<{ available: boolean; biometry_type: string }>("biometric_status").catch(() => ({
        available: false,
        biometry_type: "none",
      }));
    }
    return mockBackend.biometricStatus();
  },

  biometricAuthenticate: async (reason?: string): Promise<boolean> => {
    if (isTauri()) {
      return invoke<boolean>("biometric_authenticate", { reason });
    }
    return mockBackend.biometricAuthenticate(reason);
  },

  // 10. Backward Compatibility / Projects (4)
  projectsList: async (): Promise<ProjectView[]> => {
    if (isTauri()) {
      return invoke<ProjectView[]>("projects_list");
    }
    return mockBackend.projectsList();
  },

  projectCreate: async (name: string, environments: string[]): Promise<ProjectView> => {
    if (isTauri()) {
      return invoke<ProjectView>("project_create", { name, environments });
    }
    return mockBackend.projectCreate(name, environments);
  },

  projectRename: async (id: string, name: string): Promise<void> => {
    if (isTauri()) {
      return invoke<void>("project_rename", { id, name });
    }
    return mockBackend.projectRename(id, name);
  },

  projectDelete: async (id: string): Promise<void> => {
    if (isTauri()) {
      return invoke<void>("project_delete", { id });
    }
    return mockBackend.projectDelete(id);
  },

  // 11. Mock helpers / Extra
  devicesList: async (): Promise<DeviceView[]> => {
    return mockBackend.devicesList();
  },

  deviceRevoke: async (deviceId: string): Promise<void> => {
    return mockBackend.deviceRevoke(deviceId);
  },

  recoveryCreate: async (): Promise<string> => {
    return mockBackend.recoveryCreate();
  },

  recoveryStatus: async (): Promise<{ created: boolean; createdAt?: number }> => {
    return mockBackend.recoveryStatus();
  },

  exportVault: async (recoveryKey: string): Promise<string> => {
    return mockBackend.exportVault(recoveryKey);
  },

  vaultRotateKey: async (): Promise<number> => {
    return mockBackend.vaultRotateKey();
  },

  syncNow: async (): Promise<SyncReport> => {
    return mockBackend.syncNow();
  },

  // 12. Event Subscriptions
  onVaultChanged: async (handler: (e: VaultChangedEvent) => void): Promise<UnlistenFn> => {
    if (isTauri()) {
      return listen<VaultChangedEvent>("vault://changed", (event) => handler(event.payload));
    }
    return mockBackend.listen("vault://changed", handler);
  },

  onVaultLocked: async (handler: () => void): Promise<UnlistenFn> => {
    if (isTauri()) {
      return listen<void>("vault://locked", () => handler());
    }
    return mockBackend.listen("vault://locked", handler);
  },

  onSyncStatus: async (handler: (e: SyncStatusEvent) => void): Promise<UnlistenFn> => {
    if (isTauri()) {
      return listen<SyncStatusEvent>("sync://status", (event) => handler(event.payload));
    }
    return mockBackend.listen("sync://status", handler);
  },
};
