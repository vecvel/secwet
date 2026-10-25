/**
 * apps/desktop/src/lib/api.ts
 *
 * Typed Tauri 2 IPC client and seamless browser mock fallback.
 * Authoritative: docs/IMPLEMENTATION.md §9.1, §9.2, and secwet-proto.
 */
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import {
  initialSecrets as mockSecretsData,
  projects as mockProjectsData,
  type SecretKind,
} from "../data/mock";

// ============================================================================
// 1. Data Types Matching Section 9.1 & secwet-proto
// ============================================================================

export type { SecretKind };

export interface EnvironmentView {
  id: string;
  project_id: string;
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
  environment_id: string;
  name: string;
  kind: SecretKind;
  note?: string;
  updated_at: number;
  value_tail: string;
  // Aliases for backward compatibility
  projectId?: string;
  environmentId?: string;
  updatedAt?: number;
}

export interface SecretDraft {
  project_id: string;
  environment_id: string;
  name: string;
  kind: SecretKind;
  value: string;
  note?: string;
  // Aliases for compatibility
  projectId?: string;
  environmentId?: string;
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
}

export interface ChecklistState {
  vault_created: boolean;
  recovery_key_created: boolean;
  cli_connected: boolean;
  add_device_done: boolean;
  pending_rotation?: string;
}

export interface Overview {
  projects_count: number;
  secrets_count: number;
  environments_count: number;
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
  scope: string; // "projects" | "environments" | "secrets" | "settings" | "all"
}

export interface SyncStatusEvent {
  state: "idle" | "syncing" | "offline" | "paused";
  detail?: string;
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
    // Section 9.2 item 5: log code only, never message body or sensitive data
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
      return "The vault is locked. Unlock it to continue.";
    case "crypto":
    case "crypto_error":
      return "This item could not be decrypted.";
    case "invalid":
      return uiErr.message || "Please check your inputs.";
    case "already_initialized":
      return "A vault already exists on this device.";
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
class BrowserMockBackend {
  private status: VaultStatus = { status: "unlocked", vault_id: "00000000-0000-0000-0000-000000000001" };
  private projects: ProjectView[];
  private secrets: Array<{
    id: string;
    project_id: string;
    environment_id: string;
    name: string;
    kind: SecretKind;
    value: string;
    note?: string;
    updated_at: number;
  }>;
  private settings: Settings = {
    theme: "system",
    lock_timeout_minutes: 15,
    lock_minutes: 15,
    device_name: "MacBook Pro",
  };
  private cliConnected = false;
  private recoveryCreated = false;
  private listeners = new Map<string, Set<(payload: any) => void>>();

  constructor() {
    this.projects = mockProjectsData.map((p) => ({
      id: p.id,
      name: p.name,
      environments: p.environments.map((e, idx) => ({
        id: e.id,
        project_id: p.id,
        name: e.name,
        position: idx,
        secret_count: mockSecretsData.filter((s) => s.projectId === p.id && s.environmentId === e.id).length,
      })),
    }));

    this.secrets = mockSecretsData.map((s) => ({
      id: s.id,
      project_id: s.projectId,
      environment_id: s.environmentId,
      name: s.name,
      kind: s.kind,
      value: s.value,
      note: s.note,
      updated_at: s.updatedAt,
    }));
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

  async projectsList(): Promise<ProjectView[]> {
    return JSON.parse(JSON.stringify(this.projects));
  }

  async projectCreate(name: string, environments: string[]): Promise<ProjectView> {
    const trimmed = name.trim();
    if (this.projects.some((p) => p.name.toLowerCase() === trimmed.toLowerCase())) {
      throw { code: "duplicate", message: `A project called ${trimmed} already exists.` };
    }
    const projectId = crypto.randomUUID();
    const envViews: EnvironmentView[] = environments.map((eName, idx) => ({
      id: crypto.randomUUID(),
      project_id: projectId,
      name: eName.trim(),
      position: idx,
      secret_count: 0,
    }));
    const newProject: ProjectView = { id: projectId, name: trimmed, environments: envViews };
    this.projects.push(newProject);
    this.emit("vault://changed", { scope: "projects" });
    return newProject;
  }

  async projectRename(id: string, name: string): Promise<void> {
    const p = this.projects.find((x) => x.id === id);
    if (!p) throw { code: "not_found", message: "Project not found" };
    p.name = name.trim();
    this.emit("vault://changed", { scope: "projects" });
  }

  async projectDelete(id: string): Promise<void> {
    this.projects = this.projects.filter((p) => p.id !== id);
    this.secrets = this.secrets.filter((s) => s.project_id !== id);
    this.emit("vault://changed", { scope: "projects" });
  }

  async environmentAdd(projectId: string, name: string): Promise<EnvironmentView> {
    const p = this.projects.find((x) => x.id === projectId);
    if (!p) throw { code: "not_found", message: "Project not found" };
    const envView: EnvironmentView = {
      id: crypto.randomUUID(),
      project_id: projectId,
      name: name.trim(),
      position: p.environments.length,
      secret_count: 0,
    };
    p.environments.push(envView);
    this.emit("vault://changed", { scope: "environments" });
    return envView;
  }

  async environmentRename(id: string, name: string): Promise<void> {
    for (const p of this.projects) {
      const e = p.environments.find((x) => x.id === id);
      if (e) {
        e.name = name.trim();
        this.emit("vault://changed", { scope: "environments" });
        return;
      }
    }
    throw { code: "not_found", message: "Environment not found" };
  }

  async environmentDelete(id: string): Promise<void> {
    for (const p of this.projects) {
      const idx = p.environments.findIndex((x) => x.id === id);
      if (idx !== -1) {
        if (p.environments.length <= 1) {
          throw { code: "last_environment", message: "Cannot delete the last environment." };
        }
        p.environments.splice(idx, 1);
        this.secrets = this.secrets.filter((s) => s.environment_id !== id);
        this.emit("vault://changed", { scope: "environments" });
        return;
      }
    }
    throw { code: "not_found", message: "Environment not found" };
  }

  async secretsList(environmentId: string): Promise<SecretMeta[]> {
    return this.secrets
      .filter((s) => s.environment_id === environmentId)
      .map((s) => ({
        id: s.id,
        project_id: s.project_id,
        environment_id: s.environment_id,
        name: s.name,
        kind: s.kind,
        note: s.note,
        updated_at: s.updated_at,
        value_tail: s.value.replace(/\s+/g, "").slice(-4),
        projectId: s.project_id,
        environmentId: s.environment_id,
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
    const projectId = draft.project_id ?? draft.projectId ?? "";
    const envId = draft.environment_id ?? draft.environmentId ?? "";
    const newId = crypto.randomUUID();
    const item = {
      id: newId,
      project_id: projectId,
      environment_id: envId,
      name: draft.name.trim(),
      kind: draft.kind,
      value: draft.value,
      note: draft.note?.trim() || undefined,
      updated_at: Date.now(),
    };
    this.secrets.push(item);
    this.updateEnvCounts(projectId);
    this.emit("vault://changed", { scope: "secrets" });
    return {
      id: item.id,
      project_id: item.project_id,
      environment_id: item.environment_id,
      name: item.name,
      kind: item.kind,
      note: item.note,
      updated_at: item.updated_at,
      value_tail: item.value.replace(/\s+/g, "").slice(-4),
      projectId: item.project_id,
      environmentId: item.environment_id,
      updatedAt: item.updated_at,
    };
  }

  async secretUpdate(id: string, draft: SecretDraft): Promise<SecretMeta> {
    const idx = this.secrets.findIndex((s) => s.id === id);
    if (idx === -1) throw { code: "not_found", message: "Secret not found" };
    const prev = this.secrets[idx];
    const projectId = draft.project_id ?? draft.projectId ?? prev.project_id;
    const envId = draft.environment_id ?? draft.environmentId ?? prev.environment_id;
    this.secrets[idx] = {
      ...prev,
      project_id: projectId,
      environment_id: envId,
      name: draft.name.trim(),
      kind: draft.kind,
      value: draft.value,
      note: draft.note?.trim() || undefined,
      updated_at: Date.now(),
    };
    this.updateEnvCounts(projectId);
    this.emit("vault://changed", { scope: "secrets" });
    return {
      id,
      project_id: projectId,
      environment_id: envId,
      name: draft.name.trim(),
      kind: draft.kind,
      note: draft.note?.trim() || undefined,
      updated_at: Date.now(),
      value_tail: draft.value.replace(/\s+/g, "").slice(-4),
      projectId,
      environmentId: envId,
      updatedAt: Date.now(),
    };
  }

  async secretDelete(id: string): Promise<void> {
    const s = this.secrets.find((x) => x.id === id);
    this.secrets = this.secrets.filter((x) => x.id !== id);
    if (s) this.updateEnvCounts(s.project_id);
    this.emit("vault://changed", { scope: "secrets" });
  }

  async secretCopyToEnvironment(id: string, targetEnvironmentId: string): Promise<SecretMeta> {
    const orig = this.secrets.find((s) => s.id === id);
    if (!orig) throw { code: "not_found", message: "Secret not found" };
    if (this.secrets.some((s) => s.environment_id === targetEnvironmentId && s.name === orig.name)) {
      throw { code: "duplicate", message: `${orig.name} already exists in target environment.` };
    }
    const newId = crypto.randomUUID();
    const copyItem = {
      ...orig,
      id: newId,
      environment_id: targetEnvironmentId,
      updated_at: Date.now(),
    };
    this.secrets.push(copyItem);
    this.updateEnvCounts(orig.project_id);
    this.emit("vault://changed", { scope: "secrets" });
    return {
      id: newId,
      project_id: copyItem.project_id,
      environment_id: copyItem.environment_id,
      name: copyItem.name,
      kind: copyItem.kind,
      note: copyItem.note,
      updated_at: copyItem.updated_at,
      value_tail: copyItem.value.replace(/\s+/g, "").slice(-4),
      projectId: copyItem.project_id,
      environmentId: copyItem.environment_id,
      updatedAt: copyItem.updated_at,
    };
  }

  async overview(): Promise<Overview> {
    const envCount = this.projects.reduce((acc, p) => acc + p.environments.length, 0);
    const sortedSecrets = [...this.secrets].sort((a, b) => b.updated_at - a.updated_at).slice(0, 5);
    const recent: RecentSecret[] = sortedSecrets.map((s) => {
      const p = this.projects.find((x) => x.id === s.project_id);
      const e = p?.environments.find((x) => x.id === s.environment_id);
      return {
        id: s.id,
        name: s.name,
        project_id: s.project_id,
        project_name: p?.name || "",
        environment_id: s.environment_id,
        environment_name: e?.name || "",
        updated_at: s.updated_at,
      };
    });

    return {
      projects_count: this.projects.length,
      secrets_count: this.secrets.length,
      environments_count: envCount,
      active_devices_count: 1,
      projects: this.projects,
      recent,
      checklist: {
        vault_created: true,
        recovery_key_created: this.recoveryCreated,
        cli_connected: this.cliConnected,
        add_device_done: false,
      },
    };
  }

  async settingsGet(): Promise<Settings> {
    return { ...this.settings };
  }

  async settingsSet(next: Partial<Settings>): Promise<Settings> {
    const lockMin = next.lock_minutes ?? next.lock_timeout_minutes ?? this.settings.lock_minutes;
    this.settings = {
      ...this.settings,
      ...next,
      lock_minutes: lockMin,
      lock_timeout_minutes: lockMin,
    };
    this.emit("vault://changed", { scope: "settings" });
    return { ...this.settings };
  }

  private updateEnvCounts(projectId: string) {
    const p = this.projects.find((x) => x.id === projectId);
    if (!p) return;
    for (const env of p.environments) {
      env.secret_count = this.secrets.filter((s) => s.project_id === projectId && s.environment_id === env.id).length;
    }
  }
}

const mockBackend = new BrowserMockBackend();

function normalizeDraft(draft: SecretDraft) {
  const projectId = draft.project_id ?? draft.projectId ?? "";
  const environmentId = draft.environment_id ?? draft.environmentId ?? "";
  return {
    project_id: projectId,
    environment_id: environmentId,
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
  };
}

function normalizeSecretMeta(s: any): SecretMeta {
  return {
    id: s.id,
    project_id: s.project_id,
    environment_id: s.environment_id,
    name: s.name,
    kind: s.kind,
    note: s.note ?? undefined,
    updated_at: s.updated_at,
    value_tail: s.value_tail,
    projectId: s.project_id,
    environmentId: s.environment_id,
    updatedAt: s.updated_at,
  };
}

// ============================================================================
// 4. Exported Typed API Functions (All 20 Tauri Commands + Events)
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

  // 2. Projects (4)
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

  // 3. Environments (3)
  environmentAdd: async (projectId: string, name: string): Promise<EnvironmentView> => {
    if (isTauri()) {
      return invoke<EnvironmentView>("environment_add", { projectId, project_id: projectId, name });
    }
    return mockBackend.environmentAdd(projectId, name);
  },

  environmentRename: async (id: string, name: string): Promise<void> => {
    if (isTauri()) {
      return invoke<void>("environment_rename", { id, name });
    }
    return mockBackend.environmentRename(id, name);
  },

  environmentDelete: async (id: string): Promise<void> => {
    if (isTauri()) {
      return invoke<void>("environment_delete", { id });
    }
    return mockBackend.environmentDelete(id);
  },

  // 4. Secrets (6)
  secretsList: async (environmentId: string): Promise<SecretMeta[]> => {
    if (isTauri()) {
      const res = await invoke<any[]>("secrets_list", { environmentId, environment_id: environmentId });
      return res.map(normalizeSecretMeta);
    }
    return mockBackend.secretsList(environmentId);
  },

  secretReveal: async (id: string): Promise<string> => {
    if (isTauri()) {
      return invoke<string>("secret_reveal", { id });
    }
    return mockBackend.secretReveal(id);
  },

  /**
   * Copies secret directly in Rust with 30s auto-clear.
   * In Tauri mode, the webview NEVER touches or receives the secret plaintext!
   */
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

  secretCopyToEnvironment: async (id: string, targetEnvironmentId: string): Promise<SecretMeta> => {
    if (isTauri()) {
      const res = await invoke<any>("secret_copy_to_environment", {
        id,
        targetEnvironmentId,
        target_environment_id: targetEnvironmentId,
      });
      return normalizeSecretMeta(res);
    }
    return mockBackend.secretCopyToEnvironment(id, targetEnvironmentId);
  },

  // 5. Overview (1)
  overview: async (): Promise<Overview> => {
    if (isTauri()) {
      return invoke<Overview>("overview");
    }
    return mockBackend.overview();
  },

  // 6. Settings (2)
  settingsGet: async (): Promise<Settings> => {
    if (isTauri()) {
      const s = await invoke<any>("settings_get");
      return normalizeSettings(s);
    }
    return mockBackend.settingsGet();
  },

  settingsSet: async (settings: Partial<Settings>): Promise<Settings> => {
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

  // 7. Event Subscriptions
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
