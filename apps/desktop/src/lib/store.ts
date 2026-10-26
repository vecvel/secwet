/**
 * apps/desktop/src/lib/store.ts
 *
 * Unified reactive state management for Secwet Desktop using useSyncExternalStore.
 * Authoritative: docs/IMPLEMENTATION.md §9.2 and Milestone 4 requirements.
 */
import { useSyncExternalStore } from "react";
import {
  api,
  isUnlocked,
  isUninitialized,
  type DashboardConfig,
  type EnvironmentView,
  type AssetMetaView,
  type FileMetaView,
  type GroupView,
  type ItemView,
  type LabelView,
  type NoteDraft,
  type NoteMetaView,
  type NoteUpdateDraft,
  type Overview,
  type ProjectView,
  type SecretDraft,
  type SecretMeta,
  type Settings,
  type SettingsPatch,
  type VaultStatus,
} from "./api";

export interface AppStateSnapshot {
  status: VaultStatus;
  groups: GroupView[];
  labels: LabelView[];
  items: ItemView[];
  environments: EnvironmentView[];
  secrets: SecretMeta[];
  assets: AssetMetaView[];
  files: FileMetaView[];
  notes: NoteMetaView[];
  overview: Overview | null;
  dashboardConfig: DashboardConfig;
  settings: Settings;
  selectedGroupId: string | null;
  selectedLabelId: string | null;
  selectedItemId: string | null;
  selectedEnvironmentId: string | null;
  loading: boolean;
  error: string | null;

  // Backward-compatibility properties
  projects: ProjectView[];
  selectedProjectId: string | null;
}

const DEFAULT_DASHBOARD_CONFIG: DashboardConfig = {
  home_label: "Overview",
  visible_kpis: ["items", "secrets", "assets", "notes", "devices"],
  widgets: ["recent_secrets", "recent_notes", "quick_actions", "checklist"],
};

const DEFAULT_SETTINGS: Settings = {
  theme: "system",
  lock_timeout_minutes: 15,
  lock_minutes: 15,
  device_name: "Desktop",
  home_label: "Overview",
};

class AppStore {
  private state: AppStateSnapshot = {
    status: { status: "uninitialized" },
    groups: [],
    labels: [],
    items: [],
    environments: [],
    secrets: [],
    assets: [],
    files: [],
    notes: [],
    overview: null,
    dashboardConfig: DEFAULT_DASHBOARD_CONFIG,
    settings: DEFAULT_SETTINGS,
    selectedGroupId: null,
    selectedLabelId: null,
    selectedItemId: null,
    selectedEnvironmentId: null,
    loading: true,
    error: null,
    projects: [],
    selectedProjectId: null,
  };

  private listeners = new Set<() => void>();
  private unlistenFns: Array<() => void> = [];
  private initialized = false;

  constructor() {
    this.init();
  }

  private notify() {
    for (const listener of this.listeners) {
      try {
        listener();
      } catch (e) {
        console.error("AppStore listener error:", e);
      }
    }
  }

  public getState = (): AppStateSnapshot => this.state;

  public subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };

  private setState(partial: Partial<AppStateSnapshot>) {
    const updated = { ...this.state, ...partial };

    // Synchronize groups and labels
    if (partial.groups && !partial.labels) {
      updated.labels = partial.groups;
    } else if (partial.labels && !partial.groups) {
      updated.groups = partial.labels;
    }

    // Synchronize selectedGroupId and selectedLabelId
    if (partial.selectedGroupId !== undefined && partial.selectedLabelId === undefined) {
      updated.selectedLabelId = partial.selectedGroupId;
    } else if (partial.selectedLabelId !== undefined && partial.selectedGroupId === undefined) {
      updated.selectedGroupId = partial.selectedLabelId;
    }

    // Keep backwards-compatible projects and selectedProjectId in sync with items
    if (partial.items || !updated.projects.length) {
      updated.projects = updated.items.map((it) => ({
        id: it.id,
        name: it.name,
        environments: updated.environments.filter(
          (e) => e.project_id === it.id || e.item_id === it.id
        ),
      }));
    }
    updated.selectedProjectId = updated.selectedItemId;

    this.state = updated;
    this.notify();
  }

  public async init() {
    if (this.initialized) return;
    this.initialized = true;

    try {
      this.setState({ loading: true, error: null });

      // 1. Setup event listeners
      const unlistenChanged = await api.onVaultChanged(async (e) => {
        await this.handleVaultChanged(e.scope);
      });

      const unlistenLocked = await api.onVaultLocked(() => {
        this.setState({
          status: { status: "locked" },
          secrets: [],
          assets: [],
          files: [],
          notes: [],
        });
      });

      this.unlistenFns = [unlistenChanged, unlistenLocked];

      // 2. Fetch initial status
      let status = await api.vaultStatus();
      if (isUninitialized(status)) {
        const sysDevName = await api.systemDeviceName().catch(() => undefined);
        status = await api.vaultCreate(sysDevName);
      }

      this.setState({ status });

      if (isUnlocked(status)) {
        await this.reloadAll();
      } else {
        this.setState({ loading: false });
      }
    } catch (err: any) {
      console.error("Initialization failed:", err);
      this.setState({ loading: false, error: err?.message || "Failed to initialize Secwet." });
    }
  }

  public destroy() {
    this.unlistenFns.forEach((fn) => fn());
    this.unlistenFns = [];
  }

  public async reloadAll() {
    try {
      const [groups, items, overview, settings, dashboardConfig] = await Promise.all([
        api.groupsList().catch(() => [] as GroupView[]),
        api.itemsList().catch(() => [] as ItemView[]),
        api.overview().catch(() => null),
        api.settingsGet().catch(() => this.state.settings),
        api.dashboardGet().catch(() => this.state.dashboardConfig),
      ]);

      if (
        settings &&
        (!settings.device_name ||
          settings.device_name === "desktop" ||
          settings.device_name === "default-device")
      ) {
        const realName = await api.systemDeviceName().catch(() => "");
        if (realName && realName !== "desktop") {
          settings.device_name = realName;
          api.settingsSet({ device_name: realName }).catch(() => {});
        }
      }

      // Resolve selected group/label
      let selectedGroupId = this.state.selectedGroupId ?? this.state.selectedLabelId;
      if (!selectedGroupId || !groups.some((g) => g.id === selectedGroupId)) {
        selectedGroupId = groups[0]?.id || null;
      }

      // Resolve selected item
      let selectedItemId = this.state.selectedItemId;
      const itemsForGroup = items.filter((i) => (i.group_id ?? i.label_id) === selectedGroupId);
      if (!selectedItemId || !items.some((i) => i.id === selectedItemId)) {
        selectedItemId = itemsForGroup[0]?.id || items[0]?.id || null;
      }

      // Load item-specific data if an item is selected
      let environments: EnvironmentView[] = [];
      let secrets: SecretMeta[] = [];
      let assets: AssetMetaView[] = [];
      let notes: NoteMetaView[] = [];

      if (selectedItemId) {
        const [loadedEnvs, loadedSecrets, loadedAssets, loadedNotes] = await Promise.all([
          api.environmentsList(selectedItemId).catch(() => [] as EnvironmentView[]),
          api.secretsList(selectedItemId).catch(() => [] as SecretMeta[]),
          api.assetsList(selectedItemId).catch(() => [] as AssetMetaView[]),
          api.notesList(selectedItemId).catch(() => [] as NoteMetaView[]),
        ]);
        environments = loadedEnvs;
        secrets = loadedSecrets;
        assets = loadedAssets;
        notes = loadedNotes;
      }

      let selectedEnvironmentId = this.state.selectedEnvironmentId;
      if (selectedEnvironmentId && !environments.some((e) => e.id === selectedEnvironmentId)) {
        selectedEnvironmentId = null;
      }

      this.setState({
        groups,
        labels: groups,
        items,
        environments,
        secrets,
        assets,
        files: assets,
        notes,
        overview,
        settings,
        dashboardConfig,
        selectedGroupId,
        selectedLabelId: selectedGroupId,
        selectedItemId,
        selectedEnvironmentId,
        loading: false,
      });
    } catch (err: any) {
      console.error("Failed to reload data:", err);
      this.setState({ loading: false, error: err?.message || "Failed to load Secwet data." });
    }
  }

  public async reloadSecrets() {
    if (this.state.selectedItemId) {
      const secrets = await api.secretsList(this.state.selectedItemId).catch(() => [] as SecretMeta[]);
      this.setState({ secrets });
    }
  }

  public async reloadItemContent(itemId: string) {
    try {
      const [environments, secrets, assets, notes, overview] = await Promise.all([
        api.environmentsList(itemId).catch(() => [] as EnvironmentView[]),
        api.secretsList(itemId).catch(() => [] as SecretMeta[]),
        api.assetsList(itemId).catch(() => [] as AssetMetaView[]),
        api.notesList(itemId).catch(() => [] as NoteMetaView[]),
        api.overview().catch(() => null),
      ]);

      let selectedEnvironmentId = this.state.selectedEnvironmentId;
      if (selectedEnvironmentId && !environments.some((e) => e.id === selectedEnvironmentId)) {
        selectedEnvironmentId = null;
      }

      this.setState({
        environments,
        secrets,
        assets,
        files: assets,
        notes,
        overview,
        selectedEnvironmentId,
      });
    } catch (err) {
      console.error("Failed to reload item content:", err);
    }
  }

  public async selectGroup(groupId: string | null) {
    const items = this.state.items.filter((i) => !groupId || (i.group_id ?? i.label_id) === groupId);
    const nextItemId = items[0]?.id || null;

    this.setState({
      selectedGroupId: groupId,
      selectedLabelId: groupId,
      selectedItemId: nextItemId,
      selectedEnvironmentId: null,
    });

    if (nextItemId) {
      await this.reloadItemContent(nextItemId);
    } else {
      this.setState({
        environments: [],
        secrets: [],
        assets: [],
        files: [],
        notes: [],
      });
    }
  }

  public selectLabel = (labelId: string | null) => this.selectGroup(labelId);

  public async selectItem(itemId: string | null, environmentId?: string | null) {
    if (!itemId) {
      this.setState({
        selectedItemId: null,
        selectedEnvironmentId: null,
        environments: [],
        secrets: [],
        assets: [],
        files: [],
        notes: [],
      });
      return;
    }

    const item = this.state.items.find((i) => i.id === itemId);
    const targetGroupId = item?.group_id ?? item?.label_id ?? this.state.selectedGroupId ?? this.state.selectedLabelId;

    this.setState({
      selectedGroupId: targetGroupId,
      selectedLabelId: targetGroupId,
      selectedItemId: itemId,
      selectedEnvironmentId: environmentId ?? null,
    });

    await this.reloadItemContent(itemId);
  }

  public selectEnvironment(projectIdOrEnvId: string | null, maybeEnvId?: string | null) {
    const envId = maybeEnvId !== undefined ? maybeEnvId : projectIdOrEnvId;
    this.setState({
      selectedEnvironmentId: envId,
    });
  }

  public async handleVaultChanged(scope: string) {
    if (!isUnlocked(this.state.status)) return;

    if (
      scope === "groups" ||
      scope === "labels" ||
      scope === "items" ||
      scope === "all" ||
      scope === "projects" ||
      scope === "environments"
    ) {
      await this.reloadAll();
    }
    if (
      scope === "environments" ||
      scope === "secrets" ||
      scope === "assets" ||
      scope === "files" ||
      scope === "notes"
    ) {
      if (scope === "secrets") {
        await this.reloadSecrets();
      }
      if (this.state.selectedItemId) {
        await this.reloadItemContent(this.state.selectedItemId);
      }
    } else if (scope === "dashboard") {
      const dashboardConfig = await api.dashboardGet();
      this.setState({ dashboardConfig });
    } else if (scope === "settings") {
      const settings = await api.settingsGet();
      this.setState({ settings });
    }
  }

  // ==========================================================================
  // Group & Label Mutations
  // ==========================================================================

  public async createGroup(name: string, icon?: string | null): Promise<GroupView> {
    const group = await api.groupCreate(name, icon);
    await this.reloadAll();
    await this.selectGroup(group.id);
    return group;
  }

  public async renameGroup(id: string, name: string, icon?: string | null): Promise<void> {
    await api.groupRename(id, name, icon);
    await this.reloadAll();
  }

  public async deleteGroup(id: string): Promise<void> {
    await api.groupDelete(id);
    await this.reloadAll();
  }

  public async reorderGroups(ids: string[]): Promise<void> {
    await api.groupReorder(ids);
    await this.reloadAll();
  }

  public createLabel = (name: string, icon?: string | null): Promise<LabelView> =>
    this.createGroup(name, icon);

  public renameLabel = (id: string, name: string, icon?: string | null): Promise<void> =>
    this.renameGroup(id, name, icon);

  public deleteLabel = (id: string): Promise<void> =>
    this.deleteGroup(id);

  public reorderLabels = (ids: string[]): Promise<void> =>
    this.reorderGroups(ids);

  // ==========================================================================
  // Item Mutations
  // ==========================================================================

  public async createItem(labelId: string, name: string, description?: string | null): Promise<ItemView> {
    const item = await api.itemCreate(labelId, name, description);
    await this.reloadAll();
    await this.selectItem(item.id);
    return item;
  }

  public async renameItem(id: string, name: string, description?: string | null): Promise<void> {
    await api.itemRename(id, name, description);
    await this.reloadAll();
  }

  public async deleteItem(id: string): Promise<void> {
    await api.itemDelete(id);
    await this.reloadAll();
  }

  // ==========================================================================
  // Environment Mutations
  // ==========================================================================

  public async addEnvironment(itemId: string, name: string): Promise<EnvironmentView> {
    const env = await api.environmentAdd(itemId, name);
    if (this.state.selectedItemId === itemId) {
      await this.reloadItemContent(itemId);
      this.selectEnvironment(env.id);
    }
    return env;
  }

  public async renameEnvironment(first: string, second: string, third?: string): Promise<void> {
    const id = third !== undefined ? second : first;
    const name = third !== undefined ? third : second;
    await api.environmentRename(id, name);
    if (this.state.selectedItemId) {
      await this.reloadItemContent(this.state.selectedItemId);
    }
  }

  public async deleteEnvironment(first: string, second?: string | boolean, third?: boolean): Promise<void> {
    const id = typeof second === "string" ? second : first;
    const preserve = typeof second === "boolean" ? second : third;
    await api.environmentDelete(id, preserve);
    if (this.state.selectedItemId) {
      await this.reloadItemContent(this.state.selectedItemId);
    }
  }

  // ==========================================================================
  // Secret Mutations
  // ==========================================================================

  public async addSecret(draft: SecretDraft): Promise<SecretMeta> {
    const secret = await api.secretCreate(draft);
    if (this.state.selectedItemId) {
      await this.reloadItemContent(this.state.selectedItemId);
    }
    return secret;
  }

  public async addSecrets(drafts: SecretDraft[]): Promise<SecretMeta[]> {
    const results: SecretMeta[] = [];
    for (const draft of drafts) {
      results.push(await api.secretCreate(draft));
    }
    if (this.state.selectedItemId) {
      await this.reloadItemContent(this.state.selectedItemId);
    }
    return results;
  }

  public async updateSecret(secretId: string, draft: SecretDraft): Promise<SecretMeta> {
    const secret = await api.secretUpdate(secretId, draft);
    if (this.state.selectedItemId) {
      await this.reloadItemContent(this.state.selectedItemId);
    }
    return secret;
  }

  public async deleteSecret(secretId: string): Promise<void> {
    await api.secretDelete(secretId);
    if (this.state.selectedItemId) {
      await this.reloadItemContent(this.state.selectedItemId);
    }
  }

  public async copySecretToEnvironment(secretId: string, targetEnvironmentId?: string | null): Promise<SecretMeta> {
    const secret = await api.secretCopyToEnvironment(secretId, targetEnvironmentId);
    if (this.state.selectedItemId) {
      await this.reloadItemContent(this.state.selectedItemId);
    }
    return secret;
  }

  // ==========================================================================
  // Asset Mutations
  // ==========================================================================

  public async uploadAsset(
    itemId: string,
    environmentId: string | undefined | null,
    name: string,
    mime: string | undefined | null,
    bytes: number[] | Uint8Array
  ): Promise<AssetMetaView> {
    const asset = await api.assetUpload(itemId, environmentId, name, mime, bytes);
    if (this.state.selectedItemId === itemId) {
      await this.reloadItemContent(itemId);
    }
    return asset;
  }

  public async renameAsset(id: string, name: string): Promise<AssetMetaView> {
    const asset = await api.assetRename(id, name);
    if (this.state.selectedItemId) {
      await this.reloadItemContent(this.state.selectedItemId);
    }
    return asset;
  }

  public async deleteAsset(id: string): Promise<void> {
    await api.assetDelete(id);
    if (this.state.selectedItemId) {
      await this.reloadItemContent(this.state.selectedItemId);
    }
  }

  // File mutations (backward-compatibility)
  public uploadFile = (
    itemId: string,
    environmentId: string | undefined | null,
    name: string,
    mime: string | undefined | null,
    bytes: number[] | Uint8Array
  ): Promise<FileMetaView> => this.uploadAsset(itemId, environmentId, name, mime, bytes);

  public renameFile = (id: string, name: string): Promise<FileMetaView> => this.renameAsset(id, name);

  public deleteFile = (id: string): Promise<void> => this.deleteAsset(id);

  // ==========================================================================
  // Note Mutations
  // ==========================================================================

  public async createNote(draft: NoteDraft): Promise<NoteMetaView> {
    const note = await api.noteCreate(draft);
    if (this.state.selectedItemId === draft.item_id) {
      await this.reloadItemContent(draft.item_id);
    }
    return {
      id: note.id,
      item_id: note.item_id,
      environment_id: note.environment_id,
      title: note.title,
      snippet: note.content.replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim().slice(0, 100),
      updated_at: note.updated_at,
      position: note.position,
    };
  }

  public async updateNote(id: string, draft: NoteUpdateDraft): Promise<void> {
    await api.noteUpdate(id, draft);
    if (this.state.selectedItemId) {
      await this.reloadItemContent(this.state.selectedItemId);
    }
  }

  public async deleteNote(id: string): Promise<void> {
    await api.noteDelete(id);
    if (this.state.selectedItemId) {
      await this.reloadItemContent(this.state.selectedItemId);
    }
  }

  // ==========================================================================
  // Dashboard & Settings Mutations
  // ==========================================================================

  public async updateDashboard(config: DashboardConfig): Promise<void> {
    await api.dashboardSet(config);
    this.setState({ dashboardConfig: config });
  }

  public async updateSettings(patch: SettingsPatch): Promise<Settings> {
    const updated = await api.settingsSet(patch);
    this.setState({ settings: updated });
    return updated;
  }

  public async unlock(): Promise<void> {
    const biometricEnabled = typeof window !== "undefined" && window.localStorage.getItem("secwet:biometric_unlock") !== "false";
    if (biometricEnabled) {
      await api.biometricAuthenticate("Unlock Secwet");
    }
    await api.vaultUnlock();
    this.setState({ status: { status: "unlocked" } });
    await this.reloadAll();
  }

  public async lock(): Promise<void> {
    await api.vaultLock();
    this.setState({
      status: { status: "locked" },
      secrets: [],
      assets: [],
      files: [],
      notes: [],
    });
  }

  // ==========================================================================
  // Backward-compatible Methods
  // ==========================================================================

  public selectProject(projectId: string, environmentId?: string) {
    this.selectItem(projectId, environmentId);
  }

  public async createProject(name: string, environments: string[]): Promise<ProjectView> {
    const defaultLabel = this.state.labels[0] || (await this.createLabel("Projects", "folder"));
    const item = await this.createItem(defaultLabel.id, name);
    const createdEnvs: EnvironmentView[] = [];
    for (const e of environments) {
      createdEnvs.push(await this.addEnvironment(item.id, e));
    }
    return {
      id: item.id,
      name: item.name,
      environments: createdEnvs,
    };
  }

  public async renameProject(projectId: string, name: string): Promise<void> {
    await this.renameItem(projectId, name);
  }

  public async deleteProject(projectId: string): Promise<void> {
    await this.deleteItem(projectId);
  }
}

export const appStore = new AppStore();
export const store = appStore;
export const vaultStore = appStore; // Backward-compatible alias

export type VaultStateSnapshot = AppStateSnapshot; // Backward-compatible alias
export type VaultStore = AppStore; // Backward-compatible alias

/** React hook subscribing to the application store */
export function useStore(): [AppStateSnapshot, AppStore] {
  const snapshot = useSyncExternalStore(appStore.subscribe, appStore.getState);
  return [snapshot, appStore];
}

/** Backward-compatible alias for useStore */
export const useVault = useStore;
