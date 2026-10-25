/**
 * apps/desktop/src/lib/store.ts
 *
 * Reactive store for Secwet Desktop using useSyncExternalStore.
 * Authoritative: docs/IMPLEMENTATION.md §9.2.
 */
import { useSyncExternalStore } from "react";
import type { Environment } from "../data/mock";
import type { VaultAction } from "../data/vault";
import {
  api,
  isUnlocked,
  isUninitialized,
  type Overview,
  type ProjectView,
  type SecretDraft,
  type SecretMeta,
  type Settings,
  type VaultStatus,
} from "./api";

export interface VaultStateSnapshot {
  status: VaultStatus;
  projects: ProjectView[];
  secrets: SecretMeta[];
  overview: Overview | null;
  settings: Settings;
  selectedProjectId: string | null;
  selectedEnvironmentId: string | null;
  loading: boolean;
  error: string | null;
}

class VaultStore {
  private state: VaultStateSnapshot = {
    status: { status: "uninitialized" },
    projects: [],
    secrets: [],
    overview: null,
    settings: {
      theme: "system",
      lock_timeout_minutes: 15,
      lock_minutes: 15,
      device_name: "MacBook Pro",
    },
    selectedProjectId: null,
    selectedEnvironmentId: null,
    loading: true,
    error: null,
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
        console.error("VaultStore listener error:", e);
      }
    }
  }

  public getState = (): VaultStateSnapshot => this.state;

  public subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };

  private setState(partial: Partial<VaultStateSnapshot>) {
    this.state = { ...this.state, ...partial };
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
        });
      });

      this.unlistenFns = [unlistenChanged, unlistenLocked];

      // 2. Fetch initial status
      let status = await api.vaultStatus();
      if (isUninitialized(status)) {
        // Section 7 F1: create vault silently on first run
        status = await api.vaultCreate();
      }

      this.setState({ status });

      if (isUnlocked(status)) {
        await this.reloadAll();
      } else {
        this.setState({ loading: false });
      }
    } catch (err: any) {
      console.error("Vault initialization failed:", err);
      this.setState({ loading: false, error: err?.message || "Failed to initialize vault." });
    }
  }

  public destroy() {
    this.unlistenFns.forEach((fn) => fn());
    this.unlistenFns = [];
  }

  public async reloadAll() {
    try {
      const [projects, overview, settings] = await Promise.all([
        api.projectsList(),
        api.overview().catch(() => null),
        api.settingsGet().catch(() => this.state.settings),
      ]);

      let selectedProjectId = this.state.selectedProjectId;
      if (!selectedProjectId || !projects.some((p) => p.id === selectedProjectId)) {
        selectedProjectId = projects[0]?.id || null;
      }

      const currentProject = projects.find((p) => p.id === selectedProjectId);
      let selectedEnvironmentId = this.state.selectedEnvironmentId;
      if (currentProject) {
        if (!selectedEnvironmentId || !currentProject.environments.some((e) => e.id === selectedEnvironmentId)) {
          selectedEnvironmentId = currentProject.environments[0]?.id || null;
        }
      }

      // Load all secrets across projects and environments
      const envIds = projects.flatMap((p) => p.environments.map((e) => e.id));
      const secretBatches = await Promise.all(
        envIds.map((id) => api.secretsList(id).catch(() => [] as SecretMeta[]))
      );
      const allSecrets = secretBatches.flat();

      this.setState({
        projects,
        overview,
        settings,
        selectedProjectId,
        selectedEnvironmentId,
        secrets: allSecrets,
        loading: false,
      });
    } catch (err: any) {
      console.error("Failed to reload vault data:", err);
      this.setState({ loading: false, error: err?.message || "Failed to load vault data." });
    }
  }

  public async reloadSecrets() {
    try {
      const projects = this.state.projects;
      const envIds = projects.flatMap((p) => p.environments.map((e) => e.id));
      const [secretBatches, overview] = await Promise.all([
        Promise.all(envIds.map((id) => api.secretsList(id).catch(() => [] as SecretMeta[]))),
        api.overview().catch(() => null),
      ]);
      const allSecrets = secretBatches.flat();
      this.setState({ secrets: allSecrets, overview });
    } catch (err) {
      console.error("Failed to reload secrets:", err);
    }
  }

  public selectProject(projectId: string, environmentId?: string) {
    const project = this.state.projects.find((p) => p.id === projectId);
    const envId = environmentId || project?.environments[0]?.id || null;
    this.setState({
      selectedProjectId: projectId,
      selectedEnvironmentId: envId,
    });
  }

  public selectEnvironment(projectId: string, environmentId: string) {
    this.setState({
      selectedProjectId: projectId,
      selectedEnvironmentId: environmentId,
    });
  }

  public async handleVaultChanged(scope: string) {
    if (!isUnlocked(this.state.status)) return;

    if (scope === "projects" || scope === "environments" || scope === "all") {
      await this.reloadAll();
    } else if (scope === "secrets") {
      await this.reloadSecrets();
    } else if (scope === "settings") {
      const settings = await api.settingsGet();
      this.setState({ settings });
    }
  }

  // ==========================================================================
  // Store Mutation Methods
  // ==========================================================================

  public async createProject(name: string, environments: string[]): Promise<ProjectView> {
    const project = await api.projectCreate(name, environments);
    await this.reloadAll();
    this.selectProject(project.id, project.environments[0]?.id);
    return project;
  }

  public async renameProject(projectId: string, name: string): Promise<void> {
    await api.projectRename(projectId, name);
    await this.reloadAll();
  }

  public async deleteProject(projectId: string): Promise<void> {
    await api.projectDelete(projectId);
    await this.reloadAll();
  }

  public async addEnvironment(projectId: string, name: string): Promise<Environment> {
    const env = await api.environmentAdd(projectId, name);
    await this.reloadAll();
    this.selectEnvironment(projectId, env.id);
    return env;
  }

  public async renameEnvironment(_projectId: string, environmentId: string, name: string): Promise<void> {
    await api.environmentRename(environmentId, name);
    await this.reloadAll();
  }

  public async deleteEnvironment(_projectId: string, environmentId: string): Promise<void> {
    await api.environmentDelete(environmentId);
    await this.reloadAll();
  }

  public async addSecret(draft: SecretDraft): Promise<SecretMeta> {
    const secret = await api.secretCreate(draft);
    await this.reloadSecrets();
    return secret;
  }

  public async updateSecret(secretId: string, draft: SecretDraft): Promise<SecretMeta> {
    const secret = await api.secretUpdate(secretId, draft);
    await this.reloadSecrets();
    return secret;
  }

  public async deleteSecret(secretId: string): Promise<void> {
    await api.secretDelete(secretId);
    await this.reloadSecrets();
  }

  public async copySecretToEnvironment(secretId: string, targetEnvironmentId: string): Promise<SecretMeta> {
    const secret = await api.secretCopyToEnvironment(secretId, targetEnvironmentId);
    await this.reloadSecrets();
    return secret;
  }

  public async unlock(): Promise<void> {
    await api.vaultUnlock();
    this.setState({ status: { status: "unlocked" } });
    await this.reloadAll();
  }

  public async lock(): Promise<void> {
    await api.vaultLock();
    this.setState({ status: { status: "locked" }, secrets: [] });
  }

  public async updateSettings(settings: Partial<Settings>): Promise<Settings> {
    const updated = await api.settingsSet(settings);
    this.setState({ settings: updated });
    return updated;
  }

  // ==========================================================================
  // Backward-compatible Dispatch Adapter for VaultAction
  // ==========================================================================

  public dispatch = (action: VaultAction) => {
    switch (action.type) {
      case "createProject":
        this.createProject(
          action.project.name,
          action.project.environments.map((e) => e.name)
        ).catch((e) => console.error("dispatch createProject error:", e));
        break;
      case "renameProject":
        this.renameProject(action.projectId, action.name).catch((e) =>
          console.error("dispatch renameProject error:", e)
        );
        break;
      case "deleteProject":
        this.deleteProject(action.projectId).catch((e) =>
          console.error("dispatch deleteProject error:", e)
        );
        break;
      case "addEnvironment":
        this.addEnvironment(action.projectId, action.environment.name).catch((e) =>
          console.error("dispatch addEnvironment error:", e)
        );
        break;
      case "renameEnvironment":
        this.renameEnvironment(action.projectId, action.environmentId, action.name).catch((e) =>
          console.error("dispatch renameEnvironment error:", e)
        );
        break;
      case "deleteEnvironment":
        this.deleteEnvironment(action.projectId, action.environmentId).catch((e) =>
          console.error("dispatch deleteEnvironment error:", e)
        );
        break;
      case "addSecret":
        this.addSecret({
          project_id: action.secret.projectId,
          environment_id: action.secret.environmentId,
          name: action.secret.name,
          kind: action.secret.kind,
          value: action.secret.value,
          note: action.secret.note,
        }).catch((e) => console.error("dispatch addSecret error:", e));
        break;
      case "updateSecret":
        this.updateSecret(action.secretId, {
          project_id: action.draft.projectId,
          environment_id: action.draft.environmentId,
          name: action.draft.name,
          kind: action.draft.kind,
          value: action.draft.value,
          note: action.draft.note,
        }).catch((e) => console.error("dispatch updateSecret error:", e));
        break;
      case "deleteSecret":
        this.deleteSecret(action.secretId).catch((e) =>
          console.error("dispatch deleteSecret error:", e)
        );
        break;
    }
  };
}

export const vaultStore = new VaultStore();

/** React hook subscribing to the VaultStore */
export function useVault(): [VaultStateSnapshot, VaultStore] {
  const snapshot = useSyncExternalStore(vaultStore.subscribe, vaultStore.getState);
  return [snapshot, vaultStore];
}
