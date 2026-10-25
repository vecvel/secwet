// In-memory vault state for the UI. The vault engine will replace this with secwet-core calls;
// the action names match the operations it will expose.
import type { Environment, Project, Secret } from "./mock";

export interface VaultState {
  projects: Project[];
  secrets: Secret[];
}

export type SecretDraft = Omit<Secret, "id" | "updatedAt">;

export type VaultAction =
  | { type: "createProject"; project: Project }
  | { type: "renameProject"; projectId: string; name: string }
  | { type: "deleteProject"; projectId: string }
  | { type: "addEnvironment"; projectId: string; environment: Environment }
  | { type: "renameEnvironment"; projectId: string; environmentId: string; name: string }
  | { type: "deleteEnvironment"; projectId: string; environmentId: string }
  | { type: "addSecret"; secret: Secret }
  | { type: "updateSecret"; secretId: string; draft: SecretDraft }
  | { type: "deleteSecret"; secretId: string };

const mapProject = (state: VaultState, id: string, fn: (p: Project) => Project): VaultState => ({
  ...state,
  projects: state.projects.map((p) => (p.id === id ? fn(p) : p)),
});

export function vaultReducer(state: VaultState, action: VaultAction): VaultState {
  switch (action.type) {
    case "createProject":
      return { ...state, projects: [...state.projects, action.project] };
    case "renameProject":
      return mapProject(state, action.projectId, (p) => ({ ...p, name: action.name }));
    case "deleteProject":
      return {
        projects: state.projects.filter((p) => p.id !== action.projectId),
        secrets: state.secrets.filter((s) => s.projectId !== action.projectId),
      };
    case "addEnvironment":
      return mapProject(state, action.projectId, (p) => ({ ...p, environments: [...p.environments, action.environment] }));
    case "renameEnvironment":
      return mapProject(state, action.projectId, (p) => ({
        ...p,
        environments: p.environments.map((e) => (e.id === action.environmentId ? { ...e, name: action.name } : e)),
      }));
    case "deleteEnvironment":
      return {
        ...mapProject(state, action.projectId, (p) => ({ ...p, environments: p.environments.filter((e) => e.id !== action.environmentId) })),
        secrets: state.secrets.filter((s) => !(s.projectId === action.projectId && s.environmentId === action.environmentId)),
      };
    case "addSecret":
      return { ...state, secrets: [...state.secrets, action.secret] };
    case "updateSecret":
      return {
        ...state,
        secrets: state.secrets.map((s) => (s.id === action.secretId ? { ...s, ...action.draft, updatedAt: Date.now() } : s)),
      };
    case "deleteSecret":
      return { ...state, secrets: state.secrets.filter((s) => s.id !== action.secretId) };
  }
}

export const newId = () => crypto.randomUUID();

const MAX_NAME = 64;
const same = (a: string, b: string) => a.trim().toLowerCase() === b.trim().toLowerCase();

/** Returns an error message, or undefined when the name is usable. */
export function projectNameError(name: string, projects: Project[], exceptId?: string): string | undefined {
  const n = name.trim();
  if (!n) return "Enter a project name.";
  if (n.length > MAX_NAME) return `Keep the name under ${MAX_NAME} characters.`;
  if (projects.some((p) => p.id !== exceptId && same(p.name, n))) return `A project called ${n} already exists.`;
  return undefined;
}

export function environmentNameError(name: string, project: Project, exceptId?: string): string | undefined {
  const n = name.trim();
  if (!n) return "Enter an environment name.";
  if (n.length > MAX_NAME) return `Keep the name under ${MAX_NAME} characters.`;
  if (project.environments.some((e) => e.id !== exceptId && same(e.name, n))) return `${project.name} already has an environment called ${n}.`;
  return undefined;
}
