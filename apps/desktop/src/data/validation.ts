import type { Project } from "./mock";

export const newId = () => crypto.randomUUID();

export type Action = { type: string; [key: string]: any };
export type VaultAction = Action;

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
