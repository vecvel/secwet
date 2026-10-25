import { useEffect, useMemo, useState, type Dispatch } from "react";
import { Button } from "../../components/Button";
import { ConfirmDialog } from "../../components/ConfirmDialog";
import { EmptyState } from "../../components/EmptyState";
import { SearchInput } from "../../components/Field";
import { MoreMenu, type MenuItem } from "../../components/Menu";
import { NameDialog } from "../../components/NameDialog";
import { SegmentedTabs } from "../../components/SegmentedTabs";
import type { Project, Secret } from "../../data/mock";
import { environmentNameError, newId, projectNameError, type VaultAction } from "../../data/vault";
import { type SecretMeta } from "../../lib/api";
import { plural } from "../../lib/format";
import { vaultStore } from "../../lib/store";
import { CopySecretDialog } from "./CopySecretDialog";
import { SecretDialog } from "./SecretDialog";
import { SecretRow } from "./SecretRow";
import styles from "./SecretsScreen.module.css";

interface Props {
  project: Project;
  projects: Project[];
  environmentId: string;
  onEnvironmentChange: (id: string) => void;
  secrets: (Secret | SecretMeta)[];
  dispatch: Dispatch<VaultAction>;
  onNewProject: () => void;
  /** Opens the add-secret dialog on mount (used by Overview's Add secret). */
  startAdding?: boolean;
  onStartedAdding?: () => void;
}

type Modal =
  | { kind: "addSecret" }
  | { kind: "editSecret"; secret: Secret | SecretMeta }
  | { kind: "copySecret"; secret: Secret | SecretMeta }
  | { kind: "deleteSecret"; secret: Secret | SecretMeta }
  | { kind: "renameProject" }
  | { kind: "deleteProject" }
  | { kind: "newEnvironment" }
  | { kind: "renameEnvironment" }
  | { kind: "deleteEnvironment" };

export function SecretsScreen({
  project,
  projects,
  environmentId,
  onEnvironmentChange,
  secrets,
  dispatch,
  onNewProject,
  startAdding,
  onStartedAdding,
}: Props) {
  const [query, setQuery] = useState("");
  const [modal, setModal] = useState<Modal | null>(() => (startAdding ? { kind: "addSecret" } : null));

  useEffect(() => {
    if (startAdding) onStartedAdding?.();
  }, []);
  const close = () => setModal(null);

  const projectSecrets = secrets.filter((s) => {
    const pId = "projectId" in s && s.projectId ? s.projectId : s.project_id;
    return pId === project.id;
  });

  const envSecrets = projectSecrets.filter((s) => {
    const eId = "environmentId" in s && s.environmentId ? s.environmentId : s.environment_id;
    return eId === environmentId;
  });

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    return envSecrets
      .filter((s) => !q || s.name.toLowerCase().includes(q))
      .sort((a, b) => a.name.localeCompare(b.name));
  }, [envSecrets, query]);

  const env = project.environments.find((e) => e.id === environmentId);
  const envName = env?.name ?? "";
  const canDeleteEnv = project.environments.length > 1;

  const tabs = project.environments.map((e) => ({
    id: e.id,
    label: e.name,
    count:
      (e as any).secret_count !== undefined
        ? (e as any).secret_count
        : projectSecrets.filter((s) => {
            const eId = "environmentId" in s && s.environmentId ? s.environmentId : s.environment_id;
            return eId === e.id;
          }).length,
  }));

  const projectMenu: MenuItem[] = [
    { label: "New project", icon: "plus", onSelect: onNewProject },
    { label: "Rename project", icon: "pencil", onSelect: () => setModal({ kind: "renameProject" }) },
    { label: "New environment", icon: "layers", onSelect: () => setModal({ kind: "newEnvironment" }) },
    { label: `Rename ${envName}`, icon: "pencil", onSelect: () => setModal({ kind: "renameEnvironment" }) },
    ...(canDeleteEnv
      ? ([
          {
            label: `Delete ${envName}`,
            icon: "trash",
            danger: true,
            separator: true,
            onSelect: () => setModal({ kind: "deleteEnvironment" }),
          } satisfies MenuItem,
        ] as MenuItem[])
      : []),
    {
      label: "Delete project",
      icon: "trash",
      danger: true,
      separator: !canDeleteEnv,
      onSelect: () => setModal({ kind: "deleteProject" }),
    },
  ];

  return (
    <div className={styles.screen}>
      <div className={styles.header}>
        <div className={styles.titles}>
          <h1 className={styles.title}>{project.name}</h1>
          <p className={styles.subtitle}>
            {plural(projectSecrets.length, "secret")} across {plural(project.environments.length, "environment")}. Encrypted on this device.
          </p>
        </div>
        <div className={styles.actions}>
          <Button variant="primary" icon="plus" onClick={() => setModal({ kind: "addSecret" })}>
            Add secret
          </Button>
          <MoreMenu label={`Project actions for ${project.name}`} items={projectMenu} />
        </div>
      </div>

      <div className={styles.toolbar}>
        <SegmentedTabs
          label="Environment"
          items={tabs}
          value={environmentId}
          onChange={onEnvironmentChange}
          onAdd={() => setModal({ kind: "newEnvironment" })}
          addLabel="New environment"
        />
        <SearchInput
          className={styles.search}
          placeholder="Filter by name"
          aria-label={`Filter ${envName} secrets by name`}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
      </div>

      <section className={styles.list} aria-label={`${envName} secrets`}>
        {envSecrets.length === 0 ? (
          <EmptyState
            icon="lock"
            title={`No secrets in ${envName} yet`}
            body="Secrets you add are encrypted on this device before they are saved. Nothing leaves this device on the Free plan."
            action={
              <Button variant="secondary" icon="plus" onClick={() => setModal({ kind: "addSecret" })}>
                Add secret
              </Button>
            }
          />
        ) : visible.length === 0 ? (
          <EmptyState
            icon="search"
            title={`No secrets match "${query.trim()}"`}
            body={`Try a different name, or clear the filter to see all ${envSecrets.length} ${envName} secrets.`}
            action={
              <Button variant="tertiary" onClick={() => setQuery("")}>
                Clear filter
              </Button>
            }
          />
        ) : (
          <ul className={styles.rows}>
            {visible.map((s) => (
              <SecretRow
                key={s.id}
                secret={s}
                canCopy={project.environments.length > 1}
                onEdit={() => setModal({ kind: "editSecret", secret: s })}
                onCopyToEnvironment={() => setModal({ kind: "copySecret", secret: s })}
                onDelete={() => setModal({ kind: "deleteSecret", secret: s })}
              />
            ))}
          </ul>
        )}
      </section>

      {(modal?.kind === "addSecret" || modal?.kind === "editSecret") && (
        <SecretDialog
          project={project}
          defaultEnvironmentId={environmentId}
          existing={projectSecrets}
          initial={modal.kind === "editSecret" ? modal.secret : undefined}
          onCancel={close}
          onSave={async (draft) => {
            if (modal.kind === "editSecret") {
              await vaultStore.updateSecret(modal.secret.id, {
                project_id: project.id,
                environment_id: draft.environmentId,
                name: draft.name,
                kind: draft.kind,
                value: draft.value,
                note: draft.note,
              });
            } else {
              await vaultStore.addSecret({
                project_id: project.id,
                environment_id: draft.environmentId,
                name: draft.name,
                kind: draft.kind,
                value: draft.value,
                note: draft.note,
              });
            }
            onEnvironmentChange(draft.environmentId);
            setQuery("");
            close();
          }}
        />
      )}

      {modal?.kind === "copySecret" && (
        <CopySecretDialog
          project={project}
          secret={modal.secret}
          existing={projectSecrets}
          onCancel={close}
          onCopy={async (targetId) => {
            try {
              await vaultStore.copySecretToEnvironment(modal.secret.id, targetId);
            } catch (e) {
              console.error("Failed to copy secret via backend:", e);
              dispatch({
                type: "addSecret",
                secret: {
                  id: newId(),
                  projectId: project.id,
                  environmentId: targetId,
                  name: modal.secret.name,
                  kind: modal.secret.kind,
                  value:
                    "value" in modal.secret && typeof (modal.secret as any).value === "string"
                      ? (modal.secret as any).value
                      : "",
                  note: modal.secret.note,
                  updatedAt: Date.now(),
                },
              });
            }
            onEnvironmentChange(targetId);
            close();
          }}
        />
      )}

      {modal?.kind === "deleteSecret" && (
        <ConfirmDialog
          title={`Delete ${modal.secret.name}?`}
          body={<p>It is removed from {envName} on this device, and from paired devices on their next sync. Change the secret at its source if anyone else may have seen it.</p>}
          confirmLabel="Delete secret"
          onCancel={close}
          onConfirm={async () => {
            await vaultStore.deleteSecret(modal.secret.id);
            close();
          }}
        />
      )}

      {modal?.kind === "renameProject" && (
        <NameDialog
          title="Rename project"
          label="Name"
          initial={project.name}
          confirmLabel="Rename"
          validate={(v) => projectNameError(v, projects, project.id)}
          onCancel={close}
          onSubmit={async (name) => {
            await vaultStore.renameProject(project.id, name);
            close();
          }}
        />
      )}

      {modal?.kind === "deleteProject" && (
        <ConfirmDialog
          title={`Delete ${project.name}?`}
          body={
            <p>
              This deletes {plural(projectSecrets.length, "secret")} in {plural(project.environments.length, "environment")} from this vault, and from paired devices on their next sync. Copies
              already on a revoked device can't be removed.
            </p>
          }
          requireText={project.name}
          confirmLabel="Delete project"
          onCancel={close}
          onConfirm={async () => {
            await vaultStore.deleteProject(project.id);
            close();
          }}
        />
      )}

      {modal?.kind === "newEnvironment" && (
        <NameDialog
          title="New environment"
          description={`Adds an empty environment to ${project.name}.`}
          label="Name"
          placeholder="Preview"
          confirmLabel="Create environment"
          validate={(v) => environmentNameError(v, project)}
          onCancel={close}
          onSubmit={async (name) => {
            const env = await vaultStore.addEnvironment(project.id, name);
            onEnvironmentChange(env.id);
            close();
          }}
        />
      )}

      {modal?.kind === "renameEnvironment" && env && (
        <NameDialog
          title={`Rename ${env.name}`}
          label="Name"
          initial={env.name}
          confirmLabel="Rename"
          validate={(v) => environmentNameError(v, project, env.id)}
          onCancel={close}
          onSubmit={async (name) => {
            await vaultStore.renameEnvironment(project.id, env.id, name);
            close();
          }}
        />
      )}

      {modal?.kind === "deleteEnvironment" && env && (
        <ConfirmDialog
          title={`Delete ${env.name}?`}
          body={<p>This deletes the environment and its {plural(envSecrets.length, "secret")} from {project.name}, and from paired devices on their next sync.</p>}
          requireText={env.name}
          confirmLabel="Delete environment"
          onCancel={close}
          onConfirm={async () => {
            await vaultStore.deleteEnvironment(project.id, env.id);
            const remaining = project.environments.filter((e) => e.id !== env.id);
            if (remaining[0]) {
              onEnvironmentChange(remaining[0].id);
            }
            close();
          }}
        />
      )}
    </div>
  );
}
