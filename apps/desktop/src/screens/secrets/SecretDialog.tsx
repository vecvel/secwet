import { useEffect, useState, type FormEvent } from "react";
import { Button } from "../../components/Button";
import { Dialog } from "../../components/Dialog";
import { SelectField, TextArea, TextField } from "../../components/Field";
import { Icon } from "../../components/Icon";
import { kindLabels, type Project, type Secret, type SecretKind } from "../../data/mock";
import { api, type SecretMeta } from "../../lib/api";
import { parseSecretText } from "../../lib/secretParser";
import styles from "./SecretDialog.module.css";

type Draft = Omit<Secret, "id" | "updatedAt">;

interface SecretEntry {
  id: string;
  name: string;
  value: string;
  note?: string;
  errorName?: string;
  errorValue?: string;
}

interface Props {
  project?: Project | { id: string; name: string; environments?: Array<{ id: string; name: string }> };
  item?: { id: string; name: string };
  environments?: Array<{ id: string; name: string }>;
  defaultEnvironmentId?: string | null;
  existing: (Secret | SecretMeta)[];
  /** Present when editing; absent when adding. */
  initial?: Secret | SecretMeta;
  onCancel: () => void;
  onSave: (secret: Draft | Draft[]) => void;
}

const NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_.@-]*$/;

export function SecretDialog({
  project,
  item,
  environments: envListProp,
  defaultEnvironmentId,
  existing,
  initial,
  onCancel,
  onSave,
}: Props) {
  const containerName = item?.name || project?.name || "Item";
  const containerId = item?.id || project?.id || "";
  const environments = envListProp || (project && "environments" in project ? project.environments : []) || [];
  const hasEnvironments = environments.length > 0;

  // Type & Environment are configured once at the top for the entire batch
  const [kind, setKind] = useState<SecretKind>(initial?.kind ?? "env_var");

  // When adding: if defaultEnvironmentId is null, it is General (environmentId = null).
  // When editing: use secret's existing environment_id (null for General).
  const initialEnvId = initial
    ? ("environmentId" in initial && initial.environmentId ? initial.environmentId : (initial.environment_id ?? null))
    : (defaultEnvironmentId ?? null);

  const [environmentId, setEnvironmentId] = useState<string | null>(initialEnvId);

  // Entries list (supports single or multiple secrets)
  const [entries, setEntries] = useState<SecretEntry[]>([
    {
      id: initial?.id ?? "1",
      name: initial?.name ?? "",
      value: initial && "value" in initial && typeof (initial as any).value === "string" ? (initial as any).value : "",
      note: initial?.note ?? "",
    },
  ]);

  const [pastedNotice, setPastedNotice] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (initial && (!("value" in initial) || !(initial as any).value)) {
      api.secretReveal(initial.id)
        .then((val) => {
          setEntries((prev) =>
            prev.map((e, idx) => (idx === 0 ? { ...e, value: val } : e))
          );
        })
        .catch((e) => console.error("Failed to reveal secret for editing:", e));
    }
  }, [initial]);

  // Smart paste detector: detects .env, JSON, or key-value structures
  function handlePaste(e: React.ClipboardEvent) {
    if (initial) return; // In edit mode, allow standard single field paste
    const text = e.clipboardData.getData("text");
    if (!text || !text.trim()) return;

    const parsed = parseSecretText(text);
    if (
      parsed.length >= 2 ||
      (parsed.length === 1 && entries.length === 1 && !entries[0].name.trim() && !entries[0].value.trim())
    ) {
      e.preventDefault();
      const newEntries: SecretEntry[] = parsed.map((p, idx) => ({
        id: `${Date.now()}-${idx}`,
        name: p.name,
        value: p.value,
        note: "",
      }));
      setEntries(newEntries);
      setPastedNotice(`Detected ${parsed.length} ${parsed.length === 1 ? "secret" : "secrets"} from clipboard`);
      setTimeout(() => setPastedNotice(null), 3500);
    }
  }

  function addRow() {
    setEntries((prev) => [
      ...prev,
      {
        id: `${Date.now()}-${prev.length}`,
        name: "",
        value: "",
        note: "",
      },
    ]);
  }

  function removeRow(index: number) {
    if (entries.length <= 1) return;
    setEntries((prev) => prev.filter((_, idx) => idx !== index));
  }

  function updateEntry(index: number, patch: Partial<SecretEntry>) {
    setEntries((prev) =>
      prev.map((entry, idx) => (idx === index ? { ...entry, ...patch } : entry))
    );
  }

  function validate(): boolean {
    let isValid = true;
    const envName = environments.find((e) => e.id === environmentId)?.name;
    const namesSeen = new Set<string>();

    const updated = entries.map((entry) => {
      const errs: { errorName?: string; errorValue?: string } = {};
      const trimmed = entry.name.trim();

      if (!trimmed) {
        errs.errorName = "Enter a name.";
        isValid = false;
      } else if (!NAME_PATTERN.test(trimmed)) {
        errs.errorName = "Use letters, numbers, underscores, dots or dashes.";
        isValid = false;
      } else if (namesSeen.has(trimmed.toLowerCase())) {
        errs.errorName = "Duplicate name in this batch.";
        isValid = false;
      } else if (
        existing.some((s) => {
          const sEnvId = "environmentId" in s && s.environmentId ? s.environmentId : (s.environment_id || null);
          return (
            s.id !== initial?.id &&
            sEnvId === environmentId &&
            s.name.toLowerCase() === trimmed.toLowerCase()
          );
        })
      ) {
        errs.errorName = envName
          ? `Already exists in ${envName}.`
          : `Already exists in General.`;
        isValid = false;
      }

      namesSeen.add(trimmed.toLowerCase());

      if (!entry.value) {
        errs.errorValue = "Enter the secret value.";
        isValid = false;
      }

      return {
        ...entry,
        errorName: errs.errorName,
        errorValue: errs.errorValue,
      };
    });

    setEntries(updated);
    return isValid;
  }

  function submit(e: FormEvent) {
    e.preventDefault();
    if (saving) return;
    if (!validate()) return;
    setSaving(true);

    const cleanEnvId = environmentId && environmentId.trim() !== "" ? environmentId.trim() : null;

    const drafts: Draft[] = entries.map((entry) => ({
      item_id: containerId,
      projectId: containerId,
      project_id: containerId,
      environmentId: cleanEnvId || undefined,
      environment_id: cleanEnvId,
      name: entry.name.trim(),
      kind,
      value: entry.value,
      note: entry.note?.trim() || undefined,
    }));

    if (initial || drafts.length === 1) {
      onSave(drafts[0]);
    } else {
      onSave(drafts);
    }
  }

  const isEnvironmentScoped = hasEnvironments && initialEnvId !== null;
  const isMultiple = entries.length > 1;

  const dialogTitle = initial
    ? `Edit ${initial.name}`
    : isMultiple
    ? `Add ${entries.length} secrets`
    : "Add secret";

  const submitLabel = saving
    ? "Saving..."
    : initial
    ? "Save changes"
    : isMultiple
    ? `Save ${entries.length} secrets`
    : "Save secret";

  return (
    <Dialog
      title={dialogTitle}
      description={
        isEnvironmentScoped
          ? `Saved to ${containerName} (${environments.find((e) => e.id === environmentId)?.name || "Environment"}). The values are encrypted on this device before storage.`
          : `Saved as general secrets to ${containerName}. The values are encrypted on this device before storage.`
      }
      onClose={onCancel}
      footer={
        <>
          <Button variant="secondary" onClick={onCancel} disabled={saving}>
            Cancel
          </Button>
          <Button variant="primary" type="submit" form="secret-dialog" disabled={saving}>
            {submitLabel}
          </Button>
        </>
      }
    >
      <form id="secret-dialog" className={styles.form} onSubmit={submit} onPaste={handlePaste} noValidate>
        {/* Top Configuration: Secret Type & Environment placed above Name */}
        <div className={styles.topConfigRow}>
          <div className={isEnvironmentScoped ? styles.pair : undefined}>
            <SelectField
              label="Type"
              name="kind"
              value={kind}
              onChange={(e) => setKind(e.target.value as SecretKind)}
            >
              {Object.entries(kindLabels).map(([k, label]) => (
                <option key={k} value={k}>
                  {label}
                </option>
              ))}
            </SelectField>

            {/* Environment selector is ONLY rendered when inside an environment, never in General */}
            {isEnvironmentScoped && (
              <SelectField
                label="Environment"
                name="environment"
                value={environmentId || ""}
                onChange={(e) => setEnvironmentId(e.target.value || null)}
              >
                {environments.map((env) => (
                  <option key={env.id} value={env.id}>
                    {env.name}
                  </option>
                ))}
              </SelectField>
            )}
          </div>
        </div>

        {pastedNotice && (
          <div className={styles.pasteNotice} role="status">
            <Icon name="check" size={14} />
            <span>{pastedNotice}</span>
          </div>
        )}

        {/* Entries list */}
        <div className={styles.entriesList}>
          {entries.map((entry, index) => (
            <div
              key={entry.id}
              className={`${styles.entryItem} ${isMultiple && index > 0 ? styles.entryItemSeparator : ""}`}
            >
              {isMultiple && (
                <div className={styles.entryHeader}>
                  <span className={styles.entryBadge}>#{index + 1}</span>
                  <button
                    type="button"
                    className={styles.removeBtn}
                    title="Remove secret from batch"
                    onClick={() => removeRow(index)}
                  >
                    <Icon name="trash" size={14} />
                  </button>
                </div>
              )}

              <TextField
                label="Name"
                name={`name-${index}`}
                autoComplete="off"
                spellCheck={false}
                placeholder="DATABASE_URL"
                value={entry.name}
                error={entry.errorName}
                autoFocus={index === 0 && !initial}
                onChange={(e) => {
                  updateEntry(index, { name: e.target.value, errorName: undefined });
                }}
              />

              <TextArea
                label="Value"
                name={`value-${index}`}
                autoComplete="off"
                spellCheck={false}
                placeholder="postgres://user:password@host:5432/db"
                value={entry.value}
                error={entry.errorValue}
                onChange={(e) => {
                  updateEntry(index, { value: e.target.value, errorValue: undefined });
                }}
              />

              {(!isMultiple || entry.note) && (
                <TextField
                  label="Note"
                  name={`note-${index}`}
                  help="Optional. Encrypted with the secret."
                  placeholder="Rotates every 90 days"
                  value={entry.note || ""}
                  onChange={(e) => updateEntry(index, { note: e.target.value })}
                />
              )}
            </div>
          ))}
        </div>

        {/* Add Another & Paste Tip */}
        {!initial && (
          <div className={styles.addAnotherSection}>
            <Button variant="secondary" icon="plus" onClick={addRow}>
              Add another
            </Button>
            <span className={styles.pasteTip}>
              Tip: Paste .env, JSON, or key=value pairs to auto-fill
            </span>
          </div>
        )}
      </form>
    </Dialog>
  );
}
