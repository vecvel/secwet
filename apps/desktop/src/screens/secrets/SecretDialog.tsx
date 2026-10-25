import { useEffect, useState, type FormEvent } from "react";
import { Button } from "../../components/Button";
import { Dialog } from "../../components/Dialog";
import { SelectField, TextArea, TextField } from "../../components/Field";
import { kindLabels, type Project, type Secret, type SecretKind } from "../../data/mock";
import { api, type SecretMeta } from "../../lib/api";
import styles from "./SecretDialog.module.css";

type Draft = Omit<Secret, "id" | "updatedAt">;

interface Props {
  project: Project;
  defaultEnvironmentId: string;
  existing: (Secret | SecretMeta)[];
  /** Present when editing; absent when adding. */
  initial?: Secret | SecretMeta;
  onCancel: () => void;
  onSave: (secret: Draft) => void;
}

const NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_.@-]*$/;

/** Adds a secret, or edits one when `initial` is given. */
export function SecretDialog({ project, defaultEnvironmentId, existing, initial, onCancel, onSave }: Props) {
  const [name, setName] = useState(initial?.name ?? "");
  const [kind, setKind] = useState<SecretKind>(initial?.kind ?? "env_var");
  const initialEnvId = initial
    ? ("environmentId" in initial && initial.environmentId ? initial.environmentId : initial.environment_id)
    : defaultEnvironmentId;
  const [environmentId, setEnvironmentId] = useState(initialEnvId ?? defaultEnvironmentId);
  const [value, setValue] = useState(
    initial && "value" in initial && typeof (initial as any).value === "string" ? (initial as any).value : ""
  );
  const [note, setNote] = useState(initial?.note ?? "");
  const [errors, setErrors] = useState<{ name?: string; value?: string }>({});
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (initial && (!("value" in initial) || !(initial as any).value)) {
      api.secretReveal(initial.id)
        .then((val) => setValue(val))
        .catch((e) => console.error("Failed to reveal secret for editing:", e));
    }
  }, [initial]);

  function validate() {
    const next: typeof errors = {};
    const trimmed = name.trim();
    const envName = project.environments.find((e) => e.id === environmentId)?.name;
    if (!trimmed) next.name = "Enter a name for this secret.";
    else if (!NAME_PATTERN.test(trimmed)) next.name = "Use letters, numbers, underscores, dots or dashes, starting with a letter or underscore.";
    else if (
      existing.some((s) => {
        const sEnvId = "environmentId" in s && s.environmentId ? s.environmentId : s.environment_id;
        return s.id !== initial?.id && sEnvId === environmentId && s.name === trimmed;
      })
    ) {
      next.name = `${trimmed} already exists in ${envName}. Pick another name or environment.`;
    }
    if (!value) next.value = "Enter the secret value.";
    return next;
  }

  function submit(e: FormEvent) {
    e.preventDefault();
    if (saving) return;
    const next = validate();
    setErrors(next);
    if (next.name || next.value) return;
    setSaving(true);
    onSave({ projectId: project.id, environmentId, name: name.trim(), kind, value, note: note.trim() || undefined });
  }

  return (
    <Dialog
      title={initial ? `Edit ${initial.name}` : "Add secret"}
      description={`Saved to ${project.name}. The value is encrypted on this device before it is stored.`}
      onClose={onCancel}
      footer={
        <>
          <Button variant="secondary" onClick={onCancel}>
            Cancel
          </Button>
          <Button variant="primary" type="submit" form="secret-dialog" disabled={saving}>
            {saving ? "Saving" : initial ? "Save changes" : "Save secret"}
          </Button>
        </>
      }
    >
      <form id="secret-dialog" className={styles.form} onSubmit={submit} noValidate>
        <TextField
          label="Name"
          name="name"
          autoComplete="off"
          spellCheck={false}
          placeholder="DATABASE_URL"
          value={name}
          error={errors.name}
          onChange={(e) => {
            setName(e.target.value);
            if (errors.name) setErrors((x) => ({ ...x, name: undefined }));
          }}
        />
        <div className={styles.pair}>
          <SelectField label="Type" name="kind" value={kind} onChange={(e) => setKind(e.target.value as SecretKind)}>
            {Object.entries(kindLabels).map(([k, label]) => (
              <option key={k} value={k}>
                {label}
              </option>
            ))}
          </SelectField>
          <SelectField label="Environment" name="environment" value={environmentId} onChange={(e) => setEnvironmentId(e.target.value)}>
            {project.environments.map((env) => (
              <option key={env.id} value={env.id}>
                {env.name}
              </option>
            ))}
          </SelectField>
        </div>
        <TextArea
          label="Value"
          name="value"
          autoComplete="off"
          spellCheck={false}
          placeholder="postgres://user:password@host:5432/db"
          value={value}
          error={errors.value}
          onChange={(e) => {
            setValue(e.target.value);
            if (errors.value) setErrors((x) => ({ ...x, value: undefined }));
          }}
        />
        <TextField label="Note" name="note" help="Optional. Encrypted with the secret." placeholder="Rotates every 90 days" value={note} onChange={(e) => setNote(e.target.value)} />
      </form>
    </Dialog>
  );
}
