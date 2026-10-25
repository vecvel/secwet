import { useState, type FormEvent } from "react";
import { Button } from "../../components/Button";
import { Dialog } from "../../components/Dialog";
import { SelectField } from "../../components/Field";
import type { Project, Secret } from "../../data/mock";
import type { SecretMeta } from "../../lib/api";

interface Props {
  project: Project;
  secret: Secret | SecretMeta;
  existing: (Secret | SecretMeta)[];
  onCancel: () => void;
  onCopy: (environmentId: string) => void;
}

/** Copies one secret into another environment of the same project. */
export function CopySecretDialog({ project, secret, existing, onCancel, onCopy }: Props) {
  const secretEnvId = "environmentId" in secret && secret.environmentId ? secret.environmentId : secret.environment_id;
  const targets = project.environments.filter((e) => e.id !== secretEnvId);
  const [target, setTarget] = useState(targets[0]?.id ?? "");
  const [error, setError] = useState<string>();

  function submit(e: FormEvent) {
    e.preventDefault();
    const env = targets.find((t) => t.id === target);
    if (!env) return;
    if (
      existing.some((s) => {
        const sEnvId = "environmentId" in s && s.environmentId ? s.environmentId : s.environment_id;
        return sEnvId === env.id && s.name === secret.name;
      })
    ) {
      setError(`${secret.name} already exists in ${env.name}. Edit that one instead, or delete it first.`);
      return;
    }
    onCopy(env.id);
  }

  return (
    <Dialog
      title={`Copy ${secret.name}`}
      description="Creates a separate copy with the same name, type, value and note. Later edits to one don't change the other."
      onClose={onCancel}
      footer={
        <>
          <Button variant="secondary" onClick={onCancel}>
            Cancel
          </Button>
          <Button variant="primary" type="submit" form="copy-secret">
            Copy secret
          </Button>
        </>
      }
    >
      <form id="copy-secret" className="form-contents" onSubmit={submit} noValidate>
        <SelectField
          label="Copy to"
          name="environment"
          value={target}
          error={error}
          onChange={(e) => {
            setTarget(e.target.value);
            setError(undefined);
          }}
        >
          {targets.map((env) => (
            <option key={env.id} value={env.id}>
              {env.name}
            </option>
          ))}
        </SelectField>
      </form>
    </Dialog>
  );
}
