import { useState, type FormEvent } from "react";
import { Button } from "../../components/Button";
import { Dialog } from "../../components/Dialog";
import { TextField } from "../../components/Field";
import type { Project } from "../../data/mock";
import { newId, projectNameError } from "../../data/vault";

const DEFAULT_ENVS = "Development, Staging, Production";
const MAX_ENVS = 12;

export function NewProjectDialog({ projects, onCreate, onCancel }: { projects: Project[]; onCreate: (p: Project) => void; onCancel: () => void }) {
  const [name, setName] = useState("");
  const [envs, setEnvs] = useState(DEFAULT_ENVS);
  const [errors, setErrors] = useState<{ name?: string; envs?: string }>({});

  function parseEnvs() {
    return envs
      .split(",")
      .map((e) => e.trim())
      .filter(Boolean);
  }

  function submit(e: FormEvent) {
    e.preventDefault();
    const list = parseEnvs();
    const lower = list.map((e) => e.toLowerCase());
    const next = {
      name: projectNameError(name, projects),
      envs:
        list.length === 0
          ? "Add at least one environment."
          : list.length > MAX_ENVS
            ? `Use at most ${MAX_ENVS} environments.`
            : new Set(lower).size !== lower.length
              ? "Each environment needs a different name."
              : undefined,
    };
    setErrors(next);
    if (next.name || next.envs) return;
    onCreate({ id: newId(), name: name.trim(), environments: list.map((n) => ({ id: newId(), name: n })) });
  }

  return (
    <Dialog
      title="New project"
      description="Projects group secrets for one app or service. Everything stays encrypted on this device."
      onClose={onCancel}
      footer={
        <>
          <Button variant="secondary" onClick={onCancel}>
            Cancel
          </Button>
          <Button variant="primary" type="submit" form="new-project">
            Create project
          </Button>
        </>
      }
    >
      <form id="new-project" onSubmit={submit} noValidate className="form-contents">
        <TextField
          label="Name"
          name="name"
          autoComplete="off"
          spellCheck={false}
          placeholder="billing-service"
          value={name}
          error={errors.name}
          onChange={(e) => {
            setName(e.target.value);
            if (errors.name) setErrors((x) => ({ ...x, name: undefined }));
          }}
        />
        <TextField
          label="Environments"
          name="environments"
          autoComplete="off"
          help="Separate names with commas. You can rename or add environments later."
          value={envs}
          error={errors.envs}
          onChange={(e) => {
            setEnvs(e.target.value);
            if (errors.envs) setErrors((x) => ({ ...x, envs: undefined }));
          }}
        />
      </form>
    </Dialog>
  );
}
