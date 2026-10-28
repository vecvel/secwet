import { useState, type FormEvent } from "react";
import { Button } from "../../components/Button";
import { Dialog } from "../../components/Dialog";
import { SelectField, TextField } from "../../components/Field";
import type { SpaceView } from "../../lib/api";

interface Props {
  onCancel: () => void;
  onCreate: (name: string, icon?: string, spaceId?: string) => Promise<void> | void;
  spaces?: SpaceView[];
  defaultSpaceId?: string | null;
}

export function NewGroupDialog({ onCancel, onCreate, spaces = [], defaultSpaceId }: Props) {
  const [name, setName] = useState("");
  const defaultSelectedSpace =
    defaultSpaceId || spaces.find((s) => s.is_default)?.id || spaces[0]?.id || "";
  const [spaceId, setSpaceId] = useState(defaultSelectedSpace);
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    const trimmed = name.trim();
    if (!trimmed) {
      setError("Name cannot be empty");
      return;
    }
    setBusy(true);
    try {
      await onCreate(trimmed, "folder", spaceId || undefined);
    } catch (err: any) {
      setError(err?.message || "Failed to create");
      setBusy(false);
    }
  }

  return (
    <Dialog
      title="New Group"
      description="Create a section to organize your projects, credentials, and services."
      onClose={onCancel}
      footer={
        <>
          <Button variant="secondary" onClick={onCancel} disabled={busy}>
            Cancel
          </Button>
          <Button variant="primary" onClick={handleSubmit} disabled={busy || !name.trim()}>
            {busy ? "Creating..." : "Create Group"}
          </Button>
        </>
      }
    >
      <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: "var(--space-4)" }}>
        <TextField
          label="Name"
          value={name}
          onChange={(e) => {
            setName(e.target.value);
            if (error) setError(undefined);
          }}
          placeholder="e.g. Backend Services, Mobile Apps, Infrastructure"
          error={error}
          autoFocus
        />

        {spaces.length > 0 && (
          <SelectField
            label="Parent Space"
            value={spaceId}
            onChange={(e) => setSpaceId(e.target.value)}
          >
            {spaces.map((s) => (
              <option key={s.id} value={s.id}>
                {s.name}
              </option>
            ))}
          </SelectField>
        )}
      </form>
    </Dialog>
  );
}

export { NewGroupDialog as NewLabelDialog };
