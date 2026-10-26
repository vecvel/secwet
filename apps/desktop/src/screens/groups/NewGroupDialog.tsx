import { useState, type FormEvent } from "react";
import { Button } from "../../components/Button";
import { Dialog } from "../../components/Dialog";
import { TextField } from "../../components/Field";

interface Props {
  onCancel: () => void;
  onCreate: (name: string, icon?: string) => Promise<void> | void;
}

export function NewGroupDialog({ onCancel, onCreate }: Props) {
  const [name, setName] = useState("");
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
      await onCreate(trimmed, "folder");
    } catch (err: any) {
      setError(err?.message || "Failed to create");
      setBusy(false);
    }
  }

  return (
    <Dialog
      title="New"
      description="Create a section to organize your projects, credentials, and services."
      onClose={onCancel}
      footer={
        <>
          <Button variant="secondary" onClick={onCancel} disabled={busy}>
            Cancel
          </Button>
          <Button variant="primary" onClick={handleSubmit} disabled={busy || !name.trim()}>
            {busy ? "Creating..." : "Create"}
          </Button>
        </>
      }
    >
      <form onSubmit={handleSubmit}>
        <TextField
          label="Name"
          value={name}
          onChange={(e) => {
            setName(e.target.value);
            if (error) setError(undefined);
          }}
          placeholder="e.g. Projects, Passwords, Personal, Work"
          error={error}
          autoFocus
        />
      </form>
    </Dialog>
  );
}

export { NewGroupDialog as NewLabelDialog };
