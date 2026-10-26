import { useState, type FormEvent } from "react";
import { Button } from "../../components/Button";
import { Dialog } from "../../components/Dialog";
import { TextField } from "../../components/Field";
import type { ItemView } from "../../lib/api";

interface Props {
  item: ItemView;
  onCancel: () => void;
  onSave: (name: string, description?: string) => Promise<void> | void;
}

export function EditItemDialog({ item, onCancel, onSave }: Props) {
  const [name, setName] = useState(item.name);
  const [description, setDescription] = useState(item.description ?? "");
  const [error, setError] = useState<string>();
  const [saving, setSaving] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    const trimmed = name.trim();
    if (!trimmed) {
      setError("Enter a name.");
      return;
    }
    setSaving(true);
    try {
      await onSave(trimmed, description.trim() || undefined);
    } finally {
      setSaving(false);
    }
  }

  return (
    <Dialog
      title="Rename"
      description="Update details for this entry."
      onClose={onCancel}
      footer={
        <>
          <Button variant="secondary" onClick={onCancel} disabled={saving}>
            Cancel
          </Button>
          <Button variant="primary" type="submit" form="edit-item-dialog" disabled={saving}>
            {saving ? "Saving" : "Save"}
          </Button>
        </>
      }
    >
      <form id="edit-item-dialog" onSubmit={submit} noValidate className="form-contents">
        <TextField
          label="Name"
          name="name"
          placeholder="e.g. Payments API, Client App"
          value={name}
          error={error}
          autoComplete="off"
          spellCheck={false}
          autoFocus
          onChange={(e) => {
            setName(e.target.value);
            if (error) setError(undefined);
          }}
        />
        <TextField
          label="Description (optional)"
          name="description"
          placeholder="Brief summary or purpose"
          value={description}
          autoComplete="off"
          onChange={(e) => setDescription(e.target.value)}
        />
      </form>
    </Dialog>
  );
}
