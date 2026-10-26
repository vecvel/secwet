import { useState, type FormEvent } from "react";
import { Button } from "../../components/Button";
import { Dialog } from "../../components/Dialog";
import { TextField } from "../../components/Field";
import type { ItemView } from "../../lib/api";

interface Props {
  existingItems: ItemView[];
  groupName?: string;
  labelName?: string;
  onCancel: () => void;
  onCreate: (name: string, description?: string) => void;
}

/**
 * Dialog for creating an item under a group.
 * Authoritative Rule: Asks ONLY for basic info (name, description).
 * Does NOT display an Environments field, does NOT require environments,
 * and does NOT create default environments.
 */
export function NewItemDialog({ existingItems, groupName, labelName, onCancel, onCreate }: Props) {
  const currentGroupName = groupName || labelName || "this group";
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [error, setError] = useState<string>();

  function submit(e: FormEvent) {
    e.preventDefault();
    const trimmed = name.trim();
    if (!trimmed) {
      setError("Enter a name.");
      return;
    }
    if (
      existingItems.some(
        (it) => it.name.trim().toLowerCase() === trimmed.toLowerCase()
      )
    ) {
      setError(`An entry called "${trimmed}" already exists under ${currentGroupName}.`);
      return;
    }
    onCreate(trimmed, description.trim() || undefined);
  }

  return (
    <Dialog
      title="New"
      description={`Add an entry to ${currentGroupName}.`}
      onClose={onCancel}
      footer={
        <>
          <Button variant="secondary" onClick={onCancel}>
            Cancel
          </Button>
          <Button variant="primary" type="submit" form="new-item-dialog">
            Create
          </Button>
        </>
      }
    >
      <form id="new-item-dialog" onSubmit={submit} noValidate className="form-contents">
        <TextField
          label="Name"
          name="name"
          placeholder="e.g. Payments API, Client App, Credentials"
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
