import { useState, type FormEvent } from "react";
import { Button } from "../../components/Button";
import { Dialog } from "../../components/Dialog";
import { SelectField, TextField } from "../../components/Field";
import type { ItemView } from "../../lib/api";

export interface GroupOption {
  id: string;
  name: string;
}

interface Props {
  existingItems: ItemView[];
  groups?: GroupOption[];
  initialGroupId?: string;
  groupName?: string;
  labelName?: string;
  onCancel: () => void;
  onCreate: (name: string, description?: string, targetGroupId?: string) => void;
}

/**
 * Dialog for creating an item under a group.
 * Allows selecting the target group when groups are provided.
 * Authoritative Rule: Asks ONLY for basic info (group, name, description).
 * Does NOT display an Environments field, does NOT require environments,
 * and does NOT create default environments.
 */
export function NewItemDialog({
  existingItems,
  groups,
  initialGroupId,
  groupName,
  labelName,
  onCancel,
  onCreate,
}: Props) {
  const [selectedGroupId, setSelectedGroupId] = useState<string>(() => {
    if (initialGroupId && groups?.some((g) => g.id === initialGroupId)) {
      return initialGroupId;
    }
    return groups?.[0]?.id || "";
  });

  const activeGroup = groups?.find((g) => g.id === selectedGroupId);
  const currentGroupName = activeGroup?.name || groupName || labelName || "this group";

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

    const itemsToCheck = selectedGroupId
      ? existingItems.filter((it) => (it.group_id ?? it.label_id) === selectedGroupId)
      : existingItems;

    if (
      itemsToCheck.some(
        (it) => it.name.trim().toLowerCase() === trimmed.toLowerCase()
      )
    ) {
      setError(`An entry called "${trimmed}" already exists under ${currentGroupName}.`);
      return;
    }
    onCreate(trimmed, description.trim() || undefined, selectedGroupId || undefined);
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
        {groups && groups.length > 0 && (
          <SelectField
            label="Group"
            name="groupId"
            value={selectedGroupId}
            onChange={(e) => {
              setSelectedGroupId(e.target.value);
              if (error) setError(undefined);
            }}
          >
            {groups.map((g) => (
              <option key={g.id} value={g.id}>
                {g.name}
              </option>
            ))}
          </SelectField>
        )}
        <TextField
          label="Name"
          name="name"
          placeholder="e.g. Payments API, Client App, Credentials"
          value={name}
          error={error}
          autoComplete="off"
          spellCheck={false}
          autoFocus={!groups || groups.length <= 1}
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
