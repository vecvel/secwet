import { useState, type FormEvent } from "react";
import { Button } from "../../components/Button";
import { Dialog } from "../../components/Dialog";
import { TextField } from "../../components/Field";
import { Icon, type IconName } from "../../components/Icon";
import type { SpaceView } from "../../lib/api";
import styles from "./NewSpaceDialog.module.css";

interface Props {
  space: SpaceView;
  onCancel: () => void;
  onSave: (name: string, icon?: string) => Promise<void> | void;
  onDelete?: () => void;
}

const AVAILABLE_ICONS: Array<{ name: IconName; label: string }> = [
  { name: "briefcase", label: "Work" },
  { name: "user", label: "Personal" },
  { name: "folder", label: "Folder" },
  { name: "globe", label: "Global" },
  { name: "layers", label: "Layers" },
  { name: "key", label: "Security" },
];

export function EditSpaceDialog({ space, onCancel, onSave, onDelete }: Props) {
  const [name, setName] = useState(space.name);
  const initialIcon = (space.icon as IconName) || (space.is_default ? "user" : "briefcase");
  const [selectedIcon, setSelectedIcon] = useState<IconName>(initialIcon);
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    const trimmed = name.trim();
    if (!trimmed) {
      setError("Space name cannot be empty");
      return;
    }
    if (trimmed.length > 64) {
      setError("Space name cannot exceed 64 characters");
      return;
    }
    setBusy(true);
    try {
      await onSave(trimmed, selectedIcon);
    } catch (err: any) {
      setError(err?.message || "Failed to save space");
      setBusy(false);
    }
  }

  return (
    <Dialog
      title="Edit Space"
      description="Update space name and icon."
      onClose={onCancel}
      footer={
        <div style={{ display: "flex", justifyContent: "space-between", width: "100%", alignItems: "center" }}>
          <div>
            {!space.is_default && onDelete && (
              <Button
                variant="danger"
                onClick={() => {
                  onCancel();
                  onDelete();
                }}
                disabled={busy}
              >
                Delete Space
              </Button>
            )}
          </div>
          <div style={{ display: "flex", gap: "var(--space-2)" }}>
            <Button variant="secondary" onClick={onCancel} disabled={busy}>
              Cancel
            </Button>
            <Button variant="primary" onClick={handleSubmit} disabled={busy || !name.trim()}>
              {busy ? "Saving..." : "Save Changes"}
            </Button>
          </div>
        </div>
      }
    >
      <form onSubmit={handleSubmit} className={styles.form}>
        <TextField
          label="Space Name"
          value={name}
          onChange={(e) => {
            setName(e.target.value);
            if (error) setError(undefined);
          }}
          placeholder="e.g. Work, Freelance, Family, Startup"
          error={error}
          autoFocus
        />

        <div className={styles.iconSection}>
          <label className={styles.iconLabel}>
            Icon
          </label>
          <div className={styles.iconGrid}>
            {AVAILABLE_ICONS.map((ic) => (
              <button
                key={ic.name}
                type="button"
                title={ic.label}
                onClick={() => setSelectedIcon(ic.name)}
                className={[
                  styles.iconBtn,
                  selectedIcon === ic.name && styles.iconBtnSelected,
                ]
                  .filter(Boolean)
                  .join(" ")}
              >
                <Icon name={ic.name} size={18} />
              </button>
            ))}
          </div>
        </div>
      </form>
    </Dialog>
  );
}

