import { useState, type FormEvent } from "react";
import { Button } from "../../components/Button";
import { Dialog } from "../../components/Dialog";
import { TextField } from "../../components/Field";
import { Icon, type IconName } from "../../components/Icon";
import styles from "./NewSpaceDialog.module.css";

interface Props {
  onCancel: () => void;
  onCreate: (name: string, icon?: string) => Promise<void> | void;
}

const AVAILABLE_ICONS: Array<{ name: IconName; label: string }> = [
  { name: "briefcase", label: "Work" },
  { name: "user", label: "Personal" },
  { name: "folder", label: "Folder" },
  { name: "globe", label: "Global" },
  { name: "layers", label: "Layers" },
  { name: "key", label: "Security" },
];

export function NewSpaceDialog({ onCancel, onCreate }: Props) {
  const [name, setName] = useState("");
  const [selectedIcon, setSelectedIcon] = useState<IconName>("briefcase");
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
      await onCreate(trimmed, selectedIcon);
    } catch (err: any) {
      setError(err?.message || "Failed to create space");
      setBusy(false);
    }
  }

  return (
    <Dialog
      title="New Space"
      description="Create a top-level workspace container to organize your groups, projects, and secrets."
      onClose={onCancel}
      footer={
        <>
          <Button variant="secondary" onClick={onCancel} disabled={busy}>
            Cancel
          </Button>
          <Button variant="primary" onClick={handleSubmit} disabled={busy || !name.trim()}>
            {busy ? "Creating..." : "Create Space"}
          </Button>
        </>
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
