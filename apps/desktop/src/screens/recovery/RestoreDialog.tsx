import { useRef, useState } from "react";
import { Button } from "../../components/Button";
import { Dialog } from "../../components/Dialog";
import { TextField } from "../../components/Field";
import { Notice } from "../../components/Notice";
import { formatUiError, isTauri, isValidRecoveryKey, normalizeRecoveryKey } from "../../lib/api";
import { useStore } from "../../lib/store";
import styles from "./RestoreDialog.module.css";

interface RestoreDialogProps {
  onClose: () => void;
  onRestored: () => void;
  defaultDeviceName?: string;
}

export function RestoreDialog({
  onClose,
  onRestored,
  defaultDeviceName = "Desktop",
}: RestoreDialogProps) {
  const [, store] = useStore();
  const [filePath, setFilePath] = useState("");
  const [recoveryKey, setRecoveryKey] = useState("");
  const [deviceName, setDeviceName] = useState(defaultDeviceName);
  const [restoring, setRestoring] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const normalizedKey = normalizeRecoveryKey(recoveryKey);
  const isKeyValid = isValidRecoveryKey(normalizedKey);
  const canSubmit = Boolean(filePath.trim()) && isKeyValid && Boolean(deviceName.trim()) && !restoring;

  async function handlePickFile() {
    try {
      if (isTauri()) {
        const { open } = await import("@tauri-apps/plugin-dialog");
        const selected = await open({
          multiple: false,
          filters: [{ name: "Secwet Archive", extensions: ["secwet"] }],
        });
        if (selected && typeof selected === "string") {
          setFilePath(selected);
          if (error) setError(null);
        }
      } else {
        fileInputRef.current?.click();
      }
    } catch (err: unknown) {
      setError(formatUiError(err, "Failed to open file picker."));
    }
  }

  function handleFileInputChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (file) {
      setFilePath(file.name);
      if (error) setError(null);
    }
  }

  async function handleRestore() {
    if (!canSubmit) return;
    try {
      setRestoring(true);
      setError(null);
      await store.restoreWorkspace(filePath, normalizedKey, deviceName.trim());
      onRestored();
      onClose();
    } catch (err: unknown) {
      setError(formatUiError(err, "Failed to restore workspace. Verify your recovery key and archive file."));
    } finally {
      setRestoring(false);
    }
  }

  return (
    <Dialog
      title="Restore from backup"
      description="Restore your complete workspace state from an encrypted .secwet backup archive."
      onClose={onClose}
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={restoring}>
            Cancel
          </Button>
          <Button
            variant="primary"
            onClick={handleRestore}
            disabled={!canSubmit}
          >
            {restoring ? "Restoring…" : "Restore Workspace"}
          </Button>
        </>
      }
    >
      <div className={styles.body}>
        {error && (
          <Notice tone="warning" label="Restore error">
            {error}
          </Notice>
        )}

        <div className={styles.fileSection}>
          <span className={styles.fileLabel}>Backup archive</span>
          <div className={styles.fileRow}>
            <div className={styles.fileBox}>
              {filePath ? (
                <span>{filePath}</span>
              ) : (
                <span className={styles.filePlaceholder}>No .secwet file selected</span>
              )}
            </div>
            <Button variant="secondary" onClick={handlePickFile} disabled={restoring}>
              Choose file…
            </Button>
            <input
              ref={fileInputRef}
              type="file"
              accept=".secwet"
              style={{ display: "none" }}
              onChange={handleFileInputChange}
            />
          </div>
          <p className={styles.fileHelp}>Select an encrypted .secwet export envelope</p>
        </div>

        <TextField
          label="Recovery key"
          help="25 Crockford Base32 characters (e.g. XXXXX-XXXXX-XXXXX-XXXXX-XXXXX)"
          placeholder="XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
          value={recoveryKey}
          disabled={restoring}
          onChange={(e) => {
            const next = normalizeRecoveryKey(e.target.value);
            setRecoveryKey(next);
            if (error) setError(null);
          }}
        />

        <TextField
          label="Device name"
          help="Device name to identify this device in the restored workspace"
          placeholder="e.g. MacBook Pro"
          value={deviceName}
          disabled={restoring}
          onChange={(e) => {
            setDeviceName(e.target.value);
            if (error) setError(null);
          }}
        />
      </div>
    </Dialog>
  );
}
