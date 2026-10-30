import { useEffect, useState } from "react";
import { Button, IconButton } from "../../components/Button";
import { Checkbox } from "../../components/Checkbox";
import { Dialog } from "../../components/Dialog";
import { Notice } from "../../components/Notice";
import { api, formatUiError, normalizeRecoveryKey } from "../../lib/api";
import styles from "./CreateRecoveryKeyDialog.module.css";

interface CreateRecoveryKeyDialogProps {
  replacing: boolean;
  onCancel: () => void;
  onDone: () => void;
}

export function CreateRecoveryKeyDialog({
  replacing,
  onCancel,
  onDone,
}: CreateRecoveryKeyDialogProps) {
  const [loading, setLoading] = useState(true);
  const [key, setKey] = useState<string>("");
  const [error, setError] = useState<string | null>(null);
  const [stored, setStored] = useState(false);
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");

  useEffect(() => {
    let active = true;
    async function deriveKey() {
      try {
        setLoading(true);
        setError(null);
        const derived = replacing
          ? await api.recoveryKeyReplace()
          : await api.recoveryKeyCreate();
        if (active) {
          const formatted = normalizeRecoveryKey(derived) || derived;
          setKey(formatted);
        }
      } catch (err: unknown) {
        if (active) {
          setError(formatUiError(err, "Failed to derive recovery key from engine."));
        }
      } finally {
        if (active) {
          setLoading(false);
        }
      }
    }

    deriveKey();
    return () => {
      active = false;
    };
  }, [replacing]);

  async function copy() {
    if (!key) return;
    try {
      await api.clipboardCopyText(key);
      setCopyState("copied");
      setTimeout(() => setCopyState("idle"), 2000);
    } catch {
      setCopyState("failed");
    }
  }

  return (
    <Dialog
      title={replacing ? "Replace recovery key" : "Create recovery key"}
      description="Store this somewhere safe, away from this device: a password manager or on paper. Secwet can't show it again."
      onClose={onCancel}
      footer={
        <>
          <Button variant="secondary" onClick={onCancel}>
            Cancel
          </Button>
          <Button
            variant="primary"
            onClick={onDone}
            disabled={!stored || loading || !key}
          >
            {replacing ? "Replace key" : "Done"}
          </Button>
        </>
      }
    >
      {error && (
        <Notice tone="warning" label="Derivation error">
          {error}
        </Notice>
      )}

      {loading ? (
        <div className={styles.loadingBox}>
          <span className={styles.loadingText}>Deriving recovery key from Secwet engine…</span>
        </div>
      ) : key ? (
        <div className={styles.keyBox}>
          <span className={styles.key}>{key}</span>
          <IconButton
            icon={copyState === "copied" ? "check" : "copy"}
            label={copyState === "copied" ? "Copied" : "Copy recovery key"}
            onClick={copy}
          />
        </div>
      ) : null}

      {copyState === "failed" && (
        <p className={styles.hint}>Copy isn't available here. Select the key and copy it manually.</p>
      )}

      {replacing && (
        <p className={styles.hint}>
          Your old recovery key stops working as soon as you replace it. Existing exports still need the old key.
        </p>
      )}

      <Checkbox
        label="I have stored my recovery key"
        checked={stored}
        disabled={loading || !key}
        onChange={(e) => setStored(e.target.checked)}
      />
    </Dialog>
  );
}
