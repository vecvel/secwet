import { useState } from "react";
import { Button } from "../../components/Button";
import { Dialog } from "../../components/Dialog";
import { Notice } from "../../components/Notice";
import { api, formatUiError, type KeyRotationReport } from "../../lib/api";
import { plural } from "../../lib/format";
import styles from "./RotateKeyDialog.module.css";

interface Props {
  onCancel: () => void;
  /** Called after a successful rotation, when the user closes the result. */
  onDone?: (report: KeyRotationReport) => void;
  /** Deprecated: called like onDone without the report. */
  onConfirm?: () => void;
  /** Overrides the IPC call, for tests and previews. */
  rotate?: () => Promise<KeyRotationReport>;
}

export function RotateKeyDialog({ onCancel, onDone, onConfirm, rotate = api.keyRotate }: Props) {
  const [running, setRunning] = useState(false);
  const [report, setReport] = useState<KeyRotationReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function run() {
    setRunning(true);
    setError(null);
    try {
      setReport(await rotate());
    } catch (err) {
      setError(formatUiError(err, "Couldn't rotate the key. Try again."));
    } finally {
      setRunning(false);
    }
  }

  function finish() {
    if (report) {
      onDone?.(report);
      onConfirm?.();
    }
    onCancel();
  }

  if (report) {
    return (
      <Dialog
        title="Key rotated"
        description="Your active devices pick up the new key on their next sync."
        onClose={finish}
        footer={
          <Button variant="primary" onClick={finish}>
            Done
          </Button>
        }
      >
        <Notice tone="success" label="Done">
          Now on key version {report.epoch}. Re-encrypted {plural(report.resealed, "item")} on this device.
        </Notice>
        {report.adopted_from_conflict && (
          <p className={styles.note}>Another device rotated first; this device switched to its key.</p>
        )}
      </Dialog>
    );
  }

  return (
    <Dialog
      title="Rotate encryption key?"
      description="A new encryption key is created on this device and shared only with your active devices."
      onClose={onCancel}
      busy={running}
      footer={
        <>
          <Button variant="secondary" onClick={onCancel} disabled={running}>
            Cancel
          </Button>
          <Button variant="primary" onClick={run} disabled={running}>
            {running ? "Rotating…" : "Rotate key"}
          </Button>
        </>
      }
    >
      <ul className={styles.limits}>
        <li>Revoked devices can't read anything changed after this.</li>
        <li>Your recovery key keeps working.</li>
      </ul>
      {running && (
        <p className={styles.note} role="status">
          Re-encrypting this device's data. Keep Secwet open.
        </p>
      )}
      {error && (
        <p className={styles.error} role="alert">
          {error}
        </p>
      )}
    </Dialog>
  );
}
