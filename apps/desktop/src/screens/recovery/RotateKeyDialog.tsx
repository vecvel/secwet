import { Button } from "../../components/Button";
import { Dialog } from "../../components/Dialog";
import styles from "./RecoveryScreen.module.css";

export function RotateKeyDialog({ onCancel, onConfirm }: { onCancel: () => void; onConfirm: () => void }) {
  return (
    <Dialog
      title="Rotate vault key?"
      description="A new vault key is created on this device and shared only with your active devices."
      onClose={onCancel}
      footer={
        <>
          <Button variant="secondary" onClick={onCancel}>
            Cancel
          </Button>
          <Button variant="primary" onClick={onConfirm}>
            Rotate key
          </Button>
        </>
      }
    >
      <ul className={styles.limits}>
        <li>Revoked devices can't read anything changed after this.</li>
        <li>Active devices pick up the new key on their next sync.</li>
        <li>Your recovery key keeps working.</li>
      </ul>
    </Dialog>
  );
}
