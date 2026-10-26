import { Button } from "../../components/Button";
import { Dialog } from "../../components/Dialog";
import type { Device } from "../../data/mock";
import styles from "./RevokeDeviceDialog.module.css";

export function RevokeDeviceDialog({ device, onCancel, onConfirm }: { device: Device; onCancel: () => void; onConfirm: () => void }) {
  return (
    <Dialog
      title={`Revoke ${device.name}?`}
      description="It stops syncing right away and can't be approved again with the same key."
      onClose={onCancel}
      footer={
        <>
          <Button variant="secondary" onClick={onCancel}>
            Cancel
          </Button>
          <Button variant="danger" onClick={onConfirm}>
            Revoke device
          </Button>
        </>
      }
    >
      <ul className={styles.points}>
        <li>Secrets already copied to {device.name} stay on it. Revoking can't erase them remotely.</li>
        <li>Rotate the encryption key afterwards so it can't read changes made from now on.</li>
        <li>If the device was lost or stolen, also change the secrets it held at their source.</li>
      </ul>
    </Dialog>
  );
}
