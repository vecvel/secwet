import { useState } from "react";
import { Button } from "../../components/Button";
import { ChoiceCards, type Choice } from "../../components/ChoiceCards";
import { Dialog } from "../../components/Dialog";
import type { Device } from "../../data/mock";
import { formatUiError } from "../../lib/api";
import styles from "./RevokeDeviceDialog.module.css";

type RevokeMode = "wipe" | "keep";

interface Props {
  device: Device;
  onCancel: () => void;
  /** Revokes the device. `wipe` asks it to erase its keys and local data on next contact. */
  onConfirm: (wipe: boolean) => Promise<void> | void;
}

export function RevokeDeviceDialog({ device, onCancel, onConfirm }: Props) {
  const [mode, setMode] = useState<RevokeMode>("wipe");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // The device in use can never revoke itself (the relay answers cannot_revoke_self).
  if (device.current) return null;

  const options: Choice<RevokeMode>[] = [
    {
      value: "wipe",
      title: "Revoke and erase",
      hint: "Recommended if lost or stolen",
      description: `${device.name} deletes its keys and local data when it next connects. If it never connects again, it keeps what it has, so change the secrets it held at their source.`,
    },
    {
      value: "keep",
      title: "Revoke and keep a read-only copy",
      hint: "Recommended for a device you're retiring",
      description: `${device.name} stops syncing. What's already on it stays there, read-only, for anyone using it.`,
    },
  ];

  async function confirm() {
    setBusy(true);
    setError(null);
    try {
      await onConfirm(mode === "wipe");
    } catch (err) {
      setError(formatUiError(err, "Couldn't revoke this device. Try again."));
      setBusy(false);
    }
  }

  return (
    <Dialog
      title={`Revoke ${device.name}?`}
      description="It stops syncing right away. Rotate the encryption key afterwards so it can't read changes made from now on."
      onClose={onCancel}
      busy={busy}
      footer={
        <>
          <Button variant="secondary" onClick={onCancel} disabled={busy}>
            Cancel
          </Button>
          <Button variant="danger" onClick={confirm} disabled={busy}>
            {busy ? "Revoking…" : mode === "wipe" ? "Revoke and erase" : "Revoke and keep copy"}
          </Button>
        </>
      }
    >
      <ChoiceCards label="How to revoke" value={mode} options={options} onChange={setMode} disabled={busy} />
      {error && (
        <p className={styles.error} role="alert">
          {error}
        </p>
      )}
    </Dialog>
  );
}
