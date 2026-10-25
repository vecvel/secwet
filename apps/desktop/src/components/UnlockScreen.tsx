import { useState } from "react";
import { Button } from "./Button";
import { EmptyState } from "./EmptyState";
import { Notice } from "./Notice";
import { formatUiError } from "../lib/api";

interface UnlockScreenProps {
  onUnlock: () => Promise<void> | void;
  deviceName?: string;
}

export function UnlockScreen({ onUnlock, deviceName }: UnlockScreenProps) {
  const [unlocking, setUnlocking] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleUnlock() {
    try {
      setUnlocking(true);
      setError(null);
      await onUnlock();
    } catch (err) {
      setError(formatUiError(err, "Failed to unlock vault."));
    } finally {
      setUnlocking(false);
    }
  }

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        height: "100%",
        width: "100%",
        padding: "2rem",
      }}
    >
      {error && (
        <div style={{ marginBottom: "1.5rem", maxWidth: 400, width: "100%" }}>
          <Notice tone="warning" label="Unlock error">
            {error}
          </Notice>
        </div>
      )}
      <EmptyState
        icon="lock"
        title="Secwet is locked"
        body={
          deviceName
            ? `Your vault on ${deviceName} is locked. Unlock to access your encrypted secrets.`
            : "Idle timer expired. Unlock to access your encrypted secrets."
        }
        action={
          <Button variant="primary" disabled={unlocking} onClick={handleUnlock}>
            {unlocking ? "Unlocking…" : "Unlock"}
          </Button>
        }
      />
    </div>
  );
}
