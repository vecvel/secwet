import { useState } from "react";
import { Button } from "./Button";
import { EmptyState } from "./EmptyState";
import { BrandMark } from "./Icon";
import { Notice } from "./Notice";
import { formatUiError } from "../lib/api";
import { onWindowDragMouseDown } from "../lib/windowDrag";
import styles from "./UnlockScreen.module.css";

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
      setError(formatUiError(err, "Failed to unlock Secwet."));
    } finally {
      setUnlocking(false);
    }
  }

  return (
    <div
      className={styles.screen}
      onMouseDown={onWindowDragMouseDown}
      data-tauri-drag-region
    >
      <header
        className={styles.header}
        onMouseDown={onWindowDragMouseDown}
        data-tauri-drag-region
      >
        <span className={styles.brand} aria-hidden="true">
          <BrandMark size={20} />
        </span>
      </header>

      <div className={styles.content}>
        {error && (
          <div className={styles.errorNotice}>
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
              ? `Secwet on ${deviceName} is locked. Unlock to access your encrypted secrets.`
              : "Idle timer expired. Unlock to access your encrypted secrets."
          }
          action={
            <Button variant="primary" disabled={unlocking} onClick={handleUnlock}>
              {unlocking ? "Unlocking…" : "Unlock"}
            </Button>
          }
        />
      </div>
    </div>
  );
}
