import { useCallback, useEffect, useRef, useState } from "react";
import { Button } from "./Button";
import { EmptyState } from "./EmptyState";
import { TextField } from "./Field";
import { BrandMark } from "./Icon";
import { Toast } from "./Toast";
import { api, formatUiError, isValidRecoveryKey, normalizeRecoveryKey, type BiometricStatus } from "../lib/api";
import { biometricName, biometricPromptIsInApp, isBiometricCancel } from "../lib/biometric";
import { WindowControls } from "./WindowControls";
import { onWindowDragMouseDown } from "../lib/windowDrag";
import styles from "./UnlockScreen.module.css";

interface UnlockScreenProps {
  /** `recoveryKey` stands in for biometric unlock while the device can't check it. */
  onUnlock: (recoveryKey?: string) => Promise<void> | void;
  deviceName?: string;
  onRestore?: () => void;
}

// The lock screen shown at launch asks for the biometric right away; later
// ones (after a manual or idle lock) wait for the user to come back to the
// window, so locking never opens a prompt by itself.
let promptedAtLaunch = false;
const LAUNCH_WINDOW_MS = 15_000;

export function UnlockScreen({ onUnlock, deviceName, onRestore }: UnlockScreenProps) {
  const [unlocking, setUnlocking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [biometric, setBiometric] = useState<BiometricStatus | null>(null);
  // Biometric unlock is on but the device can't check it: ask for the recovery key.
  const [keyNeeded, setKeyNeeded] = useState<string | null>(null);
  const [recoveryKey, setRecoveryKey] = useState("");
  const [keyError, setKeyError] = useState<string | null>(null);
  const busy = useRef(false);
  const unlockRef = useRef(onUnlock);
  unlockRef.current = onUnlock;

  const biometricOn = biometric?.enabled === true;
  const name = biometric ? biometricName(biometric.kind) : "";
  const inAppPrompt = biometricOn && biometric !== null && biometricPromptIsInApp(biometric.kind);

  const handleUnlock = useCallback(async (withKey?: string) => {
    if (busy.current) return;
    busy.current = true;
    try {
      setUnlocking(true);
      setError(null);
      setKeyError(null);
      // With biometric unlock on, the Rust side shows the OS prompt and only
      // opens the store after it passes.
      await unlockRef.current(withKey);
    } catch (err) {
      const code = (err as { code?: string } | null)?.code;
      if (code === "recovery_key_required") {
        setKeyNeeded(formatUiError(err, "Enter your recovery key to unlock."));
      } else if (code === "recovery_key_invalid") {
        setKeyError(formatUiError(err, "That recovery key doesn't match this Secwet."));
      } else if (!isBiometricCancel(err)) {
        setError(formatUiError(err, "Failed to unlock Secwet."));
      }
    } finally {
      busy.current = false;
      setUnlocking(false);
    }
  }, []);

  useEffect(() => {
    let alive = true;
    api.biometricStatus().then((s) => {
      if (alive) setBiometric(s);
    });
    return () => {
      alive = false;
    };
  }, []);

  // Prompt on launch, and again whenever the user comes back to the window.
  // Focus that returns when the system prompt closes is ignored, so
  // cancelling does not open the prompt again.
  useEffect(() => {
    if (!biometricOn) return;
    if (!promptedAtLaunch) {
      promptedAtLaunch = true;
      if (performance.now() < LAUNCH_WINDOW_MS && document.hasFocus()) void handleUnlock();
    }
    let leftWindow = false;
    const onBlur = () => {
      if (!busy.current) leftWindow = true;
    };
    const onFocus = () => {
      if (!leftWindow) return;
      leftWindow = false;
      void handleUnlock();
    };
    window.addEventListener("blur", onBlur);
    window.addEventListener("focus", onFocus);
    return () => {
      window.removeEventListener("blur", onBlur);
      window.removeEventListener("focus", onFocus);
    };
  }, [biometricOn, handleUnlock]);

  let body = deviceName
    ? `Secwet on ${deviceName} is locked. Unlock to access your encrypted secrets.`
    : "Idle timer expired. Unlock to access your encrypted secrets.";
  if (keyNeeded) body = keyNeeded;
  else if (unlocking && inAppPrompt) body = "Touch the fingerprint reader to unlock Secwet.";
  else if (unlocking && biometricOn) body = `Confirm with ${name} to unlock Secwet.`;
  const keyReady = isValidRecoveryKey(normalizeRecoveryKey(recoveryKey));

  const unlockLabel = biometricOn
    ? biometric?.kind === "fingerprint"
      ? "Unlock with fingerprint"
      : `Unlock with ${name}`
    : "Unlock";

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
        <WindowControls />
      </header>

      {error && (
        <div className={styles.toastContainer}>
          <Toast
            tone="warning"
            onDismiss={() => setError(null)}
          >
            {error}
          </Toast>
        </div>
      )}

      <div className={styles.content}>
        <EmptyState
          icon="lock"
          title="Secwet is locked"
          body={body}
          action={
            keyNeeded ? (
              <form
                className={styles.recovery}
                onSubmit={(e) => {
                  e.preventDefault();
                  if (keyReady) void handleUnlock(normalizeRecoveryKey(recoveryKey));
                }}
              >
                <TextField
                  label="Recovery key"
                  placeholder="XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
                  autoComplete="off"
                  spellCheck={false}
                  value={recoveryKey}
                  disabled={unlocking}
                  error={keyError}
                  onChange={(e) => {
                    setRecoveryKey(normalizeRecoveryKey(e.target.value));
                    if (keyError) setKeyError(null);
                  }}
                />
                <div className={styles.actions}>
                  <Button type="submit" variant="primary" disabled={unlocking || !keyReady}>
                    {unlocking ? "Unlocking…" : "Unlock with recovery key"}
                  </Button>
                  <Button
                    type="button"
                    variant="secondary"
                    disabled={unlocking}
                    onClick={() => {
                      setKeyNeeded(null);
                      setRecoveryKey("");
                      void handleUnlock();
                    }}
                  >
                    {unlockLabel}
                  </Button>
                </div>
              </form>
            ) : (
            <div className={styles.actions}>
              {unlocking && inAppPrompt ? (
                <Button variant="secondary" onClick={() => void api.biometricCancel()}>
                  Cancel
                </Button>
              ) : (
                <Button variant="primary" disabled={unlocking} onClick={() => void handleUnlock()}>
                  {unlocking ? "Unlocking…" : unlockLabel}
                </Button>
              )}
              {onRestore && (
                <Button variant="secondary" disabled={unlocking} onClick={onRestore}>
                  Restore from backup
                </Button>
              )}
            </div>
            )
          }
        />
      </div>
    </div>
  );
}
