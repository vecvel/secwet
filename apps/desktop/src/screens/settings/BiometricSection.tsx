import { useEffect, useState } from "react";
import { SelectControl } from "../../components/Field";
import { List, ListRow } from "../../components/List";
import { Notice } from "../../components/Notice";
import { Section } from "../../components/PageHeader";
import { Button } from "../../components/Button";
import { api, formatUiError, type BiometricStatus } from "../../lib/api";
import {
  biometricDetail,
  biometricFallback,
  biometricName,
  biometricPromptIsInApp,
  isBiometricCancel,
} from "../../lib/biometric";
import styles from "./BiometricSection.module.css";

/**
 * Settings > Security: turn biometric unlock on or off. Renders nothing when
 * the system has no usable biometric, so the default unlock stays as is,
 * unless it is still on: then it can be turned off here.
 */
export function BiometricSection() {
  const [status, setStatus] = useState<BiometricStatus | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    api.biometricStatus().then((s) => {
      if (alive) setStatus(s);
    });
    return () => {
      alive = false;
    };
  }, []);

  if (!status || (!status.available && !status.enabled)) return null;

  const name = biometricName(status.kind);
  const detail = biometricDetail(status.kind);
  const inApp = biometricPromptIsInApp(status.kind);
  const title = status.kind === "fingerprint" ? "Unlock with fingerprint" : `Unlock with ${name}`;

  async function change(enabled: boolean) {
    setSaving(true);
    setError(null);
    try {
      setStatus(await api.biometricSetEnabled(enabled));
    } catch (err) {
      if (!isBiometricCancel(err)) {
        setError(formatUiError(err, `Couldn't turn on ${name}.`));
      }
    } finally {
      setSaving(false);
    }
  }

  let meta = status.available
    ? `Ask for ${name}${detail ? ` (${detail})` : ""} before Secwet opens, including after it locks itself. ${biometricFallback(status.kind)}`
    : "This device can't check biometric unlock right now. Until it can, Secwet opens with your recovery key.";
  if (saving && inApp) meta = "Touch the fingerprint reader to confirm.";
  else if (saving) meta = `Confirm with ${name} to continue.`;

  return (
    <Section title="Biometric unlock">
      {error && (
        <Notice
          tone="warning"
          label="Not turned on"
          action={
            <Button variant="tertiary" arrow={false} onClick={() => setError(null)}>
              Dismiss
            </Button>
          }
        >
          {error}
        </Notice>
      )}
      <List>
        <ListRow
          title={title}
          meta={meta}
          trailing={
            saving && inApp ? (
              <Button variant="secondary" onClick={() => void api.biometricCancel()}>
                Cancel
              </Button>
            ) : (
              <div className={styles.select}>
                <SelectControl
                  aria-label={title}
                  value={status.enabled ? "enabled" : "disabled"}
                  disabled={saving}
                  onChange={(e) => void change(e.target.value === "enabled")}
                >
                  <option value="enabled">Required</option>
                  <option value="disabled">Disabled</option>
                </SelectControl>
              </div>
            )
          }
        />
      </List>
    </Section>
  );
}
