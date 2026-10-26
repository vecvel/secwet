import { useEffect, useState } from "react";
import { Badge } from "../../components/Badge";
import { Button } from "../../components/Button";
import { Dialog } from "../../components/Dialog";
import { QrCode } from "../../components/QrCode";
import { mockNewDevice, type Device } from "../../data/mock";
import { formatCountdown, randomToken } from "../../lib/format";
import styles from "./PairDeviceDialog.module.css";

const LIFETIME_MS = 5 * 60_000;
/** Mock only: how long until the simulated new device scans the code. */
const MOCK_SCAN_DELAY_MS = 3_000;

type Phase = "waiting" | "found" | "expired";

function newSession() {
  const digits = crypto.getRandomValues(new Uint32Array(1))[0] % 1_000_000;
  return {
    // One-time session id and ephemeral public key. No encryption key, no reusable credential.
    payload: `secwet://pair?v=1&s=${randomToken(12)}&k=${randomToken(32)}`,
    code: String(digits).padStart(6, "0").replace(/(\d{3})(\d{3})/, "$1 $2"),
    expiresAt: Date.now() + LIFETIME_MS,
  };
}

/** Pairing option A: this device shows the code, the new device scans it, both show a code to compare. */
export function PairDeviceDialog({ onCancel, onApprove }: { onCancel: () => void; onApprove: (d: Device) => void }) {
  const [session, setSession] = useState(newSession);
  const [phase, setPhase] = useState<Phase>("waiting");
  const [now, setNow] = useState(Date.now());

  useEffect(() => {
    const tick = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(tick);
  }, []);

  useEffect(() => {
    if (phase !== "waiting") return;
    const t = setTimeout(() => setPhase("found"), MOCK_SCAN_DELAY_MS);
    return () => clearTimeout(t);
  }, [phase, session]);

  const remaining = session.expiresAt - now;
  useEffect(() => {
    if (remaining <= 0 && phase !== "expired") setPhase("expired");
  }, [remaining, phase]);

  function restart() {
    setSession(newSession());
    setNow(Date.now());
    setPhase("waiting");
  }

  function approve() {
    onApprove({ id: crypto.randomUUID(), ...mockNewDevice, addedAt: Date.now() });
  }

  return (
    <Dialog
      title="Pair a device"
      description="Open Secwet on the new device, choose Join, and scan this code."
      onClose={onCancel}
      footer={
        <>
          <Button variant="secondary" onClick={onCancel}>
            Cancel
          </Button>
          {phase === "expired" ? (
            <Button variant="primary" onClick={restart}>
              Show a new code
            </Button>
          ) : (
            <Button variant="primary" onClick={approve} disabled={phase !== "found"}>
              Codes match, approve
            </Button>
          )}
        </>
      }
    >
      <div className={styles.scan}>
        <div className={phase === "expired" ? styles.expiredQr : undefined}>
          <QrCode value={session.payload} label="Pairing QR code for a new device" />
        </div>
        <div className={styles.scanText}>
          <span className={styles.status}>
            {phase === "waiting" && <Badge tone="accent">Waiting for the new device</Badge>}
            {phase === "found" && <Badge tone="success">New device found</Badge>}
            {phase === "expired" && <Badge tone="warning">Code expired</Badge>}
          </span>
          <p className={styles.help}>
            {phase === "expired"
              ? "This code can no longer be used. Show a new one to keep pairing."
              : `This code works once and expires in ${formatCountdown(remaining)}. It holds no encryption key.`}
          </p>
        </div>
      </div>

      <div className={styles.compare} aria-live="polite">
        {phase === "found" ? (
          <>
            <span className={styles.compareLabel}>
              {mockNewDevice.name} ({mockNewDevice.platform}) wants to join. Check it shows this code:
            </span>
            <span className={styles.code}>{session.code}</span>
            <span className={styles.compareLabel}>Device key {mockNewDevice.fingerprint}</span>
          </>
        ) : (
          <span className={styles.compareLabel}>A matching code appears on both devices once the new device scans.</span>
        )}
      </div>
    </Dialog>
  );
}
