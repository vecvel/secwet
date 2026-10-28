import { useEffect, useState } from "react";
import { Badge } from "../../components/Badge";
import { Button } from "../../components/Button";
import { Dialog } from "../../components/Dialog";
import { QrCode } from "../../components/QrCode";
import type { Device } from "../../data/mock";
import { formatCountdown } from "../../lib/format";
import { api, type PairingSessionInfo } from "../../lib/api";
import styles from "./PairDeviceDialog.module.css";

type Phase = "waiting" | "found" | "expired";

interface FoundPeer {
  name: string;
  platform: string;
  fingerprint: string;
  code: string;
  device_id: string;
}

/** Pairing option A: this device shows the code, the new device scans it, both show a code to compare. */
export function PairDeviceDialog({
  onCancel,
  onApprove,
}: {
  onCancel: () => void;
  onApprove: (d: Device) => void;
}) {
  const [session, setSession] = useState<PairingSessionInfo | null>(null);
  const [peer, setPeer] = useState<FoundPeer | null>(null);
  const [phase, setPhase] = useState<Phase>("waiting");
  const [expiresAtMs, setExpiresAtMs] = useState(Date.now() + 5 * 60_000);
  const [now, setNow] = useState(Date.now());
  const [approving, setApproving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // 1. Start pairing session on mount
  useEffect(() => {
    let cancelled = false;

    async function initPairing() {
      try {
        setError(null);
        const s = await api.pairingStart();
        if (cancelled) return;
        setSession(s);
        const exp = new Date(s.expires_at).getTime() || Date.now() + 5 * 60_000;
        setExpiresAtMs(exp);
        setPhase("waiting");
        setPeer(null);
      } catch (err: any) {
        if (cancelled) return;
        setError(err?.message || "Failed to start pairing session.");
      }
    }

    initPairing();

    return () => {
      cancelled = true;
      api.pairingCancel().catch(() => {});
    };
  }, []);

  // 2. Countdown timer
  useEffect(() => {
    const tick = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(tick);
  }, []);

  const remaining = Math.max(0, expiresAtMs - now);

  useEffect(() => {
    if (remaining <= 0 && phase !== "expired") {
      setPhase("expired");
    }
  }, [remaining, phase]);

  // 3. Poll for peer join while waiting
  useEffect(() => {
    if (phase !== "waiting" || !session) return;

    let active = true;
    const pollInterval = setInterval(async () => {
      try {
        const pollResp = await api.pairingPoll();
        if (!active) return;

        if (pollResp.status === "found") {
          setPeer(pollResp);
          setPhase("found");
        } else if (pollResp.status === "expired") {
          setPhase("expired");
        }
      } catch {
        // Continue polling
      }
    }, 1500);

    return () => {
      active = false;
      clearInterval(pollInterval);
    };
  }, [phase, session]);

  async function restart() {
    try {
      setError(null);
      setPhase("waiting");
      setPeer(null);
      const s = await api.pairingStart();
      setSession(s);
      const exp = new Date(s.expires_at).getTime() || Date.now() + 5 * 60_000;
      setExpiresAtMs(exp);
    } catch (err: any) {
      setError(err?.message || "Failed to start new pairing session.");
    }
  }

  async function approve() {
    try {
      setApproving(true);
      setError(null);
      const devDto = await api.pairingApprove();
      onApprove({
        id: devDto.id,
        name: devDto.name,
        platform: devDto.platform,
        fingerprint: devDto.fingerprint,
        addedAt: devDto.added_at,
        lastSyncAt: devDto.last_seen_at ?? devDto.last_sync_at,
        current: devDto.is_current ?? devDto.current,
      });
    } catch (err: any) {
      setError(err?.message || "Failed to approve device.");
    } finally {
      setApproving(false);
    }
  }

  return (
    <Dialog
      title="Pair a device"
      description="Open Secwet on the new device, choose Join, and scan this code."
      onClose={onCancel}
      footer={
        <>
          <Button variant="secondary" onClick={onCancel} disabled={approving}>
            Cancel
          </Button>
          {phase === "expired" ? (
            <Button variant="primary" onClick={restart}>
              Show a new code
            </Button>
          ) : (
            <Button
              variant="primary"
              onClick={approve}
              disabled={phase !== "found" || approving}
            >
              {approving ? "Approving…" : "Codes match, approve"}
            </Button>
          )}
        </>
      }
    >
      {error && (
        <div style={{ marginBottom: "var(--space-3)", color: "var(--color-danger)", fontSize: "var(--font-size-sm)" }}>
          {error}
        </div>
      )}

      <div className={styles.scan}>
        <div className={phase === "expired" ? styles.expiredQr : undefined}>
          <QrCode
            value={session?.qr_payload || "secwet://pair?v=1"}
            label="Pairing QR code for a new device"
          />
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
        {phase === "found" && peer ? (
          <>
            <span className={styles.compareLabel}>
              {peer.name} ({peer.platform}) wants to join. Check it shows this code:
            </span>
            <span className={styles.code}>{peer.code}</span>
            <span className={styles.compareLabel}>Device key {peer.fingerprint}</span>
          </>
        ) : (
          <span className={styles.compareLabel}>
            A matching code appears on both devices once the new device scans.
          </span>
        )}
      </div>
    </Dialog>
  );
}
