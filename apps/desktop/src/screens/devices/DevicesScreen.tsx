import { useState } from "react";
import { Badge } from "../../components/Badge";
import { Button } from "../../components/Button";
import { List, ListRow } from "../../components/List";
import { Notice } from "../../components/Notice";
import { PageHeader } from "../../components/PageHeader";
import type { Device, Plan } from "../../data/mock";
import { planEndDate } from "../../lib/access";
import { formatAgo, formatDate } from "../../lib/format";
import { usePlanStatus } from "../../lib/usePlan";
import { PlanDialog } from "../PlanDialog";
import { PairDeviceDialog } from "./PairDeviceDialog";
import { RevokeDeviceDialog } from "./RevokeDeviceDialog";
import styles from "./DevicesScreen.module.css";

interface Props {
  devices: Device[];
  plan: Plan;
  /** Name of the last revoked device until the encryption key is rotated. */
  pendingRotation?: string;
  onPair: (device: Device) => void;
  onRevoke: (id: string, wipe: boolean) => void;
  onOpenRecovery: () => void;
}

function deviceMeta(d: Device, paused: boolean) {
  if (d.revokedAt) return `${d.platform}, revoked ${formatDate(d.revokedAt)}.`;
  if (d.current) return `${d.platform}, added ${formatDate(d.addedAt)}, key ${d.fingerprint}`;
  const sync = d.lastSyncAt ? `last synced ${formatAgo(d.lastSyncAt)}` : "active";
  return `${d.platform}, ${paused ? `sync paused, ${sync}` : sync}, key ${d.fingerprint}`;
}

export function DevicesScreen({ devices, plan, pendingRotation, onPair, onRevoke, onOpenRecovery }: Props) {
  const [pairing, setPairing] = useState(false);
  const [revoking, setRevoking] = useState<Device | null>(null);
  const status = usePlanStatus();
  // When Pro ends, the other devices stop syncing; everything stays on each device.
  const paused = status?.plan === "paused";
  const end = planEndDate(status?.expires_at);

  const active = devices.filter((d) => !d.revokedAt);
  const revoked = devices.filter((d) => d.revokedAt);
  const limit = status && status.plan !== "free" ? status.device_limit : 1;

  return (
    <div className={styles.screen}>
      <PageHeader
        title="Devices"
        subtitle="Devices that can access Secwet. Each one has its own key, and you approve every new device from one you already trust."
        action={
          <Button variant="primary" icon="plus" onClick={() => setPairing(true)}>
            Pair a device
          </Button>
        }
      />

      {paused && (
        <Notice tone="warning" label="Sync paused">
          Pro ended{end ? ` on ${end}` : ""}, so devices stop syncing. Everything on each device stays available and
          exportable. Renew Pro to sync again.
        </Notice>
      )}

      {pendingRotation && (
        <Notice tone="warning" label="Rotate key" action={<Button variant="tertiary" onClick={onOpenRecovery}>Rotate encryption key</Button>}>
          {pendingRotation} was revoked. Rotate the encryption key so it can't read changes made from now on.
        </Notice>
      )}

      <List label={`Active devices, ${active.length} of ${limit}`}>
        {active.map((d) => (
          <ListRow
            key={d.id}
            title={
              <>
                {d.name}
                {d.current && <Badge>This device</Badge>}
                {!d.current && paused && <Badge tone="warning">Paused</Badge>}
              </>
            }
            meta={deviceMeta(d, paused)}
            trailing={
              d.current ? (
                <Badge tone="success">Active</Badge>
              ) : (
                <Button variant="tertiary" arrow={false} onClick={() => setRevoking(d)}>
                  Revoke
                </Button>
              )
            }
          />
        ))}
      </List>

      {revoked.length > 0 && (
        <List label="Revoked devices">
          {revoked.map((d) => (
            <ListRow key={d.id} muted title={d.name} meta={deviceMeta(d, false)} trailing={<Badge tone="danger">Revoked</Badge>} />
          ))}
        </List>
      )}

      {pairing &&
        (plan === "pro" ? (
          <PairDeviceDialog
            onCancel={() => setPairing(false)}
            onApprove={(d) => {
              onPair(d);
              setPairing(false);
            }}
          />
        ) : (
          <PlanDialog
            plan={paused ? "paused" : plan}
            reason={
              paused
                ? "Pro ended, so pairing is paused. Everything on this device stays available."
                : "Pairing a second device needs Pro. Everything on this device keeps working on Free."
            }
            onClose={() => setPairing(false)}
          />
        ))}

      {revoking && (
        <RevokeDeviceDialog
          device={revoking}
          onCancel={() => setRevoking(null)}
          onConfirm={(wipe) => {
            onRevoke(revoking.id, wipe);
            setRevoking(null);
          }}
        />
      )}
    </div>
  );
}
