import { useState } from "react";
import { Badge } from "../../components/Badge";
import { Button } from "../../components/Button";
import { List, ListRow } from "../../components/List";
import { PageHeader, Section } from "../../components/PageHeader";
import { formatAgo, formatDate } from "../../lib/format";
import { CreateRecoveryKeyDialog } from "./CreateRecoveryKeyDialog";
import { ExportDialog } from "./ExportDialog";
import { RotateKeyDialog } from "./RotateKeyDialog";
import styles from "./RecoveryScreen.module.css";

interface Props {
  recoveryKeyCreatedAt?: number;
  keyRotatedAt?: number;
  pendingRotation?: string;
  secretCount: number;
  projectCount: number;
  onRecoveryKeyCreated: () => void;
  onRotated: () => void;
}

type Open = "create" | "export" | "rotate" | null;

export function RecoveryScreen({ recoveryKeyCreatedAt, keyRotatedAt, pendingRotation, secretCount, projectCount, onRecoveryKeyCreated, onRotated }: Props) {
  const [open, setOpen] = useState<Open>(null);
  const close = () => setOpen(null);
  const hasKey = recoveryKeyCreatedAt !== undefined;

  return (
    <div className={styles.screen}>
      <PageHeader title="Recovery and backup" subtitle="Only you hold these. Secwet has no account to reset and cannot recover your data for you." />

      <List label="Recovery and backup">
        <ListRow
          title={
            <>
              Recovery key
              {hasKey ? <Badge tone="success">Created</Badge> : <Badge tone="warning">Not created</Badge>}
            </>
          }
          meta={hasKey ? `Created ${formatDate(recoveryKeyCreatedAt)}. Keep it somewhere other than this device.` : "Without it, losing every device means losing your data."}
          trailing={
            <Button variant={hasKey ? "secondary" : "primary"} onClick={() => setOpen("create")}>
              {hasKey ? "Replace" : "Create"}
            </Button>
          }
        />
        <ListRow
          title="Encrypted export"
          meta={hasKey ? "One file with every project, encrypted with your recovery key." : "Create a recovery key first. The export is encrypted with it."}
          trailing={
            <Button variant="secondary" onClick={() => setOpen(hasKey ? "export" : "create")}>
              {hasKey ? "Export" : "Create key first"}
            </Button>
          }
        />
        <ListRow
          title={
            <>
              Rotate encryption key
              {pendingRotation && <Badge tone="warning">Recommended</Badge>}
            </>
          }
          meta={
            pendingRotation
              ? `${pendingRotation} was revoked. Rotating stops it reading changes made from now on.`
              : keyRotatedAt
                ? `Last rotated ${formatAgo(keyRotatedAt).toLowerCase()}.`
                : "Recommended after revoking a device."
          }
          trailing={
            <Button variant="tertiary" onClick={() => setOpen("rotate")}>
              Rotate
            </Button>
          }
        />
      </List>

      <Section title="What recovery cannot do">
        <ul className={styles.limits}>
          <li>Secwet's servers never hold your encryption key, so there is no way to reset access without your recovery key or another trusted device.</li>
          <li>Revoking a device or rotating the key can't erase secrets a device already copied.</li>
          <li>Ending a Pro subscription never deletes or locks your local data. Export stays available on every plan.</li>
        </ul>
      </Section>

      {open === "create" && (
        <CreateRecoveryKeyDialog
          replacing={hasKey}
          onCancel={close}
          onDone={() => {
            onRecoveryKeyCreated();
            close();
          }}
        />
      )}
      {open === "export" && <ExportDialog secretCount={secretCount} projectCount={projectCount} onClose={close} />}
      {open === "rotate" && (
        <RotateKeyDialog
          onCancel={close}
          onConfirm={() => {
            onRotated();
            close();
          }}
        />
      )}
    </div>
  );
}
