import { useState } from "react";
import { Button } from "../../components/Button";
import { Dialog } from "../../components/Dialog";
import { plural } from "../../lib/format";
import styles from "./ExportDialog.module.css";

export function ExportDialog({ secretCount, projectCount, onClose }: { secretCount: number; projectCount: number; onClose: () => void }) {
  const [attempted, setAttempted] = useState(false);

  return (
    <Dialog
      title="Encrypted export"
      description="Creates one file you can keep as a backup or import on a new device."
      onClose={onClose}
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Close
          </Button>
          <Button variant="primary" onClick={() => setAttempted(true)}>
            Save export
          </Button>
        </>
      }
    >
      <dl className={styles.facts}>
        <dt>Includes</dt>
        <dd>
          {plural(secretCount, "secret")} in {plural(projectCount, "project")}, with names, notes and environments
        </dd>
        <dt>Encrypted with</dt>
        <dd>Your recovery key</dd>
        <dt>Readable by</dt>
        <dd>Anyone holding both the file and the recovery key</dd>
      </dl>
      {attempted && (
        <p className={styles.unavailable} role="status">
          Saving exports isn't available in this build yet.
        </p>
      )}
    </Dialog>
  );
}
