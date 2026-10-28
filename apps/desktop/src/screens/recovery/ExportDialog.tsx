import { useState } from "react";
import { Button } from "../../components/Button";
import { Dialog } from "../../components/Dialog";
import { TextField } from "../../components/Field";
import { Notice } from "../../components/Notice";
import { formatUiError, isTauri, isValidRecoveryKey, normalizeRecoveryKey, type ExportSummaryDto } from "../../lib/api";
import { plural } from "../../lib/format";
import { useStore } from "../../lib/store";
import styles from "./ExportDialog.module.css";

interface ExportDialogProps {
  secretCount?: number;
  projectCount?: number;
  itemCount?: number;
  noteCount?: number;
  fileCount?: number;
  onClose: () => void;
}

export function ExportDialog({
  secretCount,
  projectCount,
  itemCount,
  noteCount,
  fileCount,
  onClose,
}: ExportDialogProps) {
  const [appState, store] = useStore();
  const [rawKey, setRawKey] = useState("");
  const [exporting, setExporting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [exportedSummary, setExportedSummary] = useState<ExportSummaryDto | null>(null);

  const effectiveSecrets = secretCount ?? appState.secrets.length;
  const effectiveItems = itemCount ?? projectCount ?? appState.items.length;
  const effectiveNotes = noteCount ?? appState.notes.length;
  const effectiveFiles = fileCount ?? (appState.files?.length || appState.assets?.length || 0);

  const normalizedKey = normalizeRecoveryKey(rawKey);
  const isValid = isValidRecoveryKey(normalizedKey);

  function getDefaultFilename(): string {
    const now = new Date();
    const yyyy = now.getFullYear();
    const mm = String(now.getMonth() + 1).padStart(2, "0");
    const dd = String(now.getDate()).padStart(2, "0");
    return `secwet-export-${yyyy}${mm}${dd}.secwet`;
  }

  async function handleExport() {
    if (!isValid) {
      setError("Please enter your full 25-character recovery key.");
      return;
    }

    try {
      setExporting(true);
      setError(null);

      let targetPath: string | null = null;
      if (isTauri()) {
        try {
          const { save } = await import("@tauri-apps/plugin-dialog");
          targetPath = await save({
            defaultPath: getDefaultFilename(),
            filters: [{ name: "Secwet Archive", extensions: ["secwet"] }],
          });
          if (!targetPath) {
            // User cancelled native file dialog
            setExporting(false);
            return;
          }
        } catch {
          // If plugin-dialog is unavailable, pass null to let backend handle dialog
          targetPath = null;
        }
      }

      const summary = await store.exportWorkspace(targetPath, normalizedKey);
      setExportedSummary(summary);
    } catch (err: unknown) {
      setError(formatUiError(err, "Failed to export workspace. Verify your recovery key and try again."));
    } finally {
      setExporting(false);
    }
  }

  return (
    <Dialog
      title="Encrypted export"
      description="Create an encrypted offline backup archive (.secwet) authenticated with your recovery key."
      onClose={onClose}
      footer={
        exportedSummary ? (
          <Button variant="primary" onClick={onClose}>
            Done
          </Button>
        ) : (
          <>
            <Button variant="secondary" onClick={onClose} disabled={exporting}>
              Cancel
            </Button>
            <Button
              variant="primary"
              onClick={handleExport}
              disabled={!isValid || exporting}
            >
              {exporting ? "Exporting…" : "Save export"}
            </Button>
          </>
        )
      }
    >
      <div className={styles.content}>
        {error && (
          <Notice tone="warning" label="Export error">
            {error}
          </Notice>
        )}

        {exportedSummary ? (
          <>
            <Notice tone="success" label="Export complete">
              Your workspace was securely encrypted and saved.
            </Notice>
            <div className={styles.summaryBox}>
              <span className={styles.filePath}>{exportedSummary.file_path}</span>
              <span>
                {exportedSummary.items_count} items, {exportedSummary.secrets_count} secrets,{" "}
                {exportedSummary.notes_count} notes, {exportedSummary.files_count} files ({exportedSummary.bytes_written} bytes)
              </span>
            </div>
          </>
        ) : (
          <>
            <dl className={styles.facts}>
              <dt>Includes</dt>
              <dd>
                {plural(effectiveItems, "item")}, {plural(effectiveSecrets, "secret")}, {plural(effectiveNotes, "note")}, and {plural(effectiveFiles, "file")}.
              </dd>
              <dt>Encrypted with</dt>
              <dd>Your 25-character recovery key</dd>
              <dt>Readable by</dt>
              <dd>Anyone holding both the .secwet archive file and the recovery key</dd>
            </dl>

            <TextField
              label="Recovery key"
              help="Enter your 25-character recovery key to authenticate and seal this archive."
              placeholder="XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
              value={rawKey}
              disabled={exporting}
              onChange={(e) => {
                const next = normalizeRecoveryKey(e.target.value);
                setRawKey(next);
                if (error) setError(null);
              }}
            />
          </>
        )}
      </div>
    </Dialog>
  );
}
