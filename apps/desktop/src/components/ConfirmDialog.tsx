import { useState, type FormEvent, type ReactNode } from "react";
import { Button } from "./Button";
import { Dialog } from "./Dialog";
import { TextField } from "./Field";
import styles from "./ConfirmDialog.module.css";

interface Props {
  title: string;
  body: ReactNode;
  confirmLabel: string;
  /** When set, the user must type this exact text before confirming. */
  requireText?: string;
  onConfirm: () => void;
  onCancel: () => void;
  /** While the confirmed action runs: buttons and close are disabled. */
  busy?: boolean;
}

/** Destructive confirmation. Large deletions ask the user to type the item's name. */
export function ConfirmDialog({ title, body, confirmLabel, requireText, onConfirm, onCancel, busy = false }: Props) {
  const [typed, setTyped] = useState("");
  const [error, setError] = useState<ReactNode>();

  function submit(e: FormEvent) {
    e.preventDefault();
    if (busy) return;
    if (requireText && typed.trim() !== requireText) {
      setError(
        <span>
          Type <code className={styles.target}>{requireText}</code> exactly to confirm.
        </span>
      );
      return;
    }
    onConfirm();
  }

  return (
    <Dialog
      title={title}
      onClose={onCancel}
      busy={busy}
      footer={
        <>
          <Button variant="secondary" onClick={onCancel} disabled={busy}>
            Cancel
          </Button>
          <Button variant="danger" type="submit" form="confirm-dialog" disabled={busy}>
            {confirmLabel}
          </Button>
        </>
      }
    >
      <form id="confirm-dialog" onSubmit={submit} noValidate className="form-contents">
        <div className={styles.body}>{body}</div>
        {requireText && (
          <TextField
            label={
              <span>
                Type <code className={styles.target}>{requireText}</code> to confirm
              </span>
            }
            name="confirm"
            autoComplete="off"
            spellCheck={false}
            value={typed}
            error={error}
            onChange={(e) => {
              setTyped(e.target.value);
              if (error) setError(undefined);
            }}
          />
        )}
      </form>
    </Dialog>
  );
}
