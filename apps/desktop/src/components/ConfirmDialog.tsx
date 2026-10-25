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
}

/** Destructive confirmation. Large deletions ask the user to type the item's name. */
export function ConfirmDialog({ title, body, confirmLabel, requireText, onConfirm, onCancel }: Props) {
  const [typed, setTyped] = useState("");
  const [error, setError] = useState<string>();

  function submit(e: FormEvent) {
    e.preventDefault();
    if (requireText && typed.trim() !== requireText) {
      setError(`Type ${requireText} exactly to confirm.`);
      return;
    }
    onConfirm();
  }

  return (
    <Dialog
      title={title}
      onClose={onCancel}
      footer={
        <>
          <Button variant="secondary" onClick={onCancel}>
            Cancel
          </Button>
          <Button variant="danger" type="submit" form="confirm-dialog">
            {confirmLabel}
          </Button>
        </>
      }
    >
      <form id="confirm-dialog" onSubmit={submit} noValidate className="form-contents">
        <div className={styles.body}>{body}</div>
        {requireText && (
          <TextField
            label={`Type ${requireText} to confirm`}
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
