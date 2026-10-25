import { useState, type FormEvent, type ReactNode } from "react";
import { Button } from "./Button";
import { Dialog } from "./Dialog";
import { TextField } from "./Field";

interface Props {
  title: string;
  description?: string;
  label: string;
  initial?: string;
  placeholder?: string;
  confirmLabel: string;
  /** Returns an error message, or undefined when the value is usable. */
  validate: (value: string) => string | undefined;
  onSubmit: (value: string) => void;
  onCancel: () => void;
  children?: ReactNode;
}

/** One-field dialog for creating or renaming something. Enter submits, Escape cancels. */
export function NameDialog({ title, description, label, initial = "", placeholder, confirmLabel, validate, onSubmit, onCancel, children }: Props) {
  const [value, setValue] = useState(initial);
  const [error, setError] = useState<string>();

  function submit(e: FormEvent) {
    e.preventDefault();
    const err = validate(value);
    setError(err);
    if (!err) onSubmit(value.trim());
  }

  return (
    <Dialog
      title={title}
      description={description}
      onClose={onCancel}
      footer={
        <>
          <Button variant="secondary" onClick={onCancel}>
            Cancel
          </Button>
          <Button variant="primary" type="submit" form="name-dialog">
            {confirmLabel}
          </Button>
        </>
      }
    >
      <form id="name-dialog" onSubmit={submit} noValidate className="form-contents">
        <TextField
          label={label}
          name="name"
          autoComplete="off"
          spellCheck={false}
          placeholder={placeholder}
          value={value}
          error={error}
          onChange={(e) => {
            setValue(e.target.value);
            if (error) setError(undefined);
          }}
        />
        {children}
      </form>
    </Dialog>
  );
}
