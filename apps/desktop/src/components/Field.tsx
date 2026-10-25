import { useId, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes, type TextareaHTMLAttributes } from "react";
import { Icon } from "./Icon";
import styles from "./Field.module.css";

interface FieldFrameProps {
  label: string;
  help?: ReactNode;
  error?: string;
  id: string;
  children: ReactNode;
}

function FieldFrame({ label, help, error, id, children }: FieldFrameProps) {
  return (
    <div className={styles.field}>
      <label htmlFor={id} className={styles.label}>
        {label}
      </label>
      {children}
      {error ? (
        <p id={`${id}-msg`} className={styles.error} role="alert">
          {error}
        </p>
      ) : help ? (
        <p id={`${id}-msg`} className={styles.help}>
          {help}
        </p>
      ) : null}
    </div>
  );
}

interface CommonProps {
  label: string;
  help?: ReactNode;
  error?: string;
}

export function TextField({ label, help, error, className, ...rest }: CommonProps & InputHTMLAttributes<HTMLInputElement>) {
  const id = useId();
  return (
    <FieldFrame label={label} help={help} error={error} id={id}>
      <input
        id={id}
        aria-invalid={error ? true : undefined}
        aria-describedby={error || help ? `${id}-msg` : undefined}
        className={[styles.control, className].filter(Boolean).join(" ")}
        {...rest}
      />
    </FieldFrame>
  );
}

export function TextArea({ label, help, error, className, ...rest }: CommonProps & TextareaHTMLAttributes<HTMLTextAreaElement>) {
  const id = useId();
  return (
    <FieldFrame label={label} help={help} error={error} id={id}>
      <textarea
        id={id}
        aria-invalid={error ? true : undefined}
        aria-describedby={error || help ? `${id}-msg` : undefined}
        className={[styles.control, styles.textarea, className].filter(Boolean).join(" ")}
        {...rest}
      />
    </FieldFrame>
  );
}

export function SelectField({ label, help, error, children, className, ...rest }: CommonProps & SelectHTMLAttributes<HTMLSelectElement>) {
  const id = useId();
  return (
    <FieldFrame label={label} help={help} error={error} id={id}>
      <SelectControl id={id} className={className} {...rest}>
        {children}
      </SelectControl>
    </FieldFrame>
  );
}

/** Bare select with the shared look; used inside fields and in bars. */
export function SelectControl({ className, children, ...rest }: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <div className={styles.selectWrap}>
      <select className={[styles.control, styles.select, className].filter(Boolean).join(" ")} {...rest}>
        {children}
      </select>
      <span className={styles.chevron}>
        <Icon name="chevronDown" size={14} />
      </span>
    </div>
  );
}

/** Search input with leading icon, no label row. */
export function SearchInput({ className, ...rest }: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <div className={[styles.searchWrap, className].filter(Boolean).join(" ")}>
      <span className={styles.searchIcon}>
        <Icon name="search" size={14} />
      </span>
      <input type="search" className={[styles.control, styles.search].join(" ")} {...rest} />
    </div>
  );
}
