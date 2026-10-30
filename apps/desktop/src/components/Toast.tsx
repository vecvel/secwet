import { useEffect, useState, type ReactNode } from "react";
import { Badge } from "./Badge";
import { Icon } from "./Icon";
import styles from "./Toast.module.css";

export interface ToastProps {
  tone?: "warning" | "danger" | "success" | "accent" | "neutral";
  label?: string;
  children: ReactNode;
  onDismiss: () => void;
  /** Auto-dismiss duration in milliseconds. 0 disables auto-dismiss. Default: 6000ms */
  duration?: number;
}

/** Floating dismissible notification matching Apple-smooth elevation and Secwet design tokens. */
export function Toast({
  tone = "warning",
  label,
  children,
  onDismiss,
  duration = 6000,
}: ToastProps) {
  const [exiting, setExiting] = useState(false);

  function handleDismiss() {
    if (exiting) return;
    setExiting(true);
    setTimeout(() => {
      onDismiss();
    }, 220);
  }

  useEffect(() => {
    if (duration <= 0) return;
    const timer = setTimeout(handleDismiss, duration);
    return () => clearTimeout(timer);
  }, [duration]);

  return (
    <div
      className={[styles.toast, exiting && styles.exiting].filter(Boolean).join(" ")}
      role="alert"
      aria-live="polite"
    >
      <Badge tone={tone} aria-label={label || `${tone} notice`}>
        {label}
      </Badge>
      <div className={styles.message}>{children}</div>
      <button
        type="button"
        className={styles.dismissBtn}
        onClick={handleDismiss}
        aria-label="Dismiss notification"
        title="Dismiss"
      >
        <Icon name="close" size={13} />
      </button>
    </div>
  );
}
