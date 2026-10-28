import type { ReactNode } from "react";
import styles from "./Badge.module.css";

type Tone = "neutral" | "accent" | "success" | "warning" | "danger";

interface BadgeProps {
  tone?: Tone;
  dot?: boolean;
  children?: ReactNode;
  "aria-label"?: string;
}

/** Status is carried by the label text or dot indicator. */
export function Badge({
  tone = "neutral",
  dot = tone !== "neutral",
  children,
  "aria-label": ariaLabel,
}: BadgeProps) {
  const isDotOnly = !children;
  return (
    <span
      className={[styles.badge, styles[tone], isDotOnly && styles.dotOnly].filter(Boolean).join(" ")}
      aria-label={ariaLabel}
    >
      {dot && <span className={styles.dot} aria-hidden="true" />}
      {children}
    </span>
  );
}
