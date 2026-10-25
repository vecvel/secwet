import type { ReactNode } from "react";
import styles from "./Badge.module.css";

type Tone = "neutral" | "accent" | "success" | "warning" | "danger";

/** Status is carried by the label text; the dot only reinforces it. */
export function Badge({ tone = "neutral", dot = tone !== "neutral", children }: { tone?: Tone; dot?: boolean; children: ReactNode }) {
  return (
    <span className={[styles.badge, styles[tone]].join(" ")}>
      {dot && <span className={styles.dot} aria-hidden="true" />}
      {children}
    </span>
  );
}
