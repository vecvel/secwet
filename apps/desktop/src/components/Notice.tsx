import type { ReactNode } from "react";
import { Badge } from "./Badge";
import styles from "./Notice.module.css";

/** Inline notice: a labelled status badge, a sentence, and an optional action. */
export function Notice({ tone, label, children, action }: { tone: "warning" | "success" | "accent"; label: string; children: ReactNode; action?: ReactNode }) {
  return (
    <div className={styles.notice} role="status">
      <Badge tone={tone}>{label}</Badge>
      <p className={styles.text}>{children}</p>
      {action}
    </div>
  );
}
