import type { ReactNode } from "react";
import styles from "./List.module.css";

/** Bordered list with near-transparent dividers, used for devices and settings. */
export function List({ label, children }: { label?: string; children: ReactNode }) {
  return (
    <ul className={styles.list} aria-label={label}>
      {children}
    </ul>
  );
}

interface RowProps {
  title: ReactNode;
  meta?: ReactNode;
  trailing?: ReactNode;
  muted?: boolean;
}

export function ListRow({ title, meta, trailing, muted }: RowProps) {
  return (
    <li className={[styles.row, muted && styles.muted].filter(Boolean).join(" ")}>
      <div className={styles.text}>
        <div className={styles.title}>{title}</div>
        {meta && <div className={styles.meta}>{meta}</div>}
      </div>
      {trailing && <div className={styles.trailing}>{trailing}</div>}
    </li>
  );
}
