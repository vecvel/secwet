import type { ReactNode } from "react";
import { BrandMark } from "../components/Icon";
import { onWindowDragMouseDown } from "../lib/windowDrag";
import styles from "./TopBar.module.css";

/** Holds the page context only. */
export function TopBar({ children }: { children: ReactNode }) {
  return (
    <header className={styles.bar} onMouseDown={onWindowDragMouseDown}>
      <span className={styles.compactBrand} aria-hidden="true">
        <BrandMark size={18} />
      </span>
      <div className={styles.context}>{children}</div>
    </header>
  );
}
