import { useLayoutEffect, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { BrandMark } from "../components/Icon";
import { WindowControls } from "../components/WindowControls";
import { onWindowDragMouseDown } from "../lib/windowDrag";
import styles from "./TopBar.module.css";

export function TopBar({
  children,
  actions,
}: {
  children: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <header className={styles.bar} onMouseDown={onWindowDragMouseDown}>
      <span className={styles.compactBrand} aria-hidden="true">
        <BrandMark size={18} />
      </span>
      <div className={styles.context}>{children}</div>
      <div
        id="topbar-actions"
        className={styles.actions}
        onMouseDown={(e) => e.stopPropagation()}
      >
        {actions}
      </div>
      <WindowControls />
    </header>
  );
}

export function TopBarActions({ children }: { children: ReactNode }) {
  const [target, setTarget] = useState<Element | null>(() =>
    typeof document !== "undefined" ? document.getElementById("topbar-actions") : null
  );

  useLayoutEffect(() => {
    if (!target) {
      setTarget(document.getElementById("topbar-actions"));
    }
  }, [target]);

  if (!target) return null;
  return createPortal(children, target);
}
