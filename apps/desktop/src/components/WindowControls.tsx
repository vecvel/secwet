import { useEffect, useState } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { IconButton } from "./Button";
import styles from "./WindowControls.module.css";

/**
 * Minimize, maximize and close for Windows and Linux, where the window has no native frame.
 * macOS keeps its own buttons (overlay title bar), so this renders nothing there or in a browser.
 */
export function WindowControls() {
  const custom = document.documentElement.dataset.titlebar === "custom";
  const [maximized, setMaximized] = useState(false);

  useEffect(() => {
    if (!custom) return;
    const win = getCurrentWindow();
    const sync = () =>
      void win.isMaximized().then((m) => {
        setMaximized(m);
        // Lets the rounded Linux window corners go square when maximized (global.css).
        document.documentElement.toggleAttribute("data-maximized", m);
      });
    sync();
    const unlisten = win.onResized(sync);
    return () => void unlisten.then((stop) => stop());
  }, [custom]);

  if (!custom) return null;
  const win = getCurrentWindow();
  return (
    <div className={styles.controls} data-no-drag>
      <IconButton icon="windowMinimize" label="Minimize" onClick={() => void win.minimize()} />
      <IconButton
        icon={maximized ? "windowRestore" : "windowMaximize"}
        label={maximized ? "Restore" : "Maximize"}
        onClick={() => void win.toggleMaximize()}
      />
      <IconButton icon="close" label="Close" onClick={() => void win.close()} />
    </div>
  );
}
