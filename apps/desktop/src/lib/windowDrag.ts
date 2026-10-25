import type { MouseEvent } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";

const inDesktopShell = "__TAURI_INTERNALS__" in window;

// Pressing on any of these keeps its normal behavior instead of moving the window.
const INTERACTIVE = 'button, a, input, select, textarea, [role="button"], [role="tab"], [role="menuitem"], [data-no-drag]';

/**
 * Title-bar behavior for custom header areas: press and drag moves the window, double-click zooms it.
 * Works on the element and everything inside it, unlike data-tauri-drag-region, which only reacts to
 * presses on the element itself.
 */
export function onWindowDragMouseDown(e: MouseEvent<HTMLElement>) {
  if (!inDesktopShell || e.button !== 0) return;
  if ((e.target as HTMLElement).closest(INTERACTIVE)) return;
  const win = getCurrentWindow();
  if (e.detail === 2) {
    void win.toggleMaximize();
    return;
  }
  void win.startDragging();
}
