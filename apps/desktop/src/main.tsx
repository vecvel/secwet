import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import "./styles/global.css";

if ("__TAURI_INTERNALS__" in window) {
  // Native desktop window: ignore web-view safe-area insets (see global.css).
  document.documentElement.dataset.shell = "desktop";
  // macOS draws the window buttons over the top-left of the app (titleBarStyle: Overlay).
  // Windows and Linux open without a native frame (tauri.windows/linux.conf.json); the app draws the buttons.
  document.documentElement.dataset.titlebar = navigator.userAgent.includes("Mac") ? "overlay" : "custom";
  // Windows 11 rounds a frameless window that keeps its system shadow; Linux does not, so the app
  // draws the corners on a transparent window (tauri.linux.conf.json).
  if (navigator.userAgent.includes("Linux")) document.documentElement.dataset.windowCorners = "rounded";
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
