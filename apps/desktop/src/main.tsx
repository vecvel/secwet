import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import "./styles/global.css";

if ("__TAURI_INTERNALS__" in window) {
  // Native desktop window: ignore web-view safe-area insets.
  document.documentElement.dataset.shell = "desktop";
  // macOS draws the window buttons over the top-left of the app (titleBarStyle: Overlay).
  if (navigator.userAgent.includes("Mac")) document.documentElement.dataset.titlebar = "overlay";
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
