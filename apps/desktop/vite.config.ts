import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Fixed port so tauri.conf.json devUrl matches.
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: { port: 1420, strictPort: true },
  build: { target: "es2021" },
});
