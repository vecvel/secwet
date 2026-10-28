import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Fixed port so tauri.conf.json devUrl matches.
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: { port: 1420, strictPort: true },
  build: {
    target: "es2021",
    rolldownOptions: {
      output: {
        // Keep React in its own chunk so the app chunk stays under the 500 kB advisory limit.
        advancedChunks: { groups: [{ name: "react", test: /node_modules[\\/](react|react-dom|scheduler)[\\/]/ }] },
      },
    },
  },
});
