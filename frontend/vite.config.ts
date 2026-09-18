import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// The dev server binds loopback and proxies the API, so the browser only ever
// talks to ScanLedger itself - never to a scanned host (PRD UX-13).
export default defineConfig({
  plugins: [react()],
  server: {
    host: "127.0.0.1",
    port: 5173,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8000",
        changeOrigin: false,
      },
    },
  },
});
