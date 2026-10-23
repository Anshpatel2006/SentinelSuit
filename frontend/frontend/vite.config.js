import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, ".", "");
  return {
    plugins: [react()],
    cacheDir: "node_modules/.vite-sentinelsuite",
    server: { port: Number(env.VITE_PORT || 3000), host: "127.0.0.1" },
  };
});
