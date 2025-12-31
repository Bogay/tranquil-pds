import process from "node:process";
import { defineConfig, loadEnv } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const target = env.VITE_API_URL || "http://localhost:3000";

  return {
    plugins: [svelte()],
    build: {
      outDir: "dist",
    },
    server: {
      port: 5173,
      proxy: {
        "/xrpc": target,
        "/oauth": target,
        "/.well-known": target,
        "/health": target,
        "/u": target,
      },
    },
  };
});
