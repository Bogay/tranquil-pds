import process from "node:process";
import { readFileSync } from "node:fs";
import { defineConfig, loadEnv } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";

const sveltePkg = JSON.parse(readFileSync("./node_modules/svelte/package.json", "utf-8"));
const svelteI18nPkg = JSON.parse(readFileSync("./node_modules/svelte-i18n/package.json", "utf-8"));
const vitePkg = JSON.parse(readFileSync("./node_modules/vite/package.json", "utf-8"));

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const target = env.VITE_API_URL || "http://localhost:3000";

  return {
    plugins: [svelte()],
    define: {
      __SVELTE_VERSION__: JSON.stringify(sveltePkg.version),
      __SVELTE_I18N_VERSION__: JSON.stringify(svelteI18nPkg.version),
      __VITE_VERSION__: JSON.stringify(vitePkg.version),
    },
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
      hmr: env.VITE_HMR_HOST
        ? {
            protocol: env.VITE_HMR_PROTOCOL || "wss",
            host: env.VITE_HMR_HOST,
            clientPort: parseInt(env.VITE_HMR_PORT || "443"),
          }
        : undefined,
    },
  };
});
