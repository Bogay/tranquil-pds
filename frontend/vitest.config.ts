import { defineConfig } from "vitest/config";
import { svelte } from "@sveltejs/vite-plugin-svelte";
export default defineConfig({
  plugins: [
    svelte({
      hot: false,
    }),
  ],
  define: {
    __SVELTE_VERSION__: JSON.stringify("0.0.0-test"),
    __SVELTE_I18N_VERSION__: JSON.stringify("0.0.0-test"),
    __VITE_VERSION__: JSON.stringify("0.0.0-test"),
  },
  resolve: {
    conditions: ["browser", "development"],
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/tests/setup.ts"],
    include: ["src/**/*.{test,spec}.{js,ts}"],
    alias: {
      "svelte": "svelte",
    },
  },
});
