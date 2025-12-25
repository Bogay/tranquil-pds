import { defineConfig } from "vitest/config";
import { svelte } from "@sveltejs/vite-plugin-svelte";
export default defineConfig({
  plugins: [
    svelte({
      hot: false,
    }),
  ],
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
