import { vitePreprocess } from '@sveltejs/vite-plugin-svelte'
const isTest = process.env.VITEST === 'true' || process.env.VITEST === true
export default {
  preprocess: isTest ? [] : vitePreprocess(),
}
