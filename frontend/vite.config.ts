import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'

export default defineConfig({
  plugins: [svelte()],
  build: {
    outDir: 'dist',
  },
  server: {
    port: 5173,
    proxy: {
      '/xrpc': 'http://localhost:3000',
      '/oauth': 'http://localhost:3000',
      '/.well-known': 'http://localhost:3000',
      '/health': 'http://localhost:3000',
      '/u': 'http://localhost:3000',
    }
  }
})
