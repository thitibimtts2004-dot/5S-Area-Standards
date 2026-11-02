import { defineConfig } from 'vite'

// Single-source setup: Vite lives at the repo root and serves the live index.html
// directly — no separate app/ copy to drift out of sync.
// base: './' => relative asset paths, so the build works whether it is served from
// the site root or a GitHub Pages project sub-path (…/5S-Area-Standards/) without
// hard-coding the repo name.
export default defineConfig({
  root: '.',
  base: './',
  publicDir: false, // assets (std/*.jpg) are referenced relatively from index.html; no separate public/ dir
  server: {
    port: 5173,
    open: false,
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      input: 'index.html',
    },
  },
})
