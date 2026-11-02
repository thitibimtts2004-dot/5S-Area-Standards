import { defineConfig } from 'vite'

// Phase 0: wrap the existing single-file app in Vite with the least possible change.
// base: './' => relative asset paths, so the build works whether it is served from
// the site root or a GitHub Pages project sub-path (…/5S-Area-Standards/) without
// hard-coding the repo name.
export default defineConfig({
  base: './',
  server: {
    port: 5173,
    open: false,
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
})
