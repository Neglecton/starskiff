import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';

// base './' keeps asset URLs relative so the bundle works when the server
// mounts it under /admin/ (and behind reverse proxies at other prefixes).
export default defineConfig({
  plugins: [vue()],
  base: './',
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    chunkSizeWarningLimit: 1500,
  },
});
