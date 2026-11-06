import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'path';

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: 'dist',
    rollupOptions: {
      input: {
        popup: resolve(__dirname, 'src/popup/index.html'),
        safeExit: resolve(__dirname, 'src/safe-exit/index.html'),
        warning: resolve(__dirname, 'src/warning/index.html'),
        serviceWorker: resolve(__dirname, 'src/background/service-worker.ts'),
        contentScript: resolve(__dirname, 'src/content/content-script.ts')
      },
      output: {
        entryFileNames: (chunkInfo) => {
          if (chunkInfo.name === 'serviceWorker') return 'service-worker.js';
          if (chunkInfo.name === 'contentScript') return 'content-script.js';
          return 'assets/[name]-[hash].js';
        },
        chunkFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash].[ext]'
      }
    }
  }
});

