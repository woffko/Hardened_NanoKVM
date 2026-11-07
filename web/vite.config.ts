import { rmSync } from 'node:fs';

import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';
import viteTsconfigPaths from 'vite-tsconfig-paths';

const excludeMockWorkerFromProduction = () => {
  let production = false;
  return {
    name: 'exclude-mock-worker-from-production',
    apply: 'build' as const,
    configResolved(config: { mode: string }) {
      production = config.mode === 'production';
    },
    closeBundle() {
      if (production) rmSync('dist/mockServiceWorker.js', { force: true });
    }
  };
};

export default defineConfig({
  plugins: [react(), viteTsconfigPaths(), excludeMockWorkerFromProduction()],
  server: {
    port: 3001
  },
  build: {
    chunkSizeWarningLimit: 1024
  }
});
