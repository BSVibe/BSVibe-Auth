import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import path from 'node:path';

/**
 * Vitest config for the Next.js 15 BSVibe-Auth app.
 *
 * Phase Z: vite.config.ts was removed alongside the Vite dependency. Vitest
 * still uses Vite under the hood (its own bundle), so this thin config keeps
 * the React plugin (for .tsx transform), jsdom + setup files.
 */
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, '.'),
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test-setup.ts'],
    exclude: ['**/node_modules/**', '**/e2e/**', '**/.next/**'],
  },
});
