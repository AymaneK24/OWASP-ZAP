import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 30081,
    proxy: {
      '/auth': 'http://localhost:30080',
      '/api':  'http://localhost:30080',
    },
  },
});