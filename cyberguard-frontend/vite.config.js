import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes('node_modules/react/') || id.includes('node_modules/react-dom/')) return 'react';
          if (id.includes('node_modules/recharts/') || id.includes('node_modules/reactflow/')) return 'charts';
          if (id.includes('node_modules/jspdf/')) return 'pdf';
          if (id.includes('node_modules/html2canvas/')) return 'canvas';
          return undefined;
        },
      },
    },
  },
})
