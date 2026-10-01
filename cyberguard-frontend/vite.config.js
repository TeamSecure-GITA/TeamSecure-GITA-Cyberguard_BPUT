import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { defineConfig, loadEnv } from 'vite'
import { fileURLToPath } from 'node:url'

export default defineConfig(({ mode }) => {
  const frontendRoot = fileURLToPath(new URL('.', import.meta.url))
  const env = loadEnv(mode, frontendRoot, 'VITE_')

  if (mode === 'production') {
    let apiUrl
    try {
      apiUrl = new URL(env.VITE_API_URL)
    } catch {
      throw new Error('Production builds require VITE_API_URL to be set to the public HTTPS backend URL.')
    }
    if (
      apiUrl.protocol !== 'https:'
      || apiUrl.username
      || apiUrl.password
      || apiUrl.hostname === 'localhost'
      || apiUrl.hostname === '::1'
      || /^127(?:\.\d{1,3}){3}$/.test(apiUrl.hostname)
    ) {
      throw new Error('Production VITE_API_URL must be a public HTTPS URL without embedded credentials or a loopback host.')
    }
  }

  return {
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
  }
})
