import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

const BACKEND = process.env.VITE_API_URL || process.env.VITE_BACKEND_URL || 'https://localhost:8000'

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': {
        target: BACKEND,
        changeOrigin: true,
        secure: false,
      }
    }
  }
})