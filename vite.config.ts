import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  server: {
    host: true,
    allowedHosts: [
      'c6c9-186-13-208-13.ngrok-free.app'
    ]
  },
  plugins: [react()],
})
