import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  base: '/portal/',
  server: {
    proxy: {
      '/api': {
        target: 'https://localhost:3443',
        secure: false,
        ws: true,
      },
    },
  },
})
