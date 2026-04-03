import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { copyFileSync, mkdirSync, existsSync } from 'fs'
import { resolve } from 'path'

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    {
      name: 'copy-locales',
      closeBundle() {
        const srcDir = resolve(__dirname, 'src/locales')
        const distDir = resolve(__dirname, 'dist/locales')
        if (!existsSync(distDir)) {
          mkdirSync(distDir, { recursive: true })
        }
        copyFileSync(resolve(srcDir, 'zh.json'), resolve(distDir, 'zh.json'))
        copyFileSync(resolve(srcDir, 'en.json'), resolve(distDir, 'en.json'))
      }
    },
    react()
  ],
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:8006',
        changeOrigin: true,
        secure: false
      }
    }
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['react', 'react-dom', 'react-router-dom', 'antd', 'recharts']
        }
      }
    }
  }
})
