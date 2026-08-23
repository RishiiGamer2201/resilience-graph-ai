import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import path from 'node:path'

// Dev: proxy /api to the local FastAPI backend so the app uses same-origin
// "/api" in both dev and production (where FastAPI serves the built SPA).
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { '@': path.resolve(__dirname, './src') } },
  build: {
    rollupOptions: {
      output: {
        // Keep the heavy, route-lazy libraries out of the entry chunk. The
        // 3D scene, the graph and the charts load only on the routes that use
        // them. Rolldown (Vite 8) wants the function form, not the map.
        manualChunks(id: string) {
          if (id.includes('node_modules')) {
            if (/three|@react-three/.test(id)) return 'three'
            if (/react-force-graph/.test(id)) return 'graph'
            if (/recharts|d3-/.test(id)) return 'charts'
          }
          return undefined
        },
      },
    },
  },
  server: {
    proxy: { '/api': { target: 'http://localhost:8000', changeOrigin: true } },
  },
})
