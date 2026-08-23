import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import path from 'node:path'

// Dev: proxy /api to the local FastAPI backend so the app uses same-origin
// "/api" in both dev and production (where FastAPI serves the built SPA).
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { '@': path.resolve(__dirname, './src') },
    // Vite's default order puts .jsx BEFORE .tsx, so while a pre-redesign
    // Screen.jsx still sits next to its ported Screen.tsx, a bare
    // "@/screens/Screen" silently resolves to the old file — the whole
    // redesign builds as dead code and nobody sees an error. TypeScript first.
    extensions: ['.mjs', '.mts', '.ts', '.tsx', '.js', '.jsx', '.json'],
  },
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
    // 8001 avoids colliding with the other local FastAPI services commonly
    // using 8000. Override without editing source when a different port is used.
    proxy: {
      '/api': {
        target: process.env.NEXTATTACK_DEV_API ?? 'http://127.0.0.1:8001',
        changeOrigin: true,
      },
    },
  },
})
