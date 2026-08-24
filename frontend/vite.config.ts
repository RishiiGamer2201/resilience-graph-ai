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
    // No manualChunks. Naming three.js / the force graph / recharts as manual
    // chunks looked like an optimisation and was the opposite: rolldown hoisted
    // them into the entry's static dependency set, so index.html eagerly loaded
    // 2 MB of libraries that the lazy routes were supposed to defer. First paint
    // pulled the 3D graph even if you never opened /graph.
    //
    // The routes in App.tsx are already React.lazy, and the 2D attack map is
    // lazy inside its screen. Left alone, the bundler keeps each behind
    // its dynamic import, which is what we wanted in the first place.
    chunkSizeWarningLimit: 1600,
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
