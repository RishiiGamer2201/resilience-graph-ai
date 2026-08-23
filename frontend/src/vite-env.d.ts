/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_BASE?: string
  /** Optional project-owned Spline scene. The UI falls back to its local WebGL scene. */
  readonly VITE_SPLINE_SCENE_URL?: string
}
interface ImportMeta {
  readonly env: ImportMetaEnv
}
