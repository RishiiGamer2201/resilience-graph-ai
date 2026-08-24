/**
 * Normalise the configured backend URL to the root of the FastAPI surface.
 *
 * Vite's default is the same-origin `/api` proxy. For deployments that provide
 * only an origin (for example `http://127.0.0.1:8001`), append `/api` so every
 * client method still targets the routes registered by FastAPI. Explicit path
 * bases such as `/api` and `https://soc.example/internal/api` are preserved.
 */
export function normalizeApiBase(configured?: string): string {
  const raw = configured?.trim()
  if (!raw || raw === '/') return '/api'

  const withoutTrailingSlash = raw.replace(/\/+$/, '')

  try {
    const url = new URL(withoutTrailingSlash)
    if ((url.protocol === 'http:' || url.protocol === 'https:') && url.pathname === '/') {
      url.pathname = '/api'
      return url.toString().replace(/\/+$/, '')
    }
  } catch {
    // Relative bases are valid in browsers and intentionally pass through.
  }

  return withoutTrailingSlash
}
