import { useCallback, useEffect, useState } from 'react'

export interface FetchState<T> {
  data: T | null
  error: unknown
  loading: boolean
  reload: () => void
}

/**
 * Fetch once on mount, expose loading and error separately.
 *
 * There is no cached-example fallback here on purpose. A screen that cannot
 * reach the backend renders ErrorState with the backend's own message; it does
 * not quietly show data nobody just computed.
 */
export function useFetch<T>(fn: () => Promise<T>, deps: unknown[] = []): FetchState<T> {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<unknown>(null)
  const [loading, setLoading] = useState(true)
  const [nonce, setNonce] = useState(0)
  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError(null)
    fn()
      .then((d) => {
        if (!cancelled) setData(d)
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(e)
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, nonce])

  const reload = useCallback(() => setNonce((n) => n + 1), [])
  return { data, error, loading, reload }
}
