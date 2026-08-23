/**
 * The current live-analysis bundle.
 *
 * Investigate and Analyze both produce a full `AnalysisBundle`. Publishing it
 * here is what lets the rest of the console render the run the operator just
 * did, instead of the pre-computed sample cache. `source` is the honesty part:
 * a screen must be able to say which of the two it is showing, because "live"
 * and "sample" looking identical is the failure mode this exists to prevent.
 *
 * Ported from src/lib/analysis.jsx. Consumers call `useAnalysis()`.
 */
import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import type { AnalysisBundle } from '@/types/api'

export type AnalysisSource = 'live' | 'sample'

interface AnalysisValue {
  bundle: AnalysisBundle | null
  source: AnalysisSource
  setBundle: (b: AnalysisBundle | null) => void
  clear: () => void
}

const AnalysisContext = createContext<AnalysisValue>({
  bundle: null,
  source: 'sample',
  setBundle: () => {},
  clear: () => {},
})

export function AnalysisProvider({ children }: { children: React.ReactNode }) {
  const [bundle, setBundle] = useState<AnalysisBundle | null>(null)
  const clear = useCallback(() => setBundle(null), [])
  const value = useMemo<AnalysisValue>(
    () => ({ bundle, source: bundle ? 'live' : 'sample', setBundle, clear }),
    [bundle, clear],
  )
  return <AnalysisContext.Provider value={value}>{children}</AnalysisContext.Provider>
}

export const useAnalysis = () => useContext(AnalysisContext)

/** Prefer a live bundle slice and only fetch the sample cache when no live
 *  value exists. This keeps route changes on the incident the operator ran. */
export function useScreenData<T>(
  live: T | null | undefined,
  cachedFetcher: () => Promise<T>,
) {
  const hasLive = live !== null && live !== undefined
  const [nonce, setNonce] = useState(0)
  const [state, setState] = useState<{
    data: T | null
    error: unknown
    loading: boolean
  }>(() => ({ data: hasLive ? live : null, error: null, loading: !hasLive }))

  useEffect(() => {
    if (hasLive) {
      setState({ data: live, error: null, loading: false })
      return
    }
    let active = true
    setState((current) => ({ ...current, error: null, loading: true }))
    cachedFetcher()
      .then((data) => {
        if (active) setState({ data, error: null, loading: false })
      })
      .catch((error: unknown) => {
        if (active) setState({ data: null, error, loading: false })
      })
    return () => {
      active = false
    }
  }, [cachedFetcher, hasLive, live, nonce])

  const reload = useCallback(() => setNonce((value) => value + 1), [])
  return { ...state, reload, source: hasLive ? 'live' : 'sample' as AnalysisSource }
}
