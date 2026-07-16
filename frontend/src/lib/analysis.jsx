import { createContext, useContext, useState, useCallback, useEffect } from 'react'

// Holds the current live-analysis bundle. When set, every screen renders it
// instead of the pre-computed sample cache. `source` drives the topbar pill so a
// viewer can always tell live analysis from the sample at a glance.
const AnalysisContext = createContext({
  bundle: null, source: 'sample', setBundle: () => {}, clear: () => {},
})

export function AnalysisProvider({ children }) {
  const [bundle, setBundleState] = useState(null)
  const setBundle = useCallback((b) => setBundleState(b), [])
  const clear = useCallback(() => setBundleState(null), [])
  const source = bundle ? 'live' : 'sample'
  return (
    <AnalysisContext.Provider value={{ bundle, source, setBundle, clear }}>
      {children}
    </AnalysisContext.Provider>
  )
}

export const useAnalysis = () => useContext(AnalysisContext)

// Screen data resolver: return the live bundle's slice if an analysis is loaded,
// otherwise fetch the cached sample endpoint (same shape). Mirrors useFetch's
// { data, error, loading } and adds `source`.
export function useScreenData(key, cachedFetcher) {
  const { bundle } = useAnalysis()
  const live = bundle ? bundle[key] : null
  const [state, setState] = useState(
    live ? { data: live, error: null, loading: false }
         : { data: null, error: null, loading: true },
  )

  useEffect(() => {
    if (live) { setState({ data: live, error: null, loading: false }); return }
    let alive = true
    setState((s) => ({ ...s, loading: true, error: null }))
    cachedFetcher()
      .then((d) => { if (alive) setState({ data: d, error: null, loading: false }) })
      .catch((e) => { if (alive) setState({ data: null, error: e, loading: false }) })
    return () => { alive = false }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [live])

  return { ...state, source: live ? 'live' : 'sample' }
}
