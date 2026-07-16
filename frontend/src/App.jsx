import { lazy, Suspense } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { ThemeProvider } from './lib/theme.jsx'
import { AnalysisProvider } from './lib/analysis.jsx'
import Layout from './components/Layout.jsx'
import { Loading } from './components/Card.jsx'
import Login from './screens/Login.jsx'
import Analyze from './screens/Analyze.jsx'
import Attackers from './screens/Attackers.jsx'
import Overview from './screens/Overview.jsx'
import Incident from './screens/Incident.jsx'
import ThreatIntel from './screens/ThreatIntel.jsx'
import ThreatRadar from './screens/ThreatRadar.jsx'
import Methodology from './screens/Methodology.jsx'

// Heavy deps (force-graph, recharts) are split off the initial bundle.
const Graph = lazy(() => import('./screens/Graph.jsx'))
const Metrics = lazy(() => import('./screens/Metrics.jsx'))

export default function App() {
  return (
    <ThemeProvider>
      <AnalysisProvider>
        <BrowserRouter>
          <Routes>
            <Route path="/" element={<Login />} />
            <Route element={<Layout />}>
              <Route path="/analyze" element={<Analyze />} />
              <Route path="/overview" element={<Overview />} />
              <Route path="/attackers" element={<Attackers />} />
              <Route path="/incident" element={<Incident />} />
              <Route path="/graph" element={<Suspense fallback={<Loading />}><Graph /></Suspense>} />
              <Route path="/threat-intel" element={<ThreatIntel />} />
              <Route path="/threat-radar" element={<ThreatRadar />} />
              <Route path="/metrics" element={<Suspense fallback={<Loading />}><Metrics /></Suspense>} />
              <Route path="/methodology" element={<Methodology />} />
            </Route>
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </BrowserRouter>
      </AnalysisProvider>
    </ThemeProvider>
  )
}
