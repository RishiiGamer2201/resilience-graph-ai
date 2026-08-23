import { lazy, Suspense } from 'react'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { ThemeProvider } from '@/providers/theme'
import { SessionProvider } from '@/providers/session'
import { AnalysisProvider } from '@/providers/analysis'
import Layout from '@/components/Layout'
import ErrorBoundary from '@/components/ErrorBoundary'
import { SkeletonRows } from '@/components/ui/skeleton'

// Heavy routes are lazy so three.js and recharts stay out of the entry chunk.
const Login = lazy(() => import('@/screens/Login'))
const Investigate = lazy(() => import('@/screens/Investigate'))
const Analyze = lazy(() => import('@/screens/Analyze'))
const Overview = lazy(() => import('@/screens/Overview'))
const DigitalTwin = lazy(() => import('@/screens/DigitalTwin'))
const Attackers = lazy(() => import('@/screens/Attackers'))
const Incident = lazy(() => import('@/screens/Incident'))
const Graph = lazy(() => import('@/screens/Graph'))
const ThreatIntel = lazy(() => import('@/screens/ThreatIntel'))
const ThreatRadar = lazy(() => import('@/screens/ThreatRadar'))
const Metrics = lazy(() => import('@/screens/Metrics'))
const Scoreboard = lazy(() => import('@/screens/Scoreboard'))
const Methodology = lazy(() => import('@/screens/Methodology'))

const Fallback = () => (
  <div className="p-4">
    <SkeletonRows rows={5} />
  </div>
)

const page = (el: React.ReactNode) => (
  <ErrorBoundary>
    <Suspense fallback={<Fallback />}>{el}</Suspense>
  </ErrorBoundary>
)

export default function App() {
  return (
    <ThemeProvider>
      <SessionProvider>
        <AnalysisProvider>
          <BrowserRouter>
            <Routes>
              <Route path="/" element={page(<Login />)} />
              <Route element={<Layout />}>
                <Route path="/investigate" element={page(<Investigate />)} />
                <Route path="/analyze" element={page(<Analyze />)} />
                <Route path="/overview" element={page(<Overview />)} />
                <Route path="/digital-twin" element={page(<DigitalTwin />)} />
                <Route path="/twin" element={<Navigate to="/digital-twin" replace />} />
                <Route path="/attackers" element={page(<Attackers />)} />
                <Route path="/incident" element={page(<Incident />)} />
                <Route path="/graph" element={page(<Graph />)} />
                <Route path="/threat-intel" element={page(<ThreatIntel />)} />
                <Route path="/threat-radar" element={page(<ThreatRadar />)} />
                <Route path="/metrics" element={page(<Metrics />)} />
                <Route path="/scoreboard" element={page(<Scoreboard />)} />
                <Route path="/methodology" element={page(<Methodology />)} />
              </Route>
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </BrowserRouter>
        </AnalysisProvider>
      </SessionProvider>
    </ThemeProvider>
  )
}
