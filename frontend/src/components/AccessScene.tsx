import { Component, lazy, Suspense, type ReactNode } from 'react'

const LocalScene = lazy(() => import('@/components/LoginScene'))
const Spline = lazy(() => import('@splinetool/react-spline'))

class SceneBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false }
  static getDerivedStateFromError() {
    return { failed: true }
  }
  render() {
    return this.state.failed ? null : this.props.children
  }
}

/**
 * Spline is opt-in because the repository does not ship a project-owned scene.
 * Set VITE_SPLINE_SCENE_URL to a .splinecode asset; without it the local,
 * deterministic topology scene remains the visual fallback.
 */
export default function AccessScene() {
  const scene = import.meta.env.VITE_SPLINE_SCENE_URL?.trim()
  return (
    <SceneBoundary>
      <Suspense fallback={null}>
        {scene ? <Spline scene={scene} /> : <LocalScene />}
      </Suspense>
    </SceneBoundary>
  )
}
