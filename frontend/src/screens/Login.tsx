/**
 * Login — the first thing anyone sees.
 *
 * There is no authentication here and there is not meant to be. The product
 * ships authorisation WITHOUT authentication on purpose so the demo needs no
 * signup: you pick a role, the role travels as a header on every request, and
 * the API enforces it server-side. Choosing "Responder" on this screen grants
 * nothing — it only changes which refusal comes back. That sentence stays on
 * screen because hiding it would make the RBAC demo look like a UI trick.
 *
 * The background is a code-authored 3D network (see components/LoginScene).
 * It is lazy so three.js never reaches the entry chunk, it sits behind a static
 * `grid-bg` layer that is painted unconditionally, and a boundary swallows any
 * failure — no WebGL, no chunk, no driver — leaving that static layer as the
 * background. Nothing on this screen depends on the scene rendering.
 */
import { Component, lazy, Suspense, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { ArrowRight, ShieldCheck } from 'lucide-react'
import { useSession } from '@/providers/session'
import { Button } from '@/components/ui/button'
import { SectionLabel } from '@/components/primitives'
import { cn } from '@/lib/utils'
import type { Role } from '@/types/api'

const LoginScene = lazy(() => import('@/components/LoginScene'))

/** Renders nothing when the scene cannot run. The static background is already
 *  underneath it, so "nothing" is the correct fallback and not a blank hole. */
class SceneBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false }
  static getDerivedStateFromError() {
    return { failed: true }
  }
  render() {
    return this.state.failed ? null : this.props.children
  }
}

export default function Login() {
  const { role, roles, setRole, can } = useSession()

  return (
    <div className="relative flex h-full flex-col overflow-hidden bg-bg">
      {/* Painted unconditionally: this is what remains if the 3D never runs. */}
      <div className="grid-bg pointer-events-none absolute inset-0 opacity-60" aria-hidden />
      <SceneBoundary>
        <Suspense fallback={null}>
          <LoginScene />
        </Suspense>
      </SceneBoundary>
      {/* Keeps the card legible over the network without a blur or a glow. */}
      <div
        className="pointer-events-none absolute inset-0 bg-bg/40"
        aria-hidden
      />

      <header className="relative flex items-center gap-2.5 px-6 py-4">
        <div className="grid size-7 place-items-center rounded-md bg-accent font-mono text-sm font-semibold text-accent-fg">
          n
        </div>
        <div className="text-sm font-medium text-text">nextATT&amp;CKs</div>
        <div className="ml-auto font-mono text-xs text-faint">PS7 · Cyber Resilience</div>
      </header>

      <main className="relative flex flex-1 items-center justify-center p-6">
        <div className="w-full max-w-md rounded-lg border border-border bg-surface p-6">
          <SectionLabel>SOC Command Center</SectionLabel>
          <h1 className="mt-1.5 text-2xl font-semibold tracking-tight text-text">
            nextATT&amp;CKs
          </h1>
          <p className="mt-2 text-sm text-dim">
            Real-time anomaly detection, attack-path reasoning and ATT&amp;CK-driven
            attribution for critical national infrastructure.
          </p>

          <label className="mt-6 block">
            <span className="section-label">Sign in as</span>
            <select
              value={role}
              onChange={(e) => setRole(e.target.value as Role)}
              className={cn(
                'mt-1.5 h-8 w-full rounded-md border border-border bg-surface-2 px-2',
                'text-sm text-text focus-visible:outline-2 focus-visible:outline-accent',
              )}
            >
              {roles.map((r) => (
                <option key={r.role} value={r.role}>
                  {r.label} — {r.can}
                </option>
              ))}
            </select>
          </label>

          <p className="mt-3 flex gap-2 text-xs text-faint">
            <ShieldCheck className="mt-0.5 size-3.5 shrink-0" aria-hidden />
            <span>
              The role travels with every request and is enforced by the API, not by
              this screen. Picking Responder here does not grant anything — try
              approving a crown-jewel action as an Analyst and the server refuses.
              This is authorisation without authentication, on purpose, so the demo
              needs no signup.
            </span>
          </p>

          <Button asChild className="mt-6 w-full" size="lg">
            <Link to="/investigate">
              Enter demo environment
              <ArrowRight className="size-4" aria-hidden />
            </Link>
          </Button>

          <div className="mt-4 flex items-center justify-between border-t border-border pt-3 font-mono text-xs text-faint">
            <span>no credentials · no API key</span>
            <span>{can}</span>
          </div>
        </div>
      </main>
    </div>
  )
}
