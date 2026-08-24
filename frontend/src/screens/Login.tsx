import { Link } from 'react-router-dom'
import { ArrowRight, Check, Database, Radio, ShieldCheck, TriangleAlert } from 'lucide-react'
import { motion } from 'motion/react'
import { getCapabilities, getScenarios } from '@/lib/api'
import { useFetch } from '@/hooks/useFetch'
import { useSession } from '@/providers/session'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import type { Capabilities, Role, ScenarioList } from '@/types/api'
import AttackSimulation from '@/components/AttackSimulation'

function Readiness() {
  const capabilities = useFetch<Capabilities>(getCapabilities)
  const scenarios = useFetch<ScenarioList>(getScenarios)
  const capValues = capabilities.data
    ? Array.isArray(capabilities.data.capabilities)
      ? capabilities.data.capabilities
      : Object.values(capabilities.data.capabilities)
    : []
  const degraded = capabilities.data?.degraded ?? []

  return (
    <div className="relative z-10 mt-auto border-t border-border bg-surface/95">
      <div className="grid divide-y divide-border sm:grid-cols-3 sm:divide-x sm:divide-y-0">
        <div className="p-4">
          <div className="section-label">API readiness</div>
          <div className="mt-2 flex items-center gap-2 text-sm text-text">
            {capabilities.loading ? (
              <span className="text-faint">checking…</span>
            ) : capabilities.error ? (
              <><TriangleAlert className="size-4 text-sev-high" /> unavailable</>
            ) : (
              <><Check className="size-4 text-ok" /> {capValues.length} capabilities</>
            )}
          </div>
        </div>
        <div className="p-4">
          <div className="section-label">Scenario inventory</div>
          <div className="mt-2 flex items-center gap-2 text-sm text-text">
            <Database className="size-4 text-accent" />
            {scenarios.loading ? 'loading…' : scenarios.error ? 'unavailable' : `${scenarios.data?.scenarios.length ?? 0} available`}
          </div>
        </div>
        <div className="p-4">
          <div className="section-label">Operating mode</div>
          <div className="mt-2 flex items-center gap-2 text-sm text-text">
            <Radio
              className={cn(
                'size-4',
                capabilities.error || degraded.length ? 'text-sev-high' : 'text-ok',
              )}
            />
            {capabilities.loading
              ? 'checking…'
              : capabilities.error
                ? 'unavailable'
                : degraded.length
                  ? `${degraded.length} degraded`
                  : capabilities.data?.usable_offline
                    ? 'offline capable'
                    : 'connected'}
          </div>
        </div>
      </div>
    </div>
  )
}

export default function Login() {
  const { role, roles, setRole, can, token, setToken } = useSession()

  return (
    <div className="grid h-full min-h-0 overflow-y-auto bg-bg lg:grid-cols-[minmax(22rem,0.82fr)_1.18fr]">
      <main className="relative z-20 flex min-h-full flex-col border-r border-border bg-bg px-6 py-6 sm:px-10 sm:py-8 lg:px-[clamp(2.5rem,6vw,6rem)] lg:py-10">
        <header className="flex items-center gap-3">
          <span className="relative grid size-10 place-items-center border border-accent/40 bg-accent-soft font-mono font-bold text-accent">
            N<span className="absolute -right-px -top-px size-1.5 bg-accent" />
          </span>
          <span>
            <span className="block text-sm font-semibold text-text">nextATT&amp;CKs</span>
            <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-faint">response intelligence</span>
          </span>
        </header>

        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.35, ease: [0.32, 0.72, 0, 1] }}
          className="my-auto max-w-xl py-12"
        >
          <div className="font-mono text-[10px] uppercase tracking-[0.18em] text-accent">Incident response workspace</div>
          <h1 className="mt-4 text-[clamp(2.7rem,7vw,5.7rem)] font-semibold leading-[0.9] tracking-[-0.065em] text-text">
            Understand the attack.<br />Respond safely.
          </h1>
          <p className="mt-6 max-w-lg text-base leading-7 text-dim">
            See what happened, what is at risk, and the next safe action.
          </p>

          <div className="mt-9 border-y border-border py-5">
            <label htmlFor="access-role" className="grid gap-2 sm:grid-cols-[8rem_1fr] sm:items-center">
              <span className="section-label">Choose your role</span>
              <select
                id="access-role"
                value={role}
                onChange={(event) => setRole(event.target.value as Role)}
                className="h-10 w-full rounded-md border border-border bg-surface px-3 text-sm text-text"
              >
                {roles.map((item) => (
                  <option key={item.role} value={item.role}>{item.label} - {item.can}</option>
                ))}
              </select>
            </label>
            <label htmlFor="access-token" className="mt-4 grid gap-2 sm:grid-cols-[8rem_1fr] sm:items-center">
              <span className="section-label">Access token</span>
              <input
                id="access-token"
                type="password"
                value={token}
                onChange={(event) => setToken(event.target.value)}
                autoComplete="off"
                placeholder="Optional access token"
                className="h-10 w-full rounded-md border border-border bg-surface px-3 font-mono text-sm text-text placeholder:text-faint"
              />
            </label>
          </div>

          <Button asChild size="lg" className="mt-6 w-full justify-between sm:w-auto sm:min-w-64">
            <Link to="/investigate">Start guided investigation <ArrowRight className="size-4" /></Link>
          </Button>

          <p className="mt-5 flex max-w-lg gap-2 text-xs leading-5 text-faint">
            <ShieldCheck className="mt-0.5 size-3.5 shrink-0 text-ok" />
            <span>The server checks your permission for every action.</span>
          </p>
        </motion.div>

        <footer className="flex items-center justify-between border-t border-border pt-4 font-mono text-[10px] uppercase tracking-[0.1em] text-faint">
          <span>Demo access</span><span>{can}</span>
        </footer>
      </main>

      <aside className="relative hidden min-h-full overflow-hidden bg-surface lg:flex lg:flex-col" aria-label="Example attack simulation and system readiness">
        <div className="grid-bg absolute inset-0 opacity-60" aria-hidden />
        <div className="absolute inset-0 bg-bg/25" aria-hidden />
        <AttackSimulation />
        <Readiness />
      </aside>
    </div>
  )
}
