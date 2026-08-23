/**
 * The application shell: sidebar, topbar, scroll container, route transitions.
 *
 * The chrome is deliberately quiet. Everything here is a hairline and a label;
 * colour is reserved for data. See frontend/DESIGN.md.
 */
import { useEffect, useRef } from 'react'
import { NavLink, Outlet, useLocation } from 'react-router-dom'
import Lenis from 'lenis'
import { AnimatePresence, motion, useReducedMotion } from 'motion/react'
import {
  ClipboardCheck,
  Cpu,
  Crosshair,
  Database,
  LayoutDashboard,
  LineChart,
  Moon,
  Radar,
  ScanSearch,
  Satellite,
  Shield,
  Sun,
  Users,
  Waypoints,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { routeVariants } from '@/lib/motion'
import { useTheme } from '@/providers/theme'
import { ROLES, useSession } from '@/providers/session'
import { TooltipProvider } from '@/components/ui/tooltip'
import type { Role } from '@/types/api'

const OPERATIONS = [
  { to: '/investigate', label: 'Investigation', icon: Crosshair },
  { to: '/analyze', label: 'Analyze Log', icon: ScanSearch },
  { to: '/overview', label: 'Overview', icon: LayoutDashboard },
  { to: '/digital-twin', label: 'Digital Twin', icon: Cpu },
  { to: '/attackers', label: 'Attackers', icon: Users },
  { to: '/incident', label: 'Live Incident', icon: Radar },
  { to: '/graph', label: 'Attack Graph', icon: Waypoints },
  { to: '/threat-intel', label: 'Threat Intel & Attribution', icon: Shield },
  { to: '/threat-radar', label: 'Threat Radar', icon: Satellite },
] as const

const EVIDENCE = [
  { to: '/scoreboard', label: 'PS7 Scoreboard', icon: ClipboardCheck },
  { to: '/metrics', label: 'Models & Metrics', icon: LineChart },
  { to: '/methodology', label: 'Data & Methodology', icon: Database },
] as const

function NavItem({
  to,
  label,
  icon: Icon,
}: {
  to: string
  label: string
  icon: React.ComponentType<{ className?: string }>
}) {
  return (
    <NavLink
      to={to}
      className={({ isActive }) =>
        cn(
          'group relative flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-sm',
          'transition-colors duration-[120ms]',
          isActive
            ? 'bg-surface-2 text-text'
            : 'text-dim hover:bg-surface-2/60 hover:text-text',
        )
      }
    >
      {({ isActive }) => (
        <>
          {/* The active marker is a 2px rule, not a filled pill. */}
          {isActive ? (
            <motion.span
              layoutId="nav-active"
              className="absolute left-0 top-1/2 h-4 w-[2px] -translate-y-1/2 rounded-full bg-accent"
              transition={{ type: 'spring', stiffness: 500, damping: 40 }}
            />
          ) : null}
          <Icon className="size-4 shrink-0" />
          <span className="truncate">{label}</span>
        </>
      )}
    </NavLink>
  )
}

function Sidebar() {
  return (
    <aside className="flex w-56 shrink-0 flex-col border-r border-border bg-surface">
      <div className="flex items-center gap-2.5 border-b border-border px-4 py-3">
        <div className="grid size-7 place-items-center rounded-md bg-accent font-mono text-sm font-semibold text-accent-fg">
          n
        </div>
        <div className="min-w-0">
          <div className="truncate text-sm font-medium text-text">nextATT&amp;CKs</div>
          <div className="truncate text-xs text-faint">SOC Command Center</div>
        </div>
      </div>

      <nav className="flex-1 overflow-y-auto px-2 py-3">
        <div className="section-label px-2.5 pb-1.5">Operations</div>
        <div className="space-y-0.5">
          {OPERATIONS.map((n) => (
            <NavItem key={n.to} {...n} />
          ))}
        </div>

        <div className="section-label px-2.5 pb-1.5 pt-5">Evidence</div>
        <div className="space-y-0.5">
          {EVIDENCE.map((n) => (
            <NavItem key={n.to} {...n} />
          ))}
        </div>
      </nav>
    </aside>
  )
}

function RoleSelect() {
  const { role, setRole, can } = useSession()
  return (
    <label className="flex items-center gap-2">
      <span className="sr-only">Acting role</span>
      <select
        value={role}
        onChange={(e) => setRole(e.target.value as Role)}
        className={cn(
          'h-7 rounded-md border border-border bg-surface-2 px-2 text-xs text-text',
          'focus-visible:outline-2 focus-visible:outline-accent',
        )}
        title={`Enforced server-side. Currently: ${can}`}
      >
        {ROLES.map((r) => (
          <option key={r.role} value={r.role}>
            {r.label} — {r.can}
          </option>
        ))}
      </select>
    </label>
  )
}

function ThemeToggle() {
  const { theme, setTheme } = useTheme()
  const next = theme === 'dark' ? 'light' : 'dark'
  return (
    <button
      type="button"
      onClick={() => setTheme(next)}
      aria-label={`Switch to ${next} theme`}
      className="grid size-7 place-items-center rounded-md border border-border bg-surface-2 text-dim transition-colors duration-[120ms] hover:text-text"
    >
      {theme === 'dark' ? <Sun className="size-3.5" /> : <Moon className="size-3.5" />}
    </button>
  )
}

function Clock() {
  return (
    <span className="font-mono text-xs text-faint">
      {new Date().toLocaleString('en-IN', {
        timeZone: 'Asia/Kolkata',
        dateStyle: 'medium',
        timeStyle: 'medium',
      })}{' '}
      IST
    </span>
  )
}

/** Smooth scroll. Disabled entirely under prefers-reduced-motion. */
function useLenis(target: React.RefObject<HTMLElement | null>) {
  const reduced = useReducedMotion()
  useEffect(() => {
    const el = target.current
    if (!el || reduced) return
    const lenis = new Lenis({
      wrapper: el,
      content: el.firstElementChild as HTMLElement,
      duration: 0.9,
      easing: (t) => 1 - Math.pow(1 - t, 3),
      smoothWheel: true,
    })
    let raf = 0
    const loop = (time: number) => {
      lenis.raf(time)
      raf = requestAnimationFrame(loop)
    }
    raf = requestAnimationFrame(loop)
    return () => {
      cancelAnimationFrame(raf)
      lenis.destroy()
    }
  }, [target, reduced])
}

export default function Layout() {
  const scroller = useRef<HTMLDivElement>(null)
  const location = useLocation()
  useLenis(scroller)

  // A route change starts at the top; Lenis owns the scroll position otherwise.
  useEffect(() => {
    scroller.current?.scrollTo({ top: 0 })
  }, [location.pathname])

  return (
    <TooltipProvider delayDuration={200}>
      <div className="flex h-full overflow-hidden bg-bg">
        <Sidebar />
        <div className="flex min-w-0 flex-1 flex-col">
          <header className="flex h-12 shrink-0 items-center justify-between gap-4 border-b border-border bg-surface px-4">
            <div className="min-w-0" id="topbar-slot" />
            <div className="flex items-center gap-3">
              <Clock />
              <RoleSelect />
              <ThemeToggle />
            </div>
          </header>

          <div ref={scroller} className="flex-1 overflow-y-auto">
            <div>
              <AnimatePresence mode="wait">
                <motion.main
                  key={location.pathname}
                  initial="hidden"
                  animate="show"
                  exit="exit"
                  variants={routeVariants}
                  className="mx-auto w-full max-w-[1600px] p-4"
                >
                  <Outlet />
                </motion.main>
              </AnimatePresence>
            </div>
          </div>
        </div>
      </div>
    </TooltipProvider>
  )
}

/** Page heading. Screens render this as their first element. */
export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow?: string
  title: string
  description?: string
  actions?: React.ReactNode
}) {
  return (
    <div className="mb-4 flex items-start justify-between gap-6">
      <div className="min-w-0">
        {eyebrow ? <div className="section-label mb-1">{eyebrow}</div> : null}
        <h1 className="text-2xl font-semibold tracking-tight text-text">{title}</h1>
        {description ? (
          <p className="mt-1 max-w-2xl text-sm text-dim">{description}</p>
        ) : null}
      </div>
      {actions ? <div className="flex shrink-0 items-center gap-2">{actions}</div> : null}
    </div>
  )
}
