import { useEffect, useRef, useState } from 'react'
import { NavLink, Outlet, useLocation } from 'react-router-dom'
import Lenis from 'lenis'
import { AnimatePresence, motion, useReducedMotion } from 'motion/react'
import { Menu, Moon, Radio, Sun } from 'lucide-react'
import { cn } from '@/lib/utils'
import { routeVariants } from '@/lib/motion'
import { getNavigationItem, navigationGroups, navigationItems } from '@/lib/navigation'
import { getHealth } from '@/lib/api'
import { useFetch } from '@/hooks/useFetch'
import { useTheme } from '@/providers/theme'
import { ROLES, useSession } from '@/providers/session'
import { TooltipProvider } from '@/components/ui/tooltip'
import {
  Sheet,
  SheetClose,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from '@/components/ui/sheet'
import type { Health, Role } from '@/types/api'

function Brand() {
  return (
    <NavLink to="/investigate" className="group flex min-w-0 items-center gap-3">
      <span className="relative grid size-9 shrink-0 place-items-center border border-accent/40 bg-accent-soft font-mono text-sm font-bold text-accent">
        N
        <span className="absolute -right-px -top-px size-1.5 bg-accent" aria-hidden />
      </span>
      <span className="min-w-0">
        <span className="block truncate text-sm font-semibold tracking-tight text-text">nextATT&amp;CKs</span>
        <span className="block truncate font-mono text-[10px] uppercase tracking-[0.14em] text-faint">response intelligence</span>
      </span>
    </NavLink>
  )
}

function RoleSelect({ compact = false }: { compact?: boolean }) {
  const { role, setRole, can } = useSession()
  return (
    <label className={cn('flex items-center gap-2', compact && 'w-full flex-col items-stretch')}>
      <span className={compact ? 'section-label' : 'sr-only'}>Acting role</span>
      <select
        value={role}
        onChange={(event) => setRole(event.target.value as Role)}
        className={cn(
          'h-8 rounded-md border border-border bg-surface-2 px-2 text-xs text-text focus-visible:outline-2 focus-visible:outline-accent',
          compact && 'w-full',
        )}
        title={`Enforced server-side. Currently: ${can}`}
      >
        {ROLES.map((item) => (
          <option key={item.role} value={item.role}>{item.label} — {item.can}</option>
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
      className="grid size-8 place-items-center rounded-md border border-border bg-surface-2 text-dim transition-colors hover:text-text"
    >
      {theme === 'dark' ? <Sun className="size-3.5" /> : <Moon className="size-3.5" />}
    </button>
  )
}

function Clock() {
  const [now, setNow] = useState(() => new Date())
  useEffect(() => {
    const timer = window.setInterval(() => setNow(new Date()), 1000)
    return () => window.clearInterval(timer)
  }, [])
  return (
    <span className="hidden font-mono text-[10px] uppercase tracking-[0.08em] text-faint xl:block">
      {now.toLocaleTimeString('en-IN', { timeZone: 'Asia/Kolkata', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })} IST
    </span>
  )
}

function DesktopNavigation() {
  const reduced = useReducedMotion()
  return (
    <nav className="hidden min-w-0 flex-1 items-stretch overflow-x-auto lg:flex" aria-label="Primary">
      {navigationItems.map((item) => (
        <NavLink
          key={item.to}
          to={item.to}
          className={({ isActive }) => cn(
            'group relative flex h-11 shrink-0 items-center gap-1.5 px-3 text-xs transition-colors',
            isActive ? 'text-text' : 'text-faint hover:text-dim',
          )}
        >
          {({ isActive }) => (
            <>
              <item.icon className="size-3.5" aria-hidden />
              <span>{item.shortLabel}</span>
              {isActive && !reduced ? (
                <motion.span
                  layoutId="primary-nav-active"
                  className="absolute inset-x-3 bottom-0 h-0.5 bg-accent"
                  transition={{ type: 'spring', stiffness: 420, damping: 36 }}
                />
              ) : isActive ? <span className="absolute inset-x-3 bottom-0 h-0.5 bg-accent" /> : null}
            </>
          )}
        </NavLink>
      ))}
    </nav>
  )
}

function SystemStatus() {
  const health = useFetch<Health>(getHealth)
  const state = health.loading
    ? { label: 'checking system', tone: 'text-faint' }
    : health.error || !health.data?.ok
      ? { label: 'system unavailable', tone: 'text-sev-critical' }
      : !health.data.cache_built || !health.data.evidence_index
        ? { label: 'system degraded', tone: 'text-sev-high' }
        : { label: 'system ready', tone: 'text-ok' }
  return (
    <div className="hidden items-center gap-1.5 border-r border-border pr-3 text-[10px] uppercase tracking-[0.12em] text-faint sm:flex">
      <Radio className={cn('size-3', state.tone)} /> {state.label}
    </div>
  )
}

function MobileNavigation() {
  const location = useLocation()
  return (
    <Sheet>
      <SheetTrigger asChild>
        <button type="button" className="grid size-9 place-items-center rounded-md border border-border bg-surface-2 text-text lg:hidden" aria-label="Open navigation">
          <Menu className="size-4" />
        </button>
      </SheetTrigger>
      <SheetContent>
        <SheetHeader>
          <SheetTitle>Command center</SheetTitle>
          <SheetDescription>Move between live response and evidence views.</SheetDescription>
        </SheetHeader>
        <div className="flex-1 overflow-y-auto p-3">
          {navigationGroups.map((group) => (
            <div key={group.label} className="mb-5">
              <div className="section-label px-2 pb-1.5">{group.label}</div>
              <div className="space-y-1">
                {group.items.map((item) => (
                  <SheetClose asChild key={item.to}>
                    <NavLink
                      to={item.to}
                      className={cn(
                        'flex items-start gap-3 rounded-md px-2 py-2.5 transition-colors',
                        location.pathname === item.to ? 'bg-accent-soft text-text' : 'text-dim hover:bg-surface-2 hover:text-text',
                      )}
                    >
                      <item.icon className="mt-0.5 size-4 shrink-0 text-accent" />
                      <span>
                        <span className="block text-sm font-medium">{item.label}</span>
                        <span className="mt-0.5 block text-xs text-faint">{item.description}</span>
                      </span>
                    </NavLink>
                  </SheetClose>
                ))}
              </div>
            </div>
          ))}
        </div>
        <div className="border-t border-border p-4"><RoleSelect compact /></div>
      </SheetContent>
    </Sheet>
  )
}

function useLenis(target: React.RefObject<HTMLElement | null>) {
  const reduced = useReducedMotion()
  useEffect(() => {
    const element = target.current
    if (!element || reduced) return
    const lenis = new Lenis({
      wrapper: element,
      content: element.firstElementChild as HTMLElement,
      allowNestedScroll: true,
      duration: 0.9,
      easing: (time) => 1 - Math.pow(1 - time, 3),
      smoothWheel: true,
    })
    let frame = 0
    const loop = (time: number) => {
      lenis.raf(time)
      frame = requestAnimationFrame(loop)
    }
    frame = requestAnimationFrame(loop)
    return () => {
      cancelAnimationFrame(frame)
      lenis.destroy()
    }
  }, [target, reduced])
}

export default function Layout() {
  const scroller = useRef<HTMLDivElement>(null)
  const main = useRef<HTMLElement>(null)
  const location = useLocation()
  const current = getNavigationItem(location.pathname)
  const reduced = useReducedMotion()
  useLenis(scroller)

  useEffect(() => {
    scroller.current?.scrollTo({ top: 0 })
    document.title = `${current.label} · nextATT&CKs`
    window.requestAnimationFrame(() => main.current?.focus({ preventScroll: true }))
  }, [current.label, location.pathname])

  return (
    <TooltipProvider delayDuration={200}>
      <div className="flex h-full min-h-0 flex-col overflow-hidden bg-bg">
        <header className="relative z-40 shrink-0 border-b border-border bg-surface">
          <div className="flex h-16 items-center gap-3 px-4 sm:px-6">
            <MobileNavigation />
            <Brand />
            <div className="ml-auto flex items-center gap-2 sm:gap-3">
              <SystemStatus />
              <Clock />
              <div className="hidden md:block"><RoleSelect /></div>
              <ThemeToggle />
            </div>
          </div>
          <div className="flex h-11 items-stretch border-t border-border/70 px-4 sm:px-6">
            <div className="flex min-w-44 items-center gap-2 pr-4 lg:hidden">
              <current.icon className="size-3.5 text-accent" />
              <span className="truncate text-xs font-medium text-text">{current.label}</span>
            </div>
            <DesktopNavigation />
          </div>
        </header>

        <div ref={scroller} className="min-h-0 flex-1 overflow-y-auto">
          <div>
            <AnimatePresence mode="wait">
              <motion.main
                ref={main}
                key={location.pathname}
                tabIndex={-1}
                aria-label={`${current.label} workspace`}
                initial={reduced ? false : 'hidden'}
                animate={reduced ? undefined : 'show'}
                exit={reduced ? undefined : 'exit'}
                variants={routeVariants}
                className="mx-auto w-full max-w-[1500px] px-4 py-6 sm:px-6 lg:px-8 lg:py-8"
              >
                <Outlet />
              </motion.main>
            </AnimatePresence>
          </div>
        </div>
      </div>
    </TooltipProvider>
  )
}

export function PageHeader({ eyebrow, title, description, actions }: {
  eyebrow?: string
  title: string
  description?: string
  actions?: React.ReactNode
}) {
  return (
    <div className="relative mb-6 border-b border-border pb-5 lg:mb-8 lg:pb-6">
      <div className="absolute -left-4 top-0 h-12 w-0.5 bg-accent sm:-left-6 lg:-left-8" aria-hidden />
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
        <div className="min-w-0">
          {eyebrow ? <div className="mb-2 font-mono text-[10px] uppercase tracking-[0.16em] text-accent">{eyebrow}</div> : null}
          <h1 className="max-w-4xl text-[clamp(1.7rem,3vw,2.6rem)] font-semibold leading-[1.05] tracking-[-0.035em] text-text">{title}</h1>
          {description ? <p className="mt-2 max-w-3xl text-sm leading-6 text-dim">{description}</p> : null}
        </div>
        {actions ? <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div> : null}
      </div>
    </div>
  )
}
